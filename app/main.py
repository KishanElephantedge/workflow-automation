import re
from datetime import datetime, timedelta

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth import COOKIE_NAME, create_session_token, get_current_user, hash_password, require_internal, verify_password
from app.config import settings
from app.db import Base, Tenant, UsageEvent, UsageSession, User, engine, ensure_columns, get_db

app = FastAPI(title="Platform Gateway")

app.add_middleware(
    CORSMiddleware,
    # FRONTEND_ORIGIN supports a comma-separated list, so the old Vercel URL and a newly
    # connected custom domain can both work during a transition, not just whichever one
    # variable happens to be set.
    allow_origins=[o.strip() for o in settings.frontend_origin.split(",") if o.strip()],
    allow_credentials=True,  # required for the browser to send/receive the httpOnly session cookie
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    # Creates the tables this gateway owns if missing -- `users`, plus `usage_sessions`/
    # `usage_events` (2026-09-13). `tenants` already exists, owned and migrated by
    # synefi/app/db/models.py; this call is a no-op against it.
    Base.metadata.create_all(bind=engine)
    ensure_columns()


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "gateway"}


# ---- Auth ----
# 2026-09-07: this used to be a genuinely single-tier login -- any authenticated user could
# reach any tenant, no exceptions. That is still true for role="internal" users (the
# default, and the only kind that existed before today), which is why nothing below changes
# behavior for the existing Elephant Edge team logins. role="partner" is new and is scoped to
# exactly one tenant by every check in this file.


def _cookie_kwargs(request: Request) -> dict:
    """Real bug fix (2026-08-19): COOKIE_SAMESITE/COOKIE_SECURE env vars were added in
    da42cb0 to fix cross-site cookies (frontend on vercel.app, gateway on onrender.com --
    SameSite=Lax cookies are silently dropped from cross-site XHR/fetch), but whether those
    env vars were actually *set* in Render's dashboard could never be confirmed from the
    repo -- and a mobile-login-stuck-on-login-screen report meant they likely weren't.
    Deriving Secure/SameSite from the request's own scheme instead removes that manual step
    entirely: Render always terminates TLS and forwards X-Forwarded-Proto: https, so a real
    HTTPS deployment gets SameSite=None/Secure=True automatically, while local plain-HTTP
    dev (where Secure would silently make the browser refuse to store the cookie at all)
    keeps SameSite=Lax/Secure=False."""
    is_https = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    return {"samesite": "none", "secure": True} if is_https else {"samesite": "lax", "secure": False}


def _user_payload(user: User, db: Session) -> dict:
    tenant = None
    if user.tenant_id is not None:
        t = db.get(Tenant, user.tenant_id)
        if t:
            tenant = {"id": t.id, "name": t.name, "slug": t.slug, "enabledFeatures": t.enabled_features or []}
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role, "tenant": tenant}


@app.post("/auth/login")
def login(email: str, password: str, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_session_token(user)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,   # JavaScript cannot read this -- not localStorage, not accessible to XSS
        max_age=settings.jwt_expire_minutes * 60,
        **_cookie_kwargs(request),
    )
    return _user_payload(user, db)


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    kwargs = _cookie_kwargs(request)
    response.delete_cookie(COOKIE_NAME, samesite=kwargs["samesite"], secure=kwargs["secure"])
    return {"logged_out": True}


@app.get("/auth/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _user_payload(user, db)


class ProfileUpdate(BaseModel):
    name: str | None = None


@app.patch("/auth/me")
def update_my_profile(payload: ProfileUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Self-service, not an admin route -- any authenticated user (partner or internal)
    editing their OWN row, gated by get_current_user alone. Deliberately does not accept
    email or password here: changing either needs its own verification step (a duplicate-email
    check, a current-password confirmation) that a plain PATCH would skip -- name is the one
    field with no such risk."""
    if payload.name is not None:
        user.name = payload.name.strip() or None
    db.commit()
    return _user_payload(user, db)


# ---- Tenant directory ----
# Authenticated only. Never returns backend_url to the client -- the client only ever needs
# to know a tenant's slug; the gateway resolves slug -> backend_url internally, server-side,
# for every proxied request below.
#
# A partner sees only their own tenant here -- the earlier version returned every tenant to
# every logged-in user unconditionally, which is what made a partner login reach Elephant
# Edge's and Synefi's data through the tenant switcher. An internal user's view is unchanged.

@app.get("/api/tenants")
def list_tenants(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role == "partner":
        if user.tenant_id is None:
            return []
        tenant = db.get(Tenant, user.tenant_id)
        return [{"id": tenant.id, "name": tenant.name, "slug": tenant.slug}] if tenant else []
    tenants = db.query(Tenant).order_by(Tenant.created_at.asc()).all()
    return [{"id": t.id, "name": t.name, "slug": t.slug} for t in tenants]


# ---- Admin: partner onboarding ----
# Everything below is require_internal-gated -- a partner login must never be able to create
# another login, read the tenant table, or change what another tenant can see. This is the
# multi-step "Add user" wizard's backend: step 1 (login) and step 2's tenant choice land here;
# step 2's ICP fields are a separate, tenant-scoped call into the product backend itself (that
# data belongs with Company/Batch/Parameter, which this gateway has no model for).

SLUG_STRIP_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    base = SLUG_STRIP_RE.sub("-", name.strip().lower()).strip("-") or "partner"
    return f"partner:{base}"


def _shared_product_backend_url(db: Session) -> str | None:
    """The backend_url every partner tenant should proxy through.

    Real gap found while wiring the "accounts" page end to end, not while reading code: every
    partner tenant created by the discovery pipeline (get_or_create_partner_tenant in
    elephantedge-abm) has backend_url=NULL -- correct at the time, since those tenants were
    only ever a DB-level data boundary, queried directly, never reached over HTTP. But
    proxy() 404s on a null backend_url regardless of role, so a partner's OWN login would hit
    that wall trying to load their own accounts page, and so would an internal admin trying to
    fetch anything for them through this gateway.

    Partner tenants and Elephant Edge's own tenant are the SAME deployed backend and the SAME
    database -- tenant separation happens via the X-Tenant-Id header proxy() already sets, not
    via a different server. So the right backend_url for a partner tenant is simply whichever
    one Elephant Edge's own tenant uses today, looked up by slug rather than a hardcoded
    constant (this file has no ELEPHANT_EDGE_TENANT_ID of its own, and slug is the stable,
    self-describing identifier already used everywhere else in this file).
    """
    elephant_edge = db.query(Tenant).filter(Tenant.slug == "elephant-edge").first()
    return elephant_edge.backend_url if elephant_edge else None


class TenantCreate(BaseModel):
    name: str


@app.get("/api/admin/tenants/search")
def search_tenants(q: str = "", user: User = Depends(require_internal), db: Session = Depends(get_db)):
    """Backs the wizard's "attach to an existing tenant" step. Several partner tenants
    already exist with real fetched companies in them (created by the discovery pipeline
    before any login existed for them, e.g. Sandy Yu, Thomas Ross) -- creating a NEW tenant
    for the same person instead of finding this one would silently orphan that data from the
    login that's supposed to see it. Matches on name OR slug so "sandy" finds
    "Partner — Sandy Yu" (slug partner:sandy-yu) either way."""
    query = db.query(Tenant)
    if q.strip():
        like = f"%{q.strip()}%"
        query = query.filter((Tenant.name.ilike(like)) | (Tenant.slug.ilike(like)))
    tenants = query.order_by(Tenant.created_at.desc()).limit(20).all()
    # Already-claimed tenants aren't hidden -- an internal user re-running the wizard against
    # a tenant that already has a login should see that plainly, not have it disappear.
    claimed = {t_id for (t_id,) in db.query(User.tenant_id).filter(User.tenant_id.isnot(None)).all()}
    return [
        {"id": t.id, "name": t.name, "slug": t.slug, "hasLogin": t.id in claimed,
         "enabledFeatures": t.enabled_features or []}
        for t in tenants
    ]


@app.post("/api/admin/tenants")
def create_tenant(payload: TenantCreate, user: User = Depends(require_internal), db: Session = Depends(get_db)):
    slug = _slugify(payload.name)
    if db.query(Tenant).filter(Tenant.slug == slug).first():
        raise HTTPException(status_code=409, detail=f"A tenant with slug '{slug}' already exists -- search for it instead of creating a duplicate")
    # backend_url is Elephant Edge's own -- see _shared_product_backend_url's docstring for
    # why that's correct rather than NULL: partner tenants share the same deployed backend,
    # separated by the X-Tenant-Id header, not by a different server. enabled_features starts
    # at stage 1 only ("accounts") per the explicit stage-by-stage rollout -- never
    # "everything", since a brand new partner tenant has nothing built for it yet beyond that.
    tenant = Tenant(name=payload.name.strip(), slug=slug,
                     backend_url=_shared_product_backend_url(db), enabled_features=["accounts"])
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return {"id": tenant.id, "name": tenant.name, "slug": tenant.slug, "enabledFeatures": tenant.enabled_features}


class TenantFeaturesUpdate(BaseModel):
    enabledFeatures: list[str]


@app.patch("/api/admin/tenants/{tenant_id}")
def update_tenant_features(tenant_id: int, payload: TenantFeaturesUpdate, user: User = Depends(require_internal), db: Session = Depends(get_db)):
    """Moves a partner from one stage to the next (e.g. accounts -> accounts+content) without
    touching their login. Deliberately does not touch name/slug/backend_url -- this endpoint's
    only job is the stage-by-stage visibility list."""
    tenant = db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.enabled_features = payload.enabledFeatures
    db.commit()
    return {"id": tenant.id, "enabledFeatures": tenant.enabled_features}


class UserCreate(BaseModel):
    email: str
    password: str
    name: str | None = None
    tenant_id: int


@app.get("/api/admin/users")
def list_users(user: User = Depends(require_internal), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    tenants_by_id = {t.id: t for t in db.query(Tenant).all()}
    out = []
    for u in users:
        t = tenants_by_id.get(u.tenant_id) if u.tenant_id else None
        out.append({
            "id": u.id, "email": u.email, "name": u.name, "role": u.role,
            "tenant": {"id": t.id, "name": t.name, "slug": t.slug} if t else None,
            "createdAt": u.created_at.isoformat() if u.created_at else None,
        })
    return out


@app.post("/api/admin/users")
def create_partner_user(payload: UserCreate, user: User = Depends(require_internal), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=409, detail="A user with this email already exists")
    tenant = db.get(Tenant, payload.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    # Backfill for tenants attached via the "existing tenant" search step (e.g. Sandy Yu's,
    # created by the discovery pipeline before this feature existed): those predate
    # enabled_features/backend_url entirely, and without this a real partner would log in to
    # a tenant with nothing configured to show them and no route to reach it through. Never
    # overwrites a value that's already set -- only fills what create_tenant would have set
    # for a brand new tenant.
    if tenant.backend_url is None:
        tenant.backend_url = _shared_product_backend_url(db)
    if tenant.enabled_features is None:
        tenant.enabled_features = ["accounts"]
    new_user = User(
        email=payload.email.strip().lower(),
        password_hash=hash_password(payload.password),
        name=payload.name,
        role="partner",
        tenant_id=tenant.id,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"id": new_user.id, "email": new_user.email, "role": new_user.role,
            "tenant": {"id": tenant.id, "name": tenant.name, "slug": tenant.slug}}


# ---- Usage analytics ----
# First-party, self-hosted, and identity-aware. Deliberately NOT PostHog/Plausible/Umami:
# Plausible and Umami are built for anonymous public web traffic and intentionally do not
# identify visitors, which is the single most important question here ("who is using it");
# PostHog does identify, but self-hosting it means running ClickHouse + Kafka + Redis + its
# own Postgres to observe a dashboard with a few dozen known, logged-in users. We already own
# the database, the backend, and the auth layer, so the honest minimum is two small tables.
#
# Everything recorded here is stamped server-side from the verified session cookie. The client
# supplies only what it alone knows (which path it navigated to, its own session id) and never
# who it is, which tenant it may see, or when the event happened.

# How recently a session must have pinged to count as "on right now". 5 minutes against a
# ~60s client heartbeat tolerates a few missed pings (sleeping laptop, flaky network) without
# reporting someone as present long after they closed the tab.
ACTIVE_WINDOW_MINUTES = 5

# Client-supplied strings are bounded before they ever reach the database -- a path or label
# is a UI string, not free-form storage, and nothing downstream needs more than this.
_MAX_TEXT = 500
_ALLOWED_EVENT_TYPES = {"pageview", "click", "heartbeat"}


def _truncate(value: str | None, limit: int = _MAX_TEXT) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return value[:limit]


def _client_ip(request: Request) -> str | None:
    """Render sits behind Cloudflare, so request.client.host is the proxy, not the visitor.
    X-Forwarded-For's FIRST entry is the original client (each hop appends its own)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:_MAX_TEXT]
    return request.client.host if request.client else None


def _create_session(db: Session, *, session_id: str, user: User, tenant_id: int | None, request: Request, referrer: str | None, now: datetime) -> UsageSession:
    """Get-or-create for a brand-new session id, safe against concurrent first events.

    Found live (2026-09-13): a page fires its first pageview and its first heartbeat close
    enough together that both requests can look up the same not-yet-existing session, both
    decide to insert it, and the second one dies on the unique index with a 500. Opening two
    tabs at once does the same thing. A pre-check alone cannot fix this -- there is always a
    window between the SELECT and the INSERT.

    The insert therefore runs inside a SAVEPOINT: if a concurrent request won the race, only
    the savepoint is rolled back (leaving the surrounding transaction intact and usable) and
    the row that other request committed is read back and used instead."""
    session = UsageSession(
        session_id=session_id,
        user_id=user.id,
        tenant_id=tenant_id,
        started_at=now,
        last_seen_at=now,
        ip=_client_ip(request),
        country=_truncate(request.headers.get("cf-ipcountry"), 8),
        user_agent=_truncate(request.headers.get("user-agent")),
        referrer=referrer,
        pageview_count=0,
    )
    try:
        with db.begin_nested():
            db.add(session)
            db.flush()
        return session
    except IntegrityError:
        existing = db.query(UsageSession).filter(UsageSession.session_id == session_id).first()
        if existing is not None:
            return existing
        raise


class UsageEventIn(BaseModel):
    event_type: str
    session_id: str
    path: str | None = None
    label: str | None = None
    referrer: str | None = None
    tenant_slug: str | None = None


@app.post("/api/usage/event")
def record_usage_event(
    payload: UsageEventIn,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Records one pageview/click, or refreshes a session's liveness on a heartbeat.

    Returns 204-ish {"ok": true} in all valid cases -- this is fire-and-forget telemetry from
    the client's point of view, and an analytics write must never be able to break a page.
    An unknown event_type is rejected outright rather than stored, so this table can never
    accumulate arbitrary client-defined strings."""
    event_type = payload.event_type.strip().lower()
    if event_type not in _ALLOWED_EVENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown event_type '{payload.event_type}'")

    session_id = _truncate(payload.session_id, 100)
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")

    path = _truncate(payload.path)
    now = datetime.utcnow()

    # Resolve the tenant the client says it is viewing, but only ever to a real tenant row,
    # and only one this user is actually allowed to see -- a partner may not attribute their
    # activity to someone else's workspace. Falls back to None rather than rejecting, so a
    # stale/unknown slug degrades to "no tenant recorded" instead of erroring the page.
    tenant_id = None
    if payload.tenant_slug:
        tenant = db.query(Tenant).filter(Tenant.slug == payload.tenant_slug.strip()).first()
        if tenant and (user.role == "internal" or user.tenant_id == tenant.id):
            tenant_id = tenant.id

    existing = db.query(UsageSession).filter(UsageSession.session_id == session_id).first()
    if existing is not None and existing.user_id != user.id:
        # A recycled or forged session id must never let one user's activity be written onto
        # another's session row. The server's identity wins: this user gets their own row,
        # keyed by the id they sent plus their real user id.
        session_id = f"{session_id}:{user.id}"
        existing = db.query(UsageSession).filter(UsageSession.session_id == session_id).first()

    session = existing or _create_session(
        db,
        session_id=session_id,
        user=user,
        tenant_id=tenant_id,
        request=request,
        referrer=_truncate(payload.referrer),
        now=now,
    )

    session.last_seen_at = now
    if tenant_id is not None:
        session.tenant_id = tenant_id
    if path:
        session.last_path = path

    if event_type in ("pageview", "click"):
        if event_type == "pageview":
            # Incremented as a SQL expression, NOT `session.pageview_count + 1` in Python.
            # Found live (2026-09-13) with 12 concurrent pageviews on one session: a Python
            # read-modify-write loses updates when requests overlap (12 events recorded, the
            # counter read 6). This emits `SET pageview_count = pageview_count + 1`, which the
            # database applies atomically per row.
            session.pageview_count = UsageSession.pageview_count + 1
        db.add(
            UsageEvent(
                session_id=session.session_id,
                user_id=user.id,
                tenant_id=tenant_id,
                event_type=event_type,
                path=path,
                label=_truncate(payload.label),
                created_at=now,
            )
        )

    db.commit()
    return {"ok": True}


@app.get("/api/usage/summary")
def usage_summary(
    window_days: int = 7,
    user: User = Depends(require_internal),
    db: Session = Depends(get_db),
):
    """Internal-only. A partner must not see who else is on the platform or what other
    workspaces are being used -- that is the same trust boundary role="partner" exists for,
    so this reuses require_internal rather than a manual role check."""
    window_days = max(1, min(window_days, 90))
    now = datetime.utcnow()
    since = now - timedelta(days=window_days)
    live_since = now - timedelta(minutes=ACTIVE_WINDOW_MINUTES)

    tenant_names = {t.id: t.name for t in db.query(Tenant).all()}
    user_rows = {u.id: u for u in db.query(User).all()}

    def _user_info(user_id: int) -> dict:
        u = user_rows.get(user_id)
        if u is None:
            return {"email": None, "name": None, "role": None}
        return {"email": u.email, "name": u.name, "role": u.role}

    live_sessions = (
        db.query(UsageSession)
        .filter(UsageSession.last_seen_at >= live_since)
        .order_by(UsageSession.last_seen_at.desc())
        .all()
    )

    sessions_in_window = db.query(UsageSession).filter(UsageSession.last_seen_at >= since).all()

    events_in_window = (
        db.query(
            UsageEvent.path,
            func.count(UsageEvent.id),
            func.count(func.distinct(UsageEvent.user_id)),
        )
        .filter(UsageEvent.created_at >= since, UsageEvent.event_type == "pageview")
        .group_by(UsageEvent.path)
        .order_by(func.count(UsageEvent.id).desc())
        .limit(50)
        .all()
    )

    per_user = (
        db.query(
            UsageEvent.user_id,
            func.count(UsageEvent.id),
            func.count(func.distinct(UsageEvent.session_id)),
            func.max(UsageEvent.created_at),
        )
        .filter(UsageEvent.created_at >= since, UsageEvent.event_type == "pageview")
        .group_by(UsageEvent.user_id)
        .order_by(func.count(UsageEvent.id).desc())
        .all()
    )

    per_tenant = (
        db.query(
            UsageEvent.tenant_id,
            func.count(UsageEvent.id),
            func.count(func.distinct(UsageEvent.user_id)),
        )
        .filter(UsageEvent.created_at >= since, UsageEvent.event_type == "pageview")
        .group_by(UsageEvent.tenant_id)
        .order_by(func.count(UsageEvent.id).desc())
        .all()
    )

    by_country: dict[str, int] = {}
    for s in sessions_in_window:
        key = s.country or "Unknown"
        by_country[key] = by_country.get(key, 0) + 1

    total_pageviews = (
        db.query(func.count(UsageEvent.id))
        .filter(UsageEvent.created_at >= since, UsageEvent.event_type == "pageview")
        .scalar()
        or 0
    )

    return {
        "window_days": window_days,
        "generated_at": now,
        "live": {
            "window_minutes": ACTIVE_WINDOW_MINUTES,
            "active_users": len({s.user_id for s in live_sessions}),
            "active_sessions": len(live_sessions),
            "now": [
                {
                    **_user_info(s.user_id),
                    "tenant": tenant_names.get(s.tenant_id),
                    "path": s.last_path,
                    "country": s.country,
                    "last_seen_at": s.last_seen_at,
                    "started_at": s.started_at,
                }
                for s in live_sessions
            ],
        },
        "totals": {
            "sessions": len(sessions_in_window),
            "users": len({s.user_id for s in sessions_in_window}),
            "pageviews": total_pageviews,
        },
        "top_pages": [
            {"path": path or "(unknown)", "views": views, "users": users}
            for path, views, users in events_in_window
        ],
        "top_users": [
            {
                **_user_info(user_id),
                "pageviews": views,
                "sessions": sessions,
                "last_seen_at": last_seen,
            }
            for user_id, views, sessions, last_seen in per_user
        ],
        "by_tenant": [
            {"tenant": tenant_names.get(tenant_id) or "(none)", "pageviews": views, "users": users}
            for tenant_id, views, users in per_tenant
        ],
        "by_country": [
            {"country": country, "sessions": count}
            for country, count in sorted(by_country.items(), key=lambda kv: -kv[1])
        ],
    }


# ---- Tenant-scoped reverse proxy ----
# The single chokepoint every tenant-scoped API call passes through. Validates the caller is
# authenticated, that a partner caller is only ever proxying to THEIR OWN tenant slug (a
# fabricated or guessed slug for another tenant is rejected before any outbound request), and
# that the requested tenant slug actually exists and has a real backend configured.

@app.api_route("/api/{tenant_slug}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(tenant_slug: str, path: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role == "partner":
        if user.tenant_id is None:
            raise HTTPException(status_code=403, detail="This account has no tenant assigned")
        allowed = db.get(Tenant, user.tenant_id)
        if not allowed or allowed.slug != tenant_slug:
            raise HTTPException(status_code=403, detail="Not authorized for this tenant")

    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant or not tenant.backend_url:
        raise HTTPException(status_code=404, detail=f"No backend configured for tenant '{tenant_slug}'")

    target_url = f"{tenant.backend_url.rstrip('/')}/{path}"
    body = await request.body()

    async with httpx.AsyncClient() as client:
        upstream_response = await client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
            # Excludes the browser's own Accept-Encoding (e.g. "br") from the upstream
            # request -- httpx has no Brotli decoder installed, so if the upstream (fronted
            # by Cloudflare on Render) compressed its response with Brotli in response to
            # that header, httpx receives undecoded compressed bytes it can't unpack, and
            # they'd be forwarded to the browser as garbage. Letting httpx omit/set its own
            # Accept-Encoding means it only ever receives encodings it can actually decode.
            #
            # X-Tenant-Id is set here, by the gateway, from the tenant row it just looked up
            # -- never forwarded from the incoming request -- so it's the one thing the
            # backend can trust about which tenant a proxied call is for without needing its
            # own copy of the user/session/auth model. A backend route that ignores this
            # header (nothing required it to change) behaves exactly as it always has.
            headers={
                **{k: v for k, v in request.headers.items() if k.lower() not in ("host", "cookie", "content-length", "accept-encoding", "x-tenant-id")},
                "x-tenant-id": str(tenant.id),
            },
            timeout=120,
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers={k: v for k, v in upstream_response.headers.items() if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")},
    )

