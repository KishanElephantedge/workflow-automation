import re
from datetime import datetime

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import COOKIE_NAME, create_session_token, get_current_user, hash_password, require_internal, verify_password
from app.config import settings
from app.db import Base, Tenant, User, engine, ensure_columns, get_db

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
    # Only ever creates the `users` table if missing -- `tenants` already exists, owned and
    # migrated by synefi/app/db/models.py; this call is a no-op against it.
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
    # backend_url stays NULL, matching partner_pipeline.get_or_create_partner_tenant's own
    # existing convention: these tenants are a data boundary inside the shared product
    # database, not a separately deployed service. enabled_features starts at stage 1 only
    # ("accounts") per the explicit stage-by-stage rollout -- never "everything", since a
    # brand new partner tenant has nothing built for it yet beyond that.
    tenant = Tenant(name=payload.name.strip(), slug=slug, backend_url=None, enabled_features=["accounts"])
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

