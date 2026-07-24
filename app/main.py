import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.auth import COOKIE_NAME, create_session_token, get_current_user, verify_password
from app.config import settings
from app.db import Base, Tenant, User, engine, get_db

app = FastAPI(title="Platform Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,  # required for the browser to send/receive the httpOnly session cookie
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    # Only ever creates the `users` table if missing -- `tenants` already exists, owned and
    # migrated by synefi/app/db/models.py; this call is a no-op against it.
    Base.metadata.create_all(bind=engine)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "gateway"}


# ---- Auth ----
# Single shared login for the whole platform -- there is no per-tenant auth. Any
# authenticated user may access any tenant; access control here is "logged in or not,"
# not "logged in as tenant X."

@app.post("/auth/login")
def login(email: str, password: str, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_session_token(user)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,   # JavaScript cannot read this -- not localStorage, not accessible to XSS
        samesite=settings.cookie_samesite,
        secure=settings.cookie_secure,
        max_age=settings.jwt_expire_minutes * 60,
    )
    return {"id": user.id, "email": user.email, "name": user.name}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, samesite=settings.cookie_samesite, secure=settings.cookie_secure)
    return {"logged_out": True}


@app.get("/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "name": user.name}


# ---- Tenant directory ----
# Authenticated only. Never returns backend_url to the client -- the client only ever needs
# to know a tenant's slug; the gateway resolves slug -> backend_url internally, server-side,
# for every proxied request below.

@app.get("/api/tenants")
def list_tenants(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    tenants = db.query(Tenant).order_by(Tenant.created_at.asc()).all()
    return [{"id": t.id, "name": t.name, "slug": t.slug} for t in tenants]


# ---- Tenant-scoped reverse proxy ----
# The single chokepoint every tenant-scoped API call passes through. Validates the caller is
# authenticated AND that the requested tenant slug actually exists, before ever making an
# outbound request -- a request for a tenant that doesn't exist, or from a caller with no
# valid session, never reaches any backend at all.

@app.api_route("/api/{tenant_slug}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(tenant_slug: str, path: str, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
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
            headers={k: v for k, v in request.headers.items() if k.lower() not in ("host", "cookie", "content-length", "accept-encoding")},
            timeout=120,
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers={k: v for k, v in upstream_response.headers.items() if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")},
    )
