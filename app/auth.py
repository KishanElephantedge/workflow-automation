from datetime import datetime, timedelta

import bcrypt
from fastapi import Cookie, Depends, HTTPException
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.db import User, get_db

COOKIE_NAME = "session"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_session_token(user: User) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": str(user.id), "email": user.email, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def get_current_user(
    session: str | None = Cookie(default=None, alias=COOKIE_NAME),
    db: Session = Depends(get_db),
) -> User:
    """The one place that decides whether a request is authenticated at all. Reads the
    session token from an httpOnly cookie set by /auth/login -- never from a header or query
    param the client could set arbitrarily, and never from localStorage (the browser attaches
    httpOnly cookies automatically; JavaScript cannot read or forge this value)."""
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(session, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user


def require_internal(user: User = Depends(get_current_user)) -> User:
    """Gate for the admin surface (creating users/tenants). A partner login must never be
    able to create another login or see the raw tenant table -- that's the same trust
    boundary a role="partner" restriction exists to protect in the first place, so the admin
    routes get their own explicit dependency rather than relying on callers to remember a
    manual `if user.role != "internal"` check."""
    if user.role != "internal":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
