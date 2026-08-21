"""
Mirrors just the two tables the gateway needs from the shared database: Tenant (read-only
here -- owned/migrated by synefi/app/db/models.py) and User (owned by the gateway; no other
codebase touches it). Same intentional-duplication pattern as elephantedge-abm/app/db/models.py
-- the database is the contract between independently deployed codebases.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

Base = declarative_base()

# pool_pre_ping guards against Neon's pooled ("-pooler") endpoint handing back a stale
# connection after the app has been idle -- this is very likely what caused the earlier
# intermittent 500 on /auth/login (first request after the free-tier instance woke up).
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Found live (2026-08-21, Neon project migration) -- a pooled ("-pooler") connection can come
# back with search_path effectively empty, making unqualified table references (tenants,
# users) fail with "relation does not exist" even though they exist in the public schema.
# Neon's pooler rejects search_path as a startup parameter outright, and an ALTER DATABASE
# -level default does not reliably apply to pooled connections either -- fixed via a normal
# post-connect query instead, same pattern applied in elephantedge-abm/app/db/session.py and
# synefi/app/db/session.py for the same shared database.
@event.listens_for(engine, "connect")
def _set_search_path(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("SET search_path TO public")
    cursor.close()


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True)
    backend_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    """A person allowed to log in to the platform. Single shared auth system across every
    tenant -- there is no per-tenant login and no per-user tenant restriction; any
    authenticated user can access any tenant, per explicit product decision. If per-tenant
    access restriction is ever needed, add a join table here rather than special-casing it."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
