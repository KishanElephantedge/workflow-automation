"""
Mirrors just the two tables the gateway needs from the shared database: Tenant (read-only
here -- owned/migrated by synefi/app/db/models.py) and User (owned by the gateway; no other
codebase touches it). Same intentional-duplication pattern as elephantedge-abm/app/db/models.py
-- the database is the contract between independently deployed codebases.
"""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, create_engine, event, text
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
    # Partner self-serve access (2026-09-07). Null/absent means "not a partner-facing
    # tenant" -- today that's every tenant created before this feature (Elephant Edge,
    # Synefi, and partner tenants that only ever existed as a data boundary for internal
    # discovery runs). A concrete list here is what makes a tenant reachable by a
    # role="partner" login at all: see proxy()'s enforcement in main.py. Ordered stage
    # names, not booleans -- "accounts" today, "content" next, matching the explicit
    # stage-by-stage rollout rather than an all-or-nothing flag.
    enabled_features = Column(JSON, nullable=True)


class User(Base):
    """A person allowed to log in to the platform.

    2026-09-07: this used to be genuinely single-tier -- "any authenticated user can access
    any tenant, per explicit product decision" (see the old version of this docstring in git
    history). That decision is now superseded by a real one: partners get their own login
    that is restricted to exactly one tenant. `role` is the switch -- "internal" (the
    default, and the only value that existed before this column did) keeps the original
    any-tenant behavior for the Elephant Edge team; "partner" is scoped to `tenant_id` by
    every check in main.py (list_tenants, proxy). A user can only be one or the other, never
    both -- if that's ever needed, this needs a join table, not a second role value.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    role = Column(String, nullable=False, default="internal")
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_columns():
    """Additive-only schema convergence for the two new columns, run once at startup.

    `tenants` is owned by synefi's own models.py (this file only mirrors it), so
    Base.metadata.create_all() -- which only ever creates `users`, per the existing startup
    comment -- can't add a column to it. Both ALTERs are idempotent (IF NOT EXISTS) and safe
    to run on every boot, matching the pattern elephantedge-abm/app/db/session.py already
    uses for its own additive migrations.
    """
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR NOT NULL DEFAULT 'internal'"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id)"))
        conn.execute(text("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS enabled_features JSON"))
