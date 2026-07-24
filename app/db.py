"""
Mirrors just the two tables the gateway needs from the shared database: Tenant (read-only
here -- owned/migrated by synefi/app/db/models.py) and User (owned by the gateway; no other
codebase touches it). Same intentional-duplication pattern as elephantedge-abm/app/db/models.py
-- the database is the contract between independently deployed codebases.
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

Base = declarative_base()

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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
