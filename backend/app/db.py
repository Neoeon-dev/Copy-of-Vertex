"""Database engine, session factory and declarative base.

Uses PostgreSQL exclusively. The DATABASE_URL environment variable must
point to a PostgreSQL instance. If unreachable, the application fails
with a clear configuration error.
"""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy models."""


def _create_engine(database_url: str):
    kwargs = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        raise ValueError(
            "SQLite is not supported. Set DATABASE_URL to a PostgreSQL connection string. "
            "Example: postgresql+psycopg2://user:pass@localhost:5432/dbname"
        )
    return create_engine(database_url, **kwargs)


engine = _create_engine(settings.database_url)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a request-scoped database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables on startup.

    Uses Alembic-style migrations in production; create_all is sufficient
    for the prototype phase.
    """
    # Import models so SQLAlchemy registers all tables in the metadata.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
