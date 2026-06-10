"""Declarative base with deterministic constraint/index naming.

The naming convention (REPO-STRUCTURE §4.2) guarantees that Alembic
autogenerate produces stable, reviewable constraint names across databases:
``pk_<table>``, ``fk_<table>_<column>``, ``uq_<table>_<column>``,
``ck_<table>_<constraint>``, ``ix_<table>_<column>``.

Domain models are M1 — along with the UUID-primary-key and
``created_at``/``updated_at`` timestamp mixins (UUIDv4 generated app-side, P5).
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION: dict[str, str] = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "ix": "ix_%(table_name)s_%(column_0_name)s",
}


class Base(DeclarativeBase):
    """Base class for every SQLAlchemy model in the platform.

    Alembic owns the schema (D4): ``Base.metadata`` is consumed by
    ``alembic/env.py`` as the autogenerate target; ``create_all()`` is
    forbidden outside tests.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
