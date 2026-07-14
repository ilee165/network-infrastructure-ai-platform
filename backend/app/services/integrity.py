"""Structured SQLAlchemy integrity-error metadata across supported drivers."""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError


def integrity_sqlstate(exc: IntegrityError) -> str | None:
    """Return the SQLSTATE exposed by SQLAlchemy's DBAPI adapter, if any."""
    orig = exc.orig
    if orig is None:
        return None
    value = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return value if isinstance(value, str) else None


def unique_constraint_name(exc: IntegrityError) -> str | None:
    """Return a named unique constraint for asyncpg or psycopg adapters.

    SQLAlchemy's asyncpg adapter exposes ``sqlstate`` itself but chains the
    driver exception carrying ``constraint_name`` under ``orig.__cause__``.
    Psycopg adapters expose the constraint through ``orig.diag`` instead.
    """
    orig = exc.orig
    if orig is None:
        return None

    driver = getattr(orig, "__cause__", None)
    value = getattr(driver, "constraint_name", None)
    if isinstance(value, str):
        return value

    diag = getattr(orig, "diag", None)
    value = getattr(diag, "constraint_name", None)
    return value if isinstance(value, str) else None
