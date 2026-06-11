"""Identity models: roles and users (D10, ADR-0010).

Role rows are seeded by migration/bootstrap — the fixed RBAC set
``viewer < operator < engineer < admin`` (rank comparison lives in the auth
layer, not the schema). Passwords are stored only as bcrypt hashes produced
by :mod:`app.core.security`.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.mixins import TimestampMixin, UuidPkMixin


class Role(UuidPkMixin, TimestampMixin, Base):
    """An RBAC role (ADR-0010); ``name`` is the wire value, e.g. ``"engineer"``."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class User(UuidPkMixin, TimestampMixin, Base):
    """A local platform account; authentication is username + bcrypt hash."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)

    role: Mapped[Role] = relationship(lazy="joined")
