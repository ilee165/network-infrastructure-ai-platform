"""Identity models: roles and users (D10, ADR-0010).

Role rows are seeded by migration/bootstrap — the fixed RBAC set
``viewer < operator < engineer < admin`` (rank comparison lives in the auth
layer, not the schema). Passwords are stored only as bcrypt hashes produced
by :mod:`app.core.security`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.mixins import TimestampMixin, UtcDateTime, UuidPkMixin, utcnow


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
    email: Mapped[str | None] = mapped_column(String(255), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    must_change_password: Mapped[bool] = mapped_column(nullable=False, default=False)

    role: Mapped[Role] = relationship(lazy="joined")


class RefreshSession(UuidPkMixin, Base):
    """A server-side refresh session (Auth & Account UI).

    The refresh JWT carries this row's ``id`` as its ``sid`` claim; ``refresh``
    validates the session is live (``revoked_at IS NULL``) and the user active.
    Revocation flips ``revoked_at`` — the row is never deleted, so the trail of
    logins/logouts survives. ``user_agent`` / ``ip`` are best-effort request
    metadata for the "your sessions" view; both are optional.
    """

    __tablename__ = "refresh_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    last_used_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    ip: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime())


class SystemSetting(UuidPkMixin, TimestampMixin, Base):
    """The single platform settings row (Auth & Account UI).

    Holds only DB-persisted operator preferences read by the LLM registry at
    runtime: the active ``llm_profile`` plus the optional reasoning/fast model
    role map (env values are the fallback). Provider API keys and endpoints
    stay in env/``Settings`` and are NEVER accepted or stored here.
    """

    __tablename__ = "system_settings"

    llm_profile: Mapped[str] = mapped_column(String(64), nullable=False, default="local")
    llm_role_reasoning: Mapped[str | None] = mapped_column(String(128))
    llm_role_fast: Mapped[str | None] = mapped_column(String(128))
