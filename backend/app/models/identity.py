"""Identity models: roles and users (D10, ADR-0010).

Role rows are seeded by migration/bootstrap — the fixed RBAC set
``viewer < operator < engineer < admin`` (rank comparison lives in the auth
layer, not the schema). Passwords are stored only as bcrypt hashes produced
by :mod:`app.core.security`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, column
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.mixins import TimestampMixin, UtcDateTime, UuidPkMixin, utcnow


class Role(UuidPkMixin, TimestampMixin, Base):
    """An RBAC role (ADR-0010); ``name`` is the wire value, e.g. ``"engineer"``."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class User(UuidPkMixin, TimestampMixin, Base):
    """A local *or* federated platform account (ADR-0010, ADR-0028).

    Local accounts authenticate with username + bcrypt hash. Federated (OIDC)
    accounts are anchored on the immutable ``(idp_iss, idp_subject)`` pair —
    never email/username, which are mutable at the IdP (ADR-0028 §2). A
    partial UNIQUE index over that pair (where ``idp_subject IS NOT NULL``)
    guarantees one federated identity maps to exactly one row, which is what
    keeps the ADR-0020 four-eyes ``user.id`` comparison a faithful 1:1 proxy
    for the IdP subject (ADR-0028 §6). Local users leave both columns NULL.
    """

    __tablename__ = "users"
    __table_args__ = (
        # One federated identity ⇒ exactly one user row (ADR-0028 §6). Partial
        # so local users (both columns NULL) are exempt; SQLite honours the same
        # WHERE-qualified unique index, so the unit suite enforces it too.
        Index(
            "uq_users_idp_identity",
            "idp_iss",
            "idp_subject",
            unique=True,
            sqlite_where=column("idp_subject").isnot(None),
            postgresql_where=column("idp_subject").isnot(None),
        ),
    )

    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id"), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    must_change_password: Mapped[bool] = mapped_column(nullable=False, default=False)
    #: Immutable IdP issuer (``iss``) for a federated account; NULL for local.
    idp_iss: Mapped[str | None] = mapped_column(String(512))
    #: Immutable IdP subject (``sub``) for a federated account; NULL for local.
    #: ``(idp_iss, idp_subject)`` is the stable federated identity (ADR-0028 §2).
    idp_subject: Mapped[str | None] = mapped_column(String(255))

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
