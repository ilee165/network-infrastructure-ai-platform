"""OIDC JIT provisioning + identity anchoring (ADR-0028 §2/§4/§6).

After the ID token is validated (:mod:`app.core.oidc`) and the groups resolve to
a non-``None`` role (:mod:`app.services.oidc.mapping`), this module finds-or-
creates the platform ``users`` row for the immutable ``(idp_iss, idp_subject)``
pair and re-derives its role on **every** login (roles are never sticky).

The identity is anchored on ``(idp_iss, idp_subject)`` — never email — and the
DB-level ``uq_users_idp_identity`` partial UNIQUE index is the backstop that
keeps one federated identity ⇒ one row (so the ADR-0020 four-eyes ``user.id``
comparison stays a faithful 1:1 proxy for the IdP subject, ADR-0028 §6).

Like every service here, functions flush but never commit — the route owns the
transaction so the user row and its audit entry commit atomically.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NetOpsError
from app.core.security import Role as RoleEnum
from app.models.identity import Role, User
from app.services import audit


class OidcDenied(NetOpsError):
    """A validated IdP identity that maps to no platform role (deny-default).

    Authenticated-but-unauthorized: the IdP proved who the user is, but no
    configured group grants a role, so **no session is minted** (ADR-0028 §4).
    A generic 401 — the browser learns only "denied", never the mapping detail.
    """

    status_code = 401
    title = "Unauthorized"
    slug = "unauthorized"

    def __init__(self) -> None:
        super().__init__("No platform role is mapped for this identity")


def resolve_display_claims(claims: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract the **display-only** ``email`` / ``name`` from validated claims.

    These are stored for UI only and are explicitly *not* identity anchors
    (ADR-0028 §2): email is mutable at the IdP and is never used to match or
    merge accounts.
    """
    email = claims.get("email")
    name = claims.get("name") or claims.get("preferred_username")
    return (str(email) if email else None, str(name) if name else None)


async def _role_row(session: AsyncSession, role: RoleEnum) -> Role:
    """Load the seeded :class:`Role` row for *role* (deny-default if unseeded)."""
    row = (await session.execute(select(Role).where(Role.name == role.value))).scalar_one_or_none()
    if row is None:  # pragma: no cover - roles are seeded by migration/bootstrap
        raise OidcDenied()
    return row


async def provision_or_link_user(
    session: AsyncSession,
    *,
    idp_iss: str,
    idp_subject: str,
    role: RoleEnum,
    email: str | None,
    display_name: str | None,
    request_id: uuid.UUID | None = None,
) -> User:
    """Find-or-create the user for ``(idp_iss, idp_subject)`` and re-derive its role.

    First login for an unseen pair JIT-provisions a row (audited
    ``auth.oidc.user_provisioned``); subsequent logins match on the immutable
    pair and refresh the display claims + role from the current token (roles are
    re-derived every login, ADR-0028 §2/§4). The username is a synthetic,
    collision-free handle derived from the subject — the federated identity is
    the ``(idp_iss, idp_subject)`` pair, not the username. Flush only.
    """
    role_row = await _role_row(session, role)
    actor = _oidc_actor(idp_iss, idp_subject)

    existing = (
        await session.execute(
            select(User).where(User.idp_iss == idp_iss, User.idp_subject == idp_subject)
        )
    ).scalar_one_or_none()

    if existing is not None:
        return await _refresh_existing(
            session,
            existing,
            role_row=role_row,
            role=role,
            email=email,
            display_name=display_name,
            actor=actor,
            request_id=request_id,
        )

    user = User(
        username=_synthetic_username(idp_iss, idp_subject),
        # Federated accounts never authenticate locally: store an unusable hash
        # sentinel so the bcrypt verify path can never match (no password login).
        password_hash="!oidc",
        role=role_row,
        email=email,
        display_name=display_name,
        idp_iss=idp_iss,
        idp_subject=idp_subject,
        must_change_password=False,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError:
        # Concurrent first-login race (ADR-0028 §6): a second callback for the
        # same (idp_iss, idp_subject) passed the pre-insert lookup and raced us
        # to the unique anchor index. The other transaction is the JIT-provision
        # winner — roll back our losing INSERT, re-select the winner's row, and
        # reuse/update it so this login still succeeds (no spurious 500/failed
        # login). Fail-closed: if the row is somehow absent, re-raise.
        await session.rollback()
        # rollback() expires/detaches role_row; reload it in the fresh tx.
        role_row = await _role_row(session, role)
        winner = (
            await session.execute(
                select(User).where(User.idp_iss == idp_iss, User.idp_subject == idp_subject)
            )
        ).scalar_one_or_none()
        if winner is None:  # pragma: no cover - integrity error without a winner row
            raise
        return await _refresh_existing(
            session,
            winner,
            role_row=role_row,
            role=role,
            email=email,
            display_name=display_name,
            actor=actor,
            request_id=request_id,
        )
    await audit.record(
        session,
        actor=actor,
        action=audit.AUTH_OIDC_USER_PROVISIONED,
        target_type="user",
        target_id=str(user.id),
        detail={"role": role.value},
        request_id=request_id,
    )
    await audit.record(
        session,
        actor=actor,
        action=audit.AUTH_OIDC_ROLE_MAPPED,
        target_type="user",
        target_id=str(user.id),
        detail={"role": role.value},
        request_id=request_id,
    )
    return user


async def _refresh_existing(
    session: AsyncSession,
    existing: User,
    *,
    role_row: Role,
    role: RoleEnum,
    email: str | None,
    display_name: str | None,
    actor: str,
    request_id: uuid.UUID | None,
) -> User:
    """Re-derive role + refresh display claims on an already-anchored row.

    Shared by the normal re-login path and the concurrent-race recovery path:
    roles are never sticky, so every login refreshes them (ADR-0028 §2/§4).
    """
    existing.role = role_row
    existing.email = email
    existing.display_name = display_name
    await session.flush()
    await audit.record(
        session,
        actor=actor,
        action=audit.AUTH_OIDC_ROLE_MAPPED,
        target_type="user",
        target_id=str(existing.id),
        detail={"role": role.value},
        request_id=request_id,
    )
    return existing


def _oidc_actor(idp_iss: str, idp_subject: str) -> str:
    """Audit actor string for a federated identity — the anchor pair, no tokens."""
    return f"oidc:{idp_iss}#{idp_subject}"


def _synthetic_username(idp_iss: str, idp_subject: str) -> str:
    """A deterministic, collision-resistant username for a federated account.

    The real identity is the ``(idp_iss, idp_subject)`` pair; this handle exists
    only to satisfy the NOT-NULL/unique ``username`` column. It is derived from
    the pair (so re-provisioning is idempotent) and namespaced to avoid clashing
    with a human-chosen local username.
    """
    digest = uuid.uuid5(uuid.NAMESPACE_URL, f"{idp_iss}|{idp_subject}")
    return f"oidc_{digest}"
