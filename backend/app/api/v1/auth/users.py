"""Admin user management (Auth & Account UI, B4): admin-only CRUD over accounts.

Every route here is gated by ``require_role("admin")``. No endpoint ever puts a
password hash in a response body or an audit detail, and the temp password
generated/accepted for create + reset is returned EXACTLY once (in the create
and reset responses) — never logged and never written to an audit ``detail``.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Annotated, Final

from fastapi import Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.api.v1.auth._shared import _EMAIL_TAKEN, router
from app.core.errors import BadRequestError, ConflictError, NotFoundError
from app.core.security import Role as RoleEnum
from app.core.security import hash_password_async
from app.models import Role, User
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service

#: Length (chars) of a generated temp password. ``secrets.token_urlsafe(16)``
#: yields ~22 URL-safe characters, comfortably above the >=16 requirement and
#: well under bcrypt's 72-byte input limit.
_TEMP_PASSWORD_BYTES: Final = 16

#: A username already taken by another account.
_USERNAME_TAKEN: Final = "That username is already in use"

#: Refusing to remove the platform's last reachable admin (lockout prevention).
_LAST_ADMIN: Final = "Cannot remove the last active admin"


def _generate_temp_password() -> str:
    """Return a fresh, unguessable temp password (URL-safe, >=16 chars).

    Uses :mod:`secrets` so the value is cryptographically random. The plaintext
    is returned to the admin once via the response and is never logged, audited,
    or persisted — only its bcrypt hash is stored.
    """
    return secrets.token_urlsafe(_TEMP_PASSWORD_BYTES)


class CreateUserRequest(BaseModel):
    """Body for ``POST /users`` — admin creates an account with a temp password."""

    username: str = Field(min_length=1, max_length=255)
    role: str = Field(min_length=1, max_length=64)
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    temp_password: str | None = Field(default=None, min_length=1, max_length=255)


class UpdateUserRequest(BaseModel):
    """Body for ``PATCH /users/{id}`` — every field optional (partial update)."""

    role: str | None = Field(default=None, min_length=1, max_length=64)
    is_active: bool | None = None
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)


class ResetPasswordRequest(BaseModel):
    """Body for ``POST /users/{id}/reset-password`` — optional explicit secret."""

    temp_password: str | None = Field(default=None, min_length=1, max_length=255)


class UserSummary(BaseModel):
    """An admin-visible account projection — never carries ``password_hash``."""

    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    role: str
    is_active: bool
    must_change_password: bool

    @classmethod
    def from_user(cls, user: User) -> UserSummary:
        """Project a :class:`User` ORM row, dropping every secret field."""
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            role=user.role.name,
            is_active=user.is_active,
            must_change_password=user.must_change_password,
        )


class CreatedUserResponse(BaseModel):
    """``POST /users`` result: the created account plus the one-time temp password.

    This is the ONLY endpoint (alongside reset-password) that ever returns a
    plaintext password, and it does so exactly once — the value is not persisted
    or audited in plaintext.
    """

    user: UserSummary
    temp_password: str


class TempPasswordResponse(BaseModel):
    """``POST /users/{id}/reset-password`` result: the one-time temp password."""

    temp_password: str


async def _resolve_role(session: AsyncSession, name: str) -> Role:
    """Resolve a wire role *name* to its :class:`Role` row or raise 400.

    Validates the name against the canonical :class:`RoleEnum` first (so an
    unknown role is a clean :class:`BadRequestError`, not a 500), then loads the
    seeded row. A known-but-unseeded role is also a 400 rather than a crash.
    """
    if RoleEnum.from_name(name) is None:
        raise BadRequestError(f"Unknown role {name!r}")
    row = (await session.execute(select(Role).where(Role.name == name))).scalar_one_or_none()
    if row is None:
        raise BadRequestError(f"Unknown role {name!r}")
    return row


async def _count_other_active_admins(session: AsyncSession, *, exclude_id: uuid.UUID) -> int:
    """Count active users with the ``admin`` role other than *exclude_id*.

    Used by the last-admin guard: a demotion/deactivation of the target is only
    safe when at least one *other* active admin remains.
    """
    count = (
        await session.execute(
            select(func.count())
            .select_from(User)
            .join(Role, User.role_id == Role.id)
            .where(
                Role.name == RoleEnum.ADMIN.value,
                User.is_active.is_(True),
                User.id != exclude_id,
            )
        )
    ).scalar_one()
    return int(count)


async def _load_user(session: AsyncSession, user_id: uuid.UUID) -> User:
    """Load a :class:`User` by id or raise 404 (no oracle beyond existence)."""
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise NotFoundError("User not found")
    return user


@router.get("/users", response_model=list[UserSummary])
async def list_users(
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[UserSummary]:
    """List every account (admin only); never includes password hashes."""
    rows = (await session.execute(select(User).order_by(User.username))).scalars().all()
    return [UserSummary.from_user(row) for row in rows]


@router.post("/users", response_model=CreatedUserResponse, status_code=201)
async def create_user(
    body: CreateUserRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> CreatedUserResponse:
    """Create an account with a temp password (admin only).

    The role name must be one of the four RBAC roles (else 400). A duplicate
    username or email is 409. When ``temp_password`` is omitted a strong random
    one is generated. The new account is forced to change its password on first
    login (``must_change_password=True``); only the bcrypt hash is stored. The
    plaintext temp password is returned exactly once and never audited.
    """
    role = await _resolve_role(session, body.role)

    clash_username = (
        await session.execute(select(User.id).where(User.username == body.username))
    ).scalar_one_or_none()
    if clash_username is not None:
        raise ConflictError(_USERNAME_TAKEN)
    if body.email is not None:
        clash_email = (
            await session.execute(select(User.id).where(User.email == body.email))
        ).scalar_one_or_none()
        if clash_email is not None:
            raise ConflictError(_EMAIL_TAKEN)

    temp_password = body.temp_password or _generate_temp_password()
    user = User(
        username=body.username,
        password_hash=await hash_password_async(temp_password),
        role=role,
        email=body.email,
        display_name=body.display_name,
        must_change_password=True,
    )
    session.add(user)
    await session.flush()

    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.USER_CREATED,
        target_type="user",
        target_id=str(user.id),
        detail={"username": user.username, "role": role.name},
    )
    await session.commit()
    await session.refresh(user)
    return CreatedUserResponse(user=UserSummary.from_user(user), temp_password=temp_password)


@router.get("/users/{user_id}", response_model=UserSummary)
async def get_user(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> UserSummary:
    """Return one account by id (admin only); 404 if unknown."""
    user = await _load_user(session, user_id)
    return UserSummary.from_user(user)


@router.patch("/users/{user_id}", response_model=UserSummary)
async def update_user(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> UserSummary:
    """Update an account's role / active flag / email / display name (admin only).

    Audits ``user.role_changed`` when the role changes, else ``user.updated``.
    Deactivating a user (``is_active`` to ``False``) revokes all that user's live
    sessions. The last-admin guard returns 409 if demoting-from-admin or
    deactivating the target would leave zero other active admins.
    """
    user = await _load_user(session, user_id)

    role_changed = False
    if body.role is not None and body.role != user.role.name:
        new_role = await _resolve_role(session, body.role)
        # Last-admin guard: demoting the final active admin would lock everyone out.
        if (
            user.role.name == RoleEnum.ADMIN.value
            and new_role.name != RoleEnum.ADMIN.value
            and user.is_active
            and await _count_other_active_admins(session, exclude_id=user.id) == 0
        ):
            raise ConflictError(_LAST_ADMIN)
        user.role = new_role
        role_changed = True

    deactivating = body.is_active is False and user.is_active
    if body.is_active is not None and body.is_active != user.is_active:
        # Last-admin guard: deactivating the final active admin locks everyone out.
        if (
            deactivating
            and user.role.name == RoleEnum.ADMIN.value
            and await _count_other_active_admins(session, exclude_id=user.id) == 0
        ):
            raise ConflictError(_LAST_ADMIN)
        user.is_active = body.is_active

    if body.email is not None and body.email != user.email:
        clash = (
            await session.execute(
                select(User.id).where(User.email == body.email, User.id != user.id)
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise ConflictError(_EMAIL_TAKEN)
        user.email = body.email
    if body.display_name is not None:
        user.display_name = body.display_name

    if deactivating:
        await session_service.revoke_all_for_user(session, user_id=user.id)

    action = audit_service.USER_ROLE_CHANGED if role_changed else audit_service.USER_UPDATED
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=action,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    await session.refresh(user)
    return UserSummary.from_user(user)


@router.post("/users/{user_id}/reset-password", response_model=TempPasswordResponse)
async def reset_user_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TempPasswordResponse:
    """Set a forced-change temp password for an account (admin only).

    Generates a strong random temp password when one is not supplied, stores its
    bcrypt hash, sets ``must_change_password``, and revokes every live session of
    the target. Audits ``user.password_reset`` (never with the plaintext). The
    plaintext is returned exactly once.
    """
    user = await _load_user(session, user_id)
    temp_password = body.temp_password or _generate_temp_password()
    user.password_hash = await hash_password_async(temp_password)
    user.must_change_password = True

    await session_service.revoke_all_for_user(session, user_id=user.id)
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.USER_PASSWORD_RESET,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return TempPasswordResponse(temp_password=temp_password)


@router.post("/users/{user_id}/revoke-sessions", status_code=200)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, int]:
    """Revoke every live session of an account (admin only); audit the revoke."""
    user = await _load_user(session, user_id)
    count = await session_service.revoke_all_for_user(session, user_id=user.id)
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.AUTH_SESSION_REVOKED,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return {"revoked": count}
