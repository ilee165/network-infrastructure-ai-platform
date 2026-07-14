"""Admin user management (Auth & Account UI, B4): admin-only CRUD over accounts.

Every route here is gated by ``require_role("admin")``. No endpoint ever puts a
password hash in a response body or an audit detail, and the temp password
generated/accepted for create + reset is returned EXACTLY once (in the create
and reset responses) — never logged and never written to an audit ``detail``.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import Depends
from pydantic import BaseModel, Field

from app.api.deps import get_db, require_role
from app.api.v1.auth._shared import router
from app.services.users import UserService, UserUpdate


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
    def from_user(cls, user: Any) -> UserSummary:
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


Admin = Annotated[Any, Depends(require_role("admin"))]


def get_user_service(session: Annotated[Any, Depends(get_db)]) -> UserService:
    """Bind admin-user persistence to the request's overridable session."""
    return UserService(session)


Service = Annotated[UserService, Depends(get_user_service)]


@router.get("/users", response_model=list[UserSummary])
async def list_users(
    admin: Admin,
    service: Service,
) -> list[UserSummary]:
    """List every account (admin only); never includes password hashes."""
    rows = await service.list()
    return [UserSummary.from_user(row) for row in rows]


@router.post("/users", response_model=CreatedUserResponse, status_code=201)
async def create_user(
    body: CreateUserRequest,
    admin: Admin,
    service: Service,
) -> CreatedUserResponse:
    """Create an account with a temp password (admin only).

    The role name must be one of the four RBAC roles (else 400). A duplicate
    username or email is 409. When ``temp_password`` is omitted a strong random
    one is generated. The new account is forced to change its password on first
    login (``must_change_password=True``); only the bcrypt hash is stored. The
    plaintext temp password is returned exactly once and never audited.
    """
    created = await service.create(
        username=body.username,
        role_name=body.role,
        email=body.email,
        display_name=body.display_name,
        temp_password=body.temp_password,
        actor_username=admin.username,
    )
    return CreatedUserResponse(
        user=UserSummary.from_user(created.user), temp_password=created.temp_password
    )


@router.get("/users/{user_id}", response_model=UserSummary)
async def get_user(
    user_id: uuid.UUID,
    admin: Admin,
    service: Service,
) -> UserSummary:
    """Return one account by id (admin only); 404 if unknown."""
    user = await service.get(user_id)
    return UserSummary.from_user(user)


@router.patch("/users/{user_id}", response_model=UserSummary)
async def update_user(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    admin: Admin,
    service: Service,
) -> UserSummary:
    """Update an account's role / active flag / email / display name (admin only).

    Audits ``user.role_changed`` when the role changes, else ``user.updated``.
    Deactivating a user (``is_active`` to ``False``) revokes all that user's live
    sessions. The last-admin guard returns 409 if demoting-from-admin or
    deactivating the target would leave zero other active admins.
    """
    user = await service.update(
        user_id,
        UserUpdate(
            role=body.role,
            is_active=body.is_active,
            email=body.email,
            display_name=body.display_name,
        ),
        actor_username=admin.username,
    )
    return UserSummary.from_user(user)


@router.post("/users/{user_id}/reset-password", response_model=TempPasswordResponse)
async def reset_user_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    admin: Admin,
    service: Service,
) -> TempPasswordResponse:
    """Set a forced-change temp password for an account (admin only).

    Generates a strong random temp password when one is not supplied, stores its
    bcrypt hash, sets ``must_change_password``, and revokes every live session of
    the target. Audits ``user.password_reset`` (never with the plaintext). The
    plaintext is returned exactly once.
    """
    temp_password = await service.reset_password(
        user_id, body.temp_password, actor_username=admin.username
    )
    return TempPasswordResponse(temp_password=temp_password)


@router.post("/users/{user_id}/revoke-sessions", status_code=200)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    admin: Admin,
    service: Service,
) -> dict[str, int]:
    """Revoke every live session of an account (admin only); audit the revoke."""
    count = await service.revoke_sessions(user_id, actor_username=admin.username)
    return {"revoked": count}
