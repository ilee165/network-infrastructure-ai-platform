"""Persistence, transaction, and audit service for admin user management."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import BadRequestError, ConflictError, NotFoundError
from app.core.security import Role as RoleEnum
from app.core.security import hash_password_async
from app.models import Role, User
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service

_TEMP_PASSWORD_BYTES: Final = 16
_EMAIL_TAKEN: Final = "That email is already in use"
_USERNAME_TAKEN: Final = "That username is already in use"
_LAST_ADMIN: Final = "Cannot remove the last active admin"


@dataclass(frozen=True, slots=True)
class CreatedUser:
    """A created account and its one-time plaintext temporary password."""

    user: User
    temp_password: str


@dataclass(frozen=True, slots=True)
class UserUpdate:
    """Validated optional fields accepted by the admin update endpoint."""

    role: str | None
    is_active: bool | None
    email: str | None
    display_name: str | None


def _generate_temp_password() -> str:
    return secrets.token_urlsafe(_TEMP_PASSWORD_BYTES)


class UserService:
    """Own relational access, account writes, audits, and commit boundaries."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _resolve_role(self, name: str) -> Role:
        if RoleEnum.from_name(name) is None:
            raise BadRequestError(f"Unknown role {name!r}")
        row = (
            await self._session.execute(select(Role).where(Role.name == name))
        ).scalar_one_or_none()
        if row is None:
            raise BadRequestError(f"Unknown role {name!r}")
        return row

    async def _count_other_active_admins(self, *, exclude_id: uuid.UUID) -> int:
        count = (
            await self._session.execute(
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

    async def _get(self, user_id: uuid.UUID) -> User:
        user = (
            await self._session.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if user is None:
            raise NotFoundError("User not found")
        return user

    async def list(self) -> list[User]:
        return list(
            (await self._session.execute(select(User).order_by(User.username))).scalars().all()
        )

    async def get(self, user_id: uuid.UUID) -> User:
        return await self._get(user_id)

    async def create(
        self,
        *,
        username: str,
        role_name: str,
        email: str | None,
        display_name: str | None,
        temp_password: str | None,
        actor_username: str,
    ) -> CreatedUser:
        role = await self._resolve_role(role_name)
        clash_username = (
            await self._session.execute(select(User.id).where(User.username == username))
        ).scalar_one_or_none()
        if clash_username is not None:
            raise ConflictError(_USERNAME_TAKEN)
        if email is not None:
            clash_email = (
                await self._session.execute(select(User.id).where(User.email == email))
            ).scalar_one_or_none()
            if clash_email is not None:
                raise ConflictError(_EMAIL_TAKEN)

        plaintext = temp_password or _generate_temp_password()
        user = User(
            username=username,
            password_hash=await hash_password_async(plaintext),
            role=role,
            email=email,
            display_name=display_name,
            must_change_password=True,
        )
        self._session.add(user)
        await self._session.flush()
        await audit_service.record(
            self._session,
            actor=f"user:{actor_username}",
            action=audit_service.USER_CREATED,
            target_type="user",
            target_id=str(user.id),
            detail={"username": user.username, "role": role.name},
        )
        await self._session.commit()
        await self._session.refresh(user)
        return CreatedUser(user=user, temp_password=plaintext)

    async def update(self, user_id: uuid.UUID, update: UserUpdate, *, actor_username: str) -> User:
        user = await self._get(user_id)
        role_changed = False
        if update.role is not None and update.role != user.role.name:
            new_role = await self._resolve_role(update.role)
            if (
                user.role.name == RoleEnum.ADMIN.value
                and new_role.name != RoleEnum.ADMIN.value
                and user.is_active
                and await self._count_other_active_admins(exclude_id=user.id) == 0
            ):
                raise ConflictError(_LAST_ADMIN)
            user.role = new_role
            role_changed = True

        deactivating = update.is_active is False and user.is_active
        if update.is_active is not None and update.is_active != user.is_active:
            if (
                deactivating
                and user.role.name == RoleEnum.ADMIN.value
                and await self._count_other_active_admins(exclude_id=user.id) == 0
            ):
                raise ConflictError(_LAST_ADMIN)
            user.is_active = update.is_active

        if update.email is not None and update.email != user.email:
            clash = (
                await self._session.execute(
                    select(User.id).where(User.email == update.email, User.id != user.id)
                )
            ).scalar_one_or_none()
            if clash is not None:
                raise ConflictError(_EMAIL_TAKEN)
            user.email = update.email
        if update.display_name is not None:
            user.display_name = update.display_name

        if deactivating:
            await session_service.revoke_all_for_user(self._session, user_id=user.id)
        action = audit_service.USER_ROLE_CHANGED if role_changed else audit_service.USER_UPDATED
        await audit_service.record(
            self._session,
            actor=f"user:{actor_username}",
            action=action,
            target_type="user",
            target_id=str(user.id),
            detail=None,
        )
        await self._session.commit()
        await self._session.refresh(user)
        return user

    async def reset_password(
        self,
        user_id: uuid.UUID,
        temp_password: str | None,
        *,
        actor_username: str,
    ) -> str:
        user = await self._get(user_id)
        plaintext = temp_password or _generate_temp_password()
        user.password_hash = await hash_password_async(plaintext)
        user.must_change_password = True
        await session_service.revoke_all_for_user(self._session, user_id=user.id)
        await audit_service.record(
            self._session,
            actor=f"user:{actor_username}",
            action=audit_service.USER_PASSWORD_RESET,
            target_type="user",
            target_id=str(user.id),
            detail=None,
        )
        await self._session.commit()
        return plaintext

    async def revoke_sessions(self, user_id: uuid.UUID, *, actor_username: str) -> int:
        user = await self._get(user_id)
        count = await session_service.revoke_all_for_user(self._session, user_id=user.id)
        await audit_service.record(
            self._session,
            actor=f"user:{actor_username}",
            action=audit_service.AUTH_SESSION_REVOKED,
            target_type="user",
            target_id=str(user.id),
            detail=None,
        )
        await self._session.commit()
        return count
