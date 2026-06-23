"""Credential vault routes (M1-15): create, rotate, list — secrets write-only.

The secret enters as a :class:`~pydantic.SecretStr`, goes straight into the
envelope-encryption service (ADR-0011), and never appears in any response,
log line, or audit detail. Reads expose metadata only via
:class:`~app.schemas.credentials.CredentialRead`. Mutations require the
``engineer`` rank; the service writes the ``credential.created`` /
``credential.rotated`` audit rows, committed atomically here.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.deps import get_app_settings, get_db, get_sessionmaker, require_role
from app.core import crypto
from app.core.config import Settings
from app.core.errors import ConflictError
from app.models import DeviceCredential, User
from app.schemas.credentials import (
    CredentialCreate,
    CredentialListResponse,
    CredentialRead,
    CredentialRotate,
)
from app.services import credentials as credentials_service

router = APIRouter(prefix="/credentials", tags=["credentials"])


def get_key_provider(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> crypto.KeyProvider:
    """The configured KEK provider; overridable in tests (no real KEK needed)."""
    return crypto.get_key_provider(settings)


DbSession = Annotated[AsyncSession, Depends(get_db)]
Sessionmaker = Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)]
Engineer = Annotated[User, Depends(require_role("engineer"))]
Viewer = Annotated[User, Depends(require_role("viewer"))]
Provider = Annotated[crypto.KeyProvider, Depends(get_key_provider)]


def _actor(user: User) -> str:
    return f"user:{user.username}"


@router.post("", response_model=CredentialRead, status_code=201)
async def create_credential(
    body: CredentialCreate,
    session: DbSession,
    sessionmaker: Sessionmaker,
    provider: Provider,
    user: Engineer,
) -> CredentialRead:
    """Encrypt and store a new credential; the service audits ``credential.created``."""
    existing = (
        await session.execute(select(DeviceCredential.id).where(DeviceCredential.name == body.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(f"a credential named {body.name!r} already exists")
    credential = await credentials_service.create_credential(
        session,
        provider,
        name=body.name,
        kind=body.kind,
        username=body.username,
        secret=body.secret.get_secret_value(),
        params=body.params,
        actor=_actor(user),
        sessionmaker=sessionmaker,
    )
    response = CredentialRead.model_validate(credential)
    await session.commit()
    return response


@router.post("/{credential_id}/rotate", response_model=CredentialRead)
async def rotate_credential(
    credential_id: uuid.UUID,
    body: CredentialRotate,
    session: DbSession,
    sessionmaker: Sessionmaker,
    provider: Provider,
    user: Engineer,
) -> CredentialRead:
    """Replace the secret payload (fresh DEK/nonces); audits ``credential.rotated``."""
    credential = await credentials_service.rotate_secret(
        session,
        provider,
        credential_id=credential_id,
        new_secret=body.secret.get_secret_value(),
        actor=_actor(user),
        sessionmaker=sessionmaker,
    )
    response = CredentialRead.model_validate(credential)
    await session.commit()
    return response


@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    session: DbSession,
    _user: Viewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CredentialListResponse:
    """List credential metadata (never secrets), paginated, ordered by name."""
    total = (await session.execute(select(func.count()).select_from(DeviceCredential))).scalar_one()
    rows = (
        (
            await session.execute(
                select(DeviceCredential).order_by(DeviceCredential.name).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return CredentialListResponse(
        items=[CredentialRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
