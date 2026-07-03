"""System settings — DB-persisted LLM profile + role map (admin only).

Only the LLM *profile choice* (``llm_profile`` + the ``reasoning``/``fast``
role map) is DB-persisted; the LLM registry reads the single ``system_settings``
row at runtime (env is the fallback). Provider API keys and the Ollama endpoint
stay in env/``Settings`` and are NEVER accepted in a request body nor returned in
a response — these schemas have no field for them, and unknown body fields are
ignored by pydantic.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_app_settings, get_db, require_role
from app.api.v1.auth._shared import router
from app.core.config import Settings
from app.core.errors import BadRequestError
from app.llm.providers import KNOWN_PROFILES
from app.models import SystemSetting, User
from app.services.audit import service as audit_service


def _validate_profile(value: str | None) -> str | None:
    """Reject any profile name not in :data:`KNOWN_PROFILES` (``None`` passes)."""
    if value is not None and value not in KNOWN_PROFILES:
        raise BadRequestError(
            f"unknown LLM profile {value!r}; known profiles: {', '.join(KNOWN_PROFILES)}"
        )
    return value


class SystemSettingsResponse(BaseModel):
    """The effective LLM profile selection (DB row, or env fallback)."""

    llm_profile: str
    llm_role_reasoning: str | None
    llm_role_fast: str | None


class UpdateSettingsRequest(BaseModel):
    """Body for ``PATCH /settings`` — every field optional (partial update).

    A field that is *omitted* is left unchanged; a field set to ``null``
    explicitly clears that override. ``llm_profile`` cannot be cleared (the row
    always carries a base profile). Profile names are validated against
    :data:`KNOWN_PROFILES`; an unknown name is a 400. No key/endpoint field
    exists, so secrets cannot be supplied here.
    """

    model_config = {"extra": "ignore"}

    llm_profile: str | None = Field(default=None, max_length=64)
    llm_role_reasoning: str | None = Field(default=None, max_length=128)
    llm_role_fast: str | None = Field(default=None, max_length=128)

    @field_validator("llm_profile", "llm_role_reasoning", "llm_role_fast")
    @classmethod
    def _known_profile(cls, value: str | None) -> str | None:
        return _validate_profile(value)


async def _load_settings_row(session: AsyncSession) -> SystemSetting | None:
    """Return the single ``system_settings`` row, or ``None`` when unset."""
    result = await session.execute(select(SystemSetting).order_by(SystemSetting.id).limit(1))
    return result.scalar_one_or_none()


@router.get("/settings", response_model=SystemSettingsResponse)
async def get_app_system_settings(
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SystemSettingsResponse:
    """Return the effective LLM profile selection (admin only).

    Reads the single ``system_settings`` row; when no row exists yet, falls
    back to the env :class:`Settings` values so a fresh deployment reports its
    real (env) configuration. Never returns API keys or endpoints.
    """
    row = await _load_settings_row(session)
    if row is None:
        return SystemSettingsResponse(
            llm_profile=settings.llm_profile,
            llm_role_reasoning=settings.llm_role_reasoning,
            llm_role_fast=settings.llm_role_fast,
        )
    return SystemSettingsResponse(
        llm_profile=row.llm_profile,
        llm_role_reasoning=row.llm_role_reasoning,
        llm_role_fast=row.llm_role_fast,
    )


@router.patch("/settings", response_model=SystemSettingsResponse)
async def update_app_system_settings(
    body: UpdateSettingsRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SystemSettingsResponse:
    """Upsert the single LLM settings row (admin only).

    Validates ``llm_profile`` and each role override against
    :data:`KNOWN_PROFILES` (an unknown name is a 400). Omitted fields are left
    unchanged; a field set explicitly to ``null`` clears that role override.
    Audits ``settings.updated`` with only the resulting profile selection — no
    secret material. API keys and endpoints are never accepted (no body field
    exists for them) nor stored.
    """
    provided = body.model_fields_set
    row = await _load_settings_row(session)
    if row is None:
        # Seed from env so an omitted field keeps the deployment's current
        # (env) value rather than silently resetting to the column default.
        row = SystemSetting(
            llm_profile=settings.llm_profile,
            llm_role_reasoning=settings.llm_role_reasoning,
            llm_role_fast=settings.llm_role_fast,
        )
        session.add(row)

    if "llm_profile" in provided and body.llm_profile is not None:
        row.llm_profile = body.llm_profile
    if "llm_role_reasoning" in provided:
        row.llm_role_reasoning = body.llm_role_reasoning
    if "llm_role_fast" in provided:
        row.llm_role_fast = body.llm_role_fast

    await session.flush()
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.SETTINGS_UPDATED,
        target_type="system_settings",
        target_id=str(row.id),
        detail={
            "llm_profile": row.llm_profile,
            "llm_role_reasoning": row.llm_role_reasoning,
            "llm_role_fast": row.llm_role_fast,
        },
    )
    await session.commit()
    await session.refresh(row)
    return SystemSettingsResponse(
        llm_profile=row.llm_profile,
        llm_role_reasoning=row.llm_role_reasoning,
        llm_role_fast=row.llm_role_fast,
    )
