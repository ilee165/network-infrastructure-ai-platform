"""Admin system-settings endpoints (B5): GET/PATCH ``/api/v1/auth/settings``.

Invariants under test (security-load-bearing):

- Both ``/settings`` routes are gated by ``require_role("admin")``: a viewer /
  operator / engineer gets 403, an unauthenticated caller 401.
- GET with no row returns the env ``Settings`` values; with a row returns the
  row's values.
- PATCH upserts the single row, validates ``llm_profile`` and the role
  overrides against ``KNOWN_PROFILES`` (junk is rejected 400/422), and audits
  ``settings.updated``.
- The request body NEVER accepts API keys / endpoints, and no response ever
  returns a key, endpoint, or any secret.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, SystemSetting

SETTINGS_URL = "/api/v1/auth/settings"

# Fields that must never appear in any settings request or response body.
_SECRET_FIELD_HINTS = (
    "api_key",
    "apikey",
    "key",
    "secret",
    "endpoint",
    "ollama",
    "password",
    "token",
)


def _admin(auth_headers: Callable[[str], dict[str, str]]) -> dict[str, str]:
    return auth_headers("admin")


async def _audit_rows(session: AsyncSession, action: str) -> list[AuditLog]:
    return list(
        (await session.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
    )


def _assert_no_secret_keys(payload: dict[str, object]) -> None:
    for field in payload:
        lowered = field.lower()
        assert not any(hint in lowered for hint in _SECRET_FIELD_HINTS), field


# --------------------------------------------------------------------------- #
# RBAC — both routes are admin-only                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_get_settings_forbidden_for_non_admin(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.get(SETTINGS_URL, headers=auth_headers(role))
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_patch_settings_forbidden_for_non_admin(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.patch(
        SETTINGS_URL, headers=auth_headers(role), json={"llm_profile": "openai"}
    )
    assert resp.status_code == 403


async def test_get_settings_unauthenticated_is_401(client, users) -> None:
    resp = await client.get(SETTINGS_URL)
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# GET — env fallback then DB row                                              #
# --------------------------------------------------------------------------- #
async def test_get_settings_returns_env_values_when_no_row(
    client, users, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.get(SETTINGS_URL, headers=_admin(auth_headers))
    assert resp.status_code == 200
    body = resp.json()
    # The test settings fixture runs the local profile with no role overrides.
    assert body["llm_profile"] == "local"
    assert body["llm_role_reasoning"] is None
    assert body["llm_role_fast"] is None
    _assert_no_secret_keys(body)


async def test_get_settings_returns_row_when_present(
    client, users, session: AsyncSession, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    session.add(
        SystemSetting(llm_profile="openai", llm_role_reasoning="anthropic", llm_role_fast=None)
    )
    await session.flush()

    resp = await client.get(SETTINGS_URL, headers=_admin(auth_headers))
    assert resp.status_code == 200
    body = resp.json()
    assert body["llm_profile"] == "openai"
    assert body["llm_role_reasoning"] == "anthropic"
    assert body["llm_role_fast"] is None
    _assert_no_secret_keys(body)


# --------------------------------------------------------------------------- #
# PATCH — upsert + validation + audit                                         #
# --------------------------------------------------------------------------- #
async def test_patch_creates_row_and_audits(
    client, users, session: AsyncSession, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.patch(
        SETTINGS_URL,
        headers=_admin(auth_headers),
        json={"llm_profile": "openai", "llm_role_reasoning": "anthropic"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["llm_profile"] == "openai"
    assert body["llm_role_reasoning"] == "anthropic"
    _assert_no_secret_keys(body)

    rows = (await session.execute(select(SystemSetting))).scalars().all()
    assert len(rows) == 1
    assert rows[0].llm_profile == "openai"

    audits = await _audit_rows(session, "settings.updated")
    assert len(audits) == 1
    # The audit detail must not carry any secret material.
    detail = audits[0].detail or {}
    for value in detail.values():
        assert "key" not in str(value).lower() or value in ("local", "openai", "anthropic", "azure")


async def test_patch_upserts_single_row(
    client, users, session: AsyncSession, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    session.add(SystemSetting(llm_profile="local"))
    await session.flush()

    resp = await client.patch(
        SETTINGS_URL, headers=_admin(auth_headers), json={"llm_profile": "azure"}
    )
    assert resp.status_code == 200

    rows = (await session.execute(select(SystemSetting))).scalars().all()
    assert len(rows) == 1
    assert rows[0].llm_profile == "azure"


async def test_patch_can_clear_role_override_with_null(
    client, users, session: AsyncSession, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    session.add(SystemSetting(llm_profile="openai", llm_role_reasoning="anthropic"))
    await session.flush()

    resp = await client.patch(
        SETTINGS_URL, headers=_admin(auth_headers), json={"llm_role_reasoning": None}
    )
    assert resp.status_code == 200
    assert resp.json()["llm_role_reasoning"] is None


@pytest.mark.parametrize("bad", ["junk", "gpt-4o", "", "LOCAL", "anthropics"])
async def test_patch_rejects_unknown_profile(
    client, users, auth_headers: Callable[[str], dict[str, str]], bad: str
) -> None:
    resp = await client.patch(SETTINGS_URL, headers=_admin(auth_headers), json={"llm_profile": bad})
    assert resp.status_code in (400, 422)


@pytest.mark.parametrize("bad", ["junk", "gpt-4o", "openais"])
async def test_patch_rejects_unknown_role_override(
    client, users, auth_headers: Callable[[str], dict[str, str]], bad: str
) -> None:
    resp = await client.patch(
        SETTINGS_URL, headers=_admin(auth_headers), json={"llm_role_fast": bad}
    )
    assert resp.status_code in (400, 422)


# --------------------------------------------------------------------------- #
# Secrets are never accepted nor returned                                     #
# --------------------------------------------------------------------------- #
async def test_patch_ignores_api_keys_and_endpoints_in_body(
    client, users, session: AsyncSession, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.patch(
        SETTINGS_URL,
        headers=_admin(auth_headers),
        json={
            "llm_profile": "openai",
            "openai_api_key": "sk-should-be-ignored",
            "anthropic_api_key": "should-be-ignored",
            "ollama_base_url": "http://evil:11434",
            "azure_openai_endpoint": "https://evil.example.com",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    _assert_no_secret_keys(body)
    # The stored row holds only the three settable fields; secrets never landed.
    row = (await session.execute(select(SystemSetting))).scalar_one()
    assert row.llm_profile == "openai"
    serialized = str(row.__dict__).lower()
    assert "sk-should-be-ignored" not in serialized
    assert "evil" not in serialized
