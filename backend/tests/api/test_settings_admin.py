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
LLM_PROFILE_URL = "/api/v1/auth/llm-profile"
LLM_READINESS_URL = "/api/v1/auth/settings/llm-readiness"
LLM_TEST_URL = "/api/v1/auth/settings/llm-test"
OIDC_STATUS_URL = "/api/v1/auth/settings/oidc-status"

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


def _assert_no_secret_keys(payload: object) -> None:
    """Reject secret-hint field names at any nesting depth."""
    if isinstance(payload, dict):
        for field, value in payload.items():
            lowered = str(field).lower()
            assert not any(hint in lowered for hint in _SECRET_FIELD_HINTS), field
            _assert_no_secret_keys(value)
    elif isinstance(payload, list):
        for item in payload:
            _assert_no_secret_keys(item)


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
# GET /llm-profile — any authenticated user (shell badge)                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("role", ["viewer", "operator", "engineer", "admin"])
async def test_get_llm_profile_allowed_for_any_authenticated(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.get(LLM_PROFILE_URL, headers=auth_headers(role))
    assert resp.status_code == 200
    body = resp.json()
    assert body["llm_profile"] == "local"
    _assert_no_secret_keys(body)


async def test_get_llm_profile_unauthenticated_is_401(client, users) -> None:
    resp = await client.get(LLM_PROFILE_URL)
    assert resp.status_code == 401


async def test_get_llm_profile_follows_db_row(
    client, users, session: AsyncSession, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    session.add(
        SystemSetting(
            llm_profile="openai",
            llm_role_reasoning=None,
            llm_role_fast=None,
        )
    )
    await session.commit()
    resp = await client.get(LLM_PROFILE_URL, headers=auth_headers("viewer"))
    assert resp.status_code == 200
    assert resp.json()["llm_profile"] == "openai"


# --------------------------------------------------------------------------- #
# GET /settings/oidc-status (admin)                                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_oidc_status_forbidden_for_non_admin(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.get(OIDC_STATUS_URL, headers=auth_headers(role))
    assert resp.status_code == 403


async def test_oidc_status_disabled_by_default(
    client, users, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.get(OIDC_STATUS_URL, headers=_admin(auth_headers))
    assert resp.status_code == 200
    body = resp.json()
    _assert_no_secret_keys(body)
    assert body["enabled"] is False
    assert body["issuer_configured"] is False
    assert body["client_id_configured"] is False
    assert body["client_ref_configured"] is False
    assert body["break_glass_local_admin_only"] is False
    assert "redirect_uri" in body
    # Never surface vault ref field names or values — presence is client_ref_configured.
    assert "oidc_client_secret_ref" not in body


async def test_oidc_status_enabled_when_fully_configured(
    client,
    app,
    users,
    auth_headers: Callable[[str], dict[str, str]],
) -> None:
    app.state.settings = app.state.settings.model_copy(
        update={
            "oidc_issuer": "https://idp.example/realms/netops",
            "oidc_client_id": "netops-spa",
            "oidc_client_secret_ref": "vault/oidc-client",
            "oidc_redirect_uri": "https://app.example/api/v1/auth/oidc/callback",
            "oidc_allow_admin": True,
        }
    )
    resp = await client.get(OIDC_STATUS_URL, headers=_admin(auth_headers))
    assert resp.status_code == 200
    body = resp.json()
    _assert_no_secret_keys(body)
    assert body["enabled"] is True
    assert body["issuer_configured"] is True
    assert body["client_id_configured"] is True
    assert body["client_ref_configured"] is True
    assert body["break_glass_local_admin_only"] is True
    assert body["allow_admin_via_oidc"] is True
    assert body["redirect_uri"] == "https://app.example/api/v1/auth/oidc/callback"
    # Vault ref string itself must never appear.
    assert "vault/oidc-client" not in resp.text
    assert "https://idp.example" not in resp.text  # issuer URL not returned


# --------------------------------------------------------------------------- #
# GET /settings/llm-readiness + POST /settings/llm-test (admin)               #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_llm_readiness_forbidden_for_non_admin(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.get(LLM_READINESS_URL, headers=auth_headers(role))
    assert resp.status_code == 403


async def test_llm_readiness_admin_ok_no_secret_fields(
    client, users, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.get(LLM_READINESS_URL, headers=_admin(auth_headers))
    assert resp.status_code == 200
    body = resp.json()
    _assert_no_secret_keys(body)
    assert body["active_profile"] == "local"
    assert "local_model" in body
    profiles = {row["profile"]: row for row in body["profiles"]}
    assert profiles["local"]["configured"] is True
    assert profiles["anthropic"]["configured"] is False
    assert profiles["anthropic"]["egress"] is True


@pytest.mark.parametrize("role", ["viewer", "operator", "engineer"])
async def test_llm_test_forbidden_for_non_admin(
    client, users, auth_headers: Callable[[str], dict[str, str]], role: str
) -> None:
    resp = await client.post(LLM_TEST_URL, headers=auth_headers(role), json={"profile": "local"})
    assert resp.status_code == 403


async def test_llm_test_unknown_profile_is_400(
    client, users, auth_headers: Callable[[str], dict[str, str]]
) -> None:
    resp = await client.post(
        LLM_TEST_URL, headers=_admin(auth_headers), json={"profile": "bedrock"}
    )
    assert resp.status_code == 400


async def test_llm_test_local_probes_and_audits(
    client,
    users,
    session: AsyncSession,
    auth_headers: Callable[[str], dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.llm import readiness

    async def fake_get(url: str, *, headers: dict[str, str] | None = None) -> object:
        return {"models": [{"name": "llama3.1:8b"}]}

    monkeypatch.setattr(readiness, "_http_get_json", fake_get)
    resp = await client.post(LLM_TEST_URL, headers=_admin(auth_headers), json={"profile": "local"})
    assert resp.status_code == 200
    body = resp.json()
    _assert_no_secret_keys(body)
    assert body["profile"] == "local"
    assert body["status"] == "ready"
    assert "llama3.1:8b" in body["models"]

    rows = await _audit_rows(session, "llm.connection_tested")
    assert len(rows) == 1
    assert rows[0].detail["profile"] == "local"
    assert rows[0].detail["status"] == "ready"
    # Audit detail must not carry secret-ish keys either.
    _assert_no_secret_keys(rows[0].detail)


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
