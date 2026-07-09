"""Unit tests for LLM readiness / connection probes (no real network)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.core.config import Settings
from app.llm import readiness


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "OPENAI_API_VERSION",
    ):
        monkeypatch.delenv(var, raising=False)


def test_static_readiness_marks_external_not_configured_without_keys(
    settings: Settings,
) -> None:
    report = readiness.static_readiness(settings, active_profile="local")
    assert report.active_profile == "local"
    assert report.local_model == settings.llm_local_model
    by_name = {row.profile: row for row in report.profiles}
    assert by_name["local"].configured is True
    assert by_name["local"].status == "ready"
    assert by_name["local"].egress is False
    assert by_name["anthropic"].configured is False
    assert by_name["anthropic"].status == "not_configured"
    assert by_name["anthropic"].egress is True
    assert by_name["openai"].configured is False
    assert by_name["azure"].configured is False


def test_static_readiness_marks_external_configured_when_env_present(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    report = readiness.static_readiness(settings, active_profile="anthropic")
    by_name = {row.profile: row for row in report.profiles}
    assert by_name["anthropic"].configured is True
    assert by_name["anthropic"].status == "ready"
    assert by_name["openai"].configured is True
    assert by_name["azure"].configured is True


@pytest.mark.asyncio
async def test_probe_local_ready_lists_models(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_get(url: str, *, headers: dict[str, str] | None = None) -> Any:
        assert url.endswith("/api/tags")
        return {
            "models": [
                {"name": settings.llm_local_model},
                {"name": "qwen2.5:7b"},
            ]
        }

    monkeypatch.setattr(readiness, "_http_get_json", fake_get)
    result = await readiness.probe_profile("local", settings)
    assert result.status == "ready"
    assert settings.llm_local_model in result.models
    assert "qwen2.5:7b" in result.models
    assert result.egress is False


@pytest.mark.asyncio
async def test_probe_local_unreachable_on_connect_error(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_get(url: str, *, headers: dict[str, str] | None = None) -> Any:
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(readiness, "_http_get_json", fake_get)
    result = await readiness.probe_profile("local", settings)
    assert result.status == "unreachable"
    assert result.detail == "connection refused or host unreachable"
    # Must never echo the underlying exception message.
    assert result.detail is not None
    assert "boom" not in result.detail


@pytest.mark.asyncio
async def test_probe_external_not_configured_without_keys(settings: Settings) -> None:
    result = await readiness.probe_profile("anthropic", settings)
    assert result.status == "not_configured"
    assert result.configured is False


@pytest.mark.asyncio
async def test_probe_anthropic_ready(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    async def fake_get(url: str, *, headers: dict[str, str] | None = None) -> Any:
        assert "anthropic.com" in url
        assert headers is not None
        assert headers.get("x-api-key") == "sk-test"
        return {"data": []}

    monkeypatch.setattr(readiness, "_http_get_json", fake_get)
    result = await readiness.probe_profile("anthropic", settings)
    assert result.status == "ready"
    assert result.configured is True
    assert result.egress is True


@pytest.mark.asyncio
async def test_probe_unknown_profile_raises(settings: Settings) -> None:
    with pytest.raises(ValueError, match="unknown LLM profile"):
        await readiness.probe_profile("bedrock", settings)


def test_safe_detail_never_embeds_raw_message() -> None:
    assert readiness._safe_detail(httpx.TimeoutException("x")) == "probe timed out"
    assert readiness._safe_detail(ValueError("sk-live-secret")) == "ValueError"
