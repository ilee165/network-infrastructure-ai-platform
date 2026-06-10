"""Settings tests: canonical defaults, env overrides, caching, prod hardening."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings


def test_canonical_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.env == "dev"
    assert settings.database_url == "postgresql+asyncpg://netops:netops@postgres:5432/netops"
    assert settings.redis_url == "redis://redis:6379/0"
    assert settings.neo4j_uri == "bolt://neo4j:7687"
    assert settings.neo4j_user == "neo4j"
    assert settings.llm_profile == "local"
    assert settings.ollama_base_url == "http://ollama:11434"
    assert isinstance(settings.cors_origins, list)


def test_env_vars_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETOPS_LLM_PROFILE", "anthropic")
    monkeypatch.setenv("NETOPS_REDIS_URL", "redis://10.0.0.5:6379/2")
    settings = Settings(_env_file=None)
    assert settings.llm_profile == "anthropic"
    assert settings.redis_url == "redis://10.0.0.5:6379/2"


def test_cors_origins_parse_from_json_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "NETOPS_CORS_ORIGINS", '["https://ops.example.com", "https://noc.example.com"]'
    )
    settings = Settings(_env_file=None)
    assert settings.cors_origins == ["https://ops.example.com", "https://noc.example.com"]


def test_env_rejects_unknown_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETOPS_ENV", "staging")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETOPS_ENV", "dev")
    first = get_settings()
    second = get_settings()
    assert first is second


def test_prod_rejects_default_secret_key() -> None:
    with pytest.raises(ValidationError, match="NETOPS_SECRET_KEY"):
        Settings(_env_file=None, env="prod")


def test_prod_accepts_explicit_secret_key() -> None:
    settings = Settings(_env_file=None, env="prod", secret_key="a-strong-operator-chosen-key")
    assert settings.env == "prod"
