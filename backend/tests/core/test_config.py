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


def test_is_prod_true_rejects_default_secret_key_even_when_env_dev() -> None:
    """CR1: the default-secret guard keys off settings.production (NETOPS_IS_PROD)."""
    with pytest.raises(ValidationError, match="NETOPS_SECRET_KEY"):
        Settings(_env_file=None, env="dev", is_prod=True)


def test_is_prod_true_accepts_explicit_secret_key() -> None:
    settings = Settings(
        _env_file=None, env="dev", is_prod=True, secret_key="a-strong-operator-chosen-key"
    )
    assert settings.production is True


def test_is_prod_false_overrides_env_prod_and_allows_default_secret() -> None:
    """Explicit NETOPS_IS_PROD=false declares non-prod even with NETOPS_ENV=prod."""
    settings = Settings(_env_file=None, env="prod", is_prod=False)
    assert settings.production is False


# ---------------------------------------------------------------------------
# Audit→SIEM export knobs (ADR-0045) — TLS-only endpoint + bounded/positive cycle
# ---------------------------------------------------------------------------


def test_https_json_export_rejects_non_https_endpoint() -> None:
    """CR[2]: a http:// endpoint for https-json is refused (no cleartext audit/token)."""
    with pytest.raises(ValidationError, match="https://"):
        Settings(
            _env_file=None,
            audit_export_format="https-json",
            audit_export_endpoint="http://siem.example.test/collector",
        )


def test_https_json_export_accepts_https_endpoint() -> None:
    settings = Settings(
        _env_file=None,
        audit_export_format="https-json",
        audit_export_endpoint="https://siem.example.test/collector",
    )
    assert settings.audit_export_endpoint == "https://siem.example.test/collector"


def test_syslog_export_endpoint_scheme_not_enforced() -> None:
    """The https-only guard applies ONLY to the https-json format (syslog uses host)."""
    settings = Settings(
        _env_file=None,
        audit_export_format="syslog",
        audit_export_host="siem.example.test",
        # An endpoint value is irrelevant for syslog; the https guard must not fire.
        audit_export_endpoint="http://ignored.example.test",
    )
    assert settings.audit_export_format == "syslog"


def test_export_batch_size_must_be_positive() -> None:
    """CR[3]: batch_size < 1 → read_unexported(limit=0) exports nothing (silent loss)."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, audit_export_batch_size=0)


def test_export_poll_seconds_must_be_positive() -> None:
    """CR[3]: a non-positive poll interval busy-spins the caught-up loop."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, audit_export_poll_seconds=0.0)


def test_export_retry_backoff_must_be_positive() -> None:
    """CR[3]: a non-positive backoff busy-spins the retry loop against a down sink."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, audit_export_retry_backoff_seconds=-1.0)
