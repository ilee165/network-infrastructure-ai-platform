"""Application settings loaded from the environment (canonical ``NETOPS_`` prefix).

The canonical M0 environment contract (one variable per field below) is shared
by the API container, the Celery worker, alembic, and docker compose — do not
rename fields without an ADR.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Development-only fallback. ``Settings`` refuses to start with this value in prod.
_DEV_ONLY_SECRET_KEY = "dev-only-insecure-secret-key-change-me"


class Settings(BaseSettings):
    """Runtime configuration for every backend entrypoint (api, worker, alembic)."""

    model_config = SettingsConfigDict(
        env_prefix="NETOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    #: Deployment environment. Controls log rendering and secret-key validation.
    env: Literal["dev", "prod"] = "dev"

    #: HS256 signing key for JWT access tokens (core/security.py). Required in prod.
    secret_key: str = _DEV_ONLY_SECRET_KEY

    #: Async SQLAlchemy DSN — asyncpg driver; host is the compose service name.
    database_url: str = "postgresql+asyncpg://netops:netops@postgres:5432/netops"

    #: Celery broker/result backend + cache (ADR-0008).
    redis_url: str = "redis://redis:6379/0"

    #: Neo4j topology/knowledge graph (ADR-0005).
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"

    #: LLM provider profile (ADR-0009): local (Ollama, default) | anthropic | openai | azure.
    llm_profile: str = "local"

    #: Ollama endpoint — compose service ``ollama`` under the "local-llm" profile.
    ollama_base_url: str = "http://ollama:11434"

    #: Allowed browser origins; set via a JSON list, e.g. ``["https://ops.example.com"]``.
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    #: JWT access-token lifetime in minutes (core/security.py default expiry).
    access_token_expire_minutes: int = 30

    #: Credential-vault master key (ADR-0011): urlsafe-base64, decodes to 32 bytes.
    #: Consumed by ``core/crypto.EnvKeyProvider``; never logged or serialized.
    kek: SecretStr | None = None

    #: Path to a file holding the urlsafe-base64 KEK (mounted Docker/K8s secret).
    #: Consumed by ``core/crypto.FileKeyProvider``; ``kek`` wins when both are set.
    kek_file: Path | None = None

    #: Version label stored with every wrapped DEK; bump together with KEK rotation.
    kek_version: str = "v1"

    @model_validator(mode="after")
    def _forbid_default_secret_in_prod(self) -> Settings:
        """Secure by default: the baked-in dev key must never sign prod tokens."""
        if self.env == "prod" and self.secret_key == _DEV_ONLY_SECRET_KEY:
            raise ValueError(
                "NETOPS_SECRET_KEY must be set to a strong unique value when NETOPS_ENV=prod"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached :class:`Settings` instance.

    Tests construct :class:`Settings` directly (or clear this cache) instead of
    mutating the returned instance.
    """
    return Settings()
