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

    #: Role -> profile indirection (ADR-0009 D2). Agents request a model by
    #: *role*; operators route the heavy "reasoning" path and the cheap "fast"
    #: summarization path to different profiles without code changes. Both
    #: default to ``llm_profile`` so a stock deployment stays fully local.
    llm_role_reasoning: str | None = None
    llm_role_fast: str | None = None

    #: Ollama endpoint — compose service ``ollama`` under the "local-llm" profile.
    ollama_base_url: str = "http://ollama:11434"

    #: Ollama model tag for the ``local`` profile (``NETOPS_LLM_LOCAL_MODEL``).
    #: Operators pick the pulled model without editing code; the default matches
    #: the historical baked-in choice so unset deployments are unchanged.
    llm_local_model: str = "llama3.1:8b"

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

    #: Nightly config-backup schedule (Celery beat, ADR-0017 §1). UTC hour/minute
    #: the ``config.nightly_backup`` task fires at; operators retune cadence
    #: without code changes. Default 02:00 UTC (a low-traffic window).
    config_backup_hour: int = 2
    config_backup_minute: int = 0

    #: Packet-analysis sandbox + pcap retention (ADR-0023). The pcap volume mount
    #: point (read-write for the capture worker, read-only for the analysis
    #: worker), the absolute tshark/tcpdump binaries the sandbox spawns by argv,
    #: the hard tshark subprocess timeout, and the retention window after which a
    #: pcap file is purged and its metadata row tombstoned. Operators retune
    #: without code changes; the defaults match ADR-0023.
    pcap_dir: Path = Path("/data/pcaps")
    tshark_bin: str = "tshark"
    tcpdump_bin: str = "tcpdump"
    packet_analysis_timeout_seconds: int = 60
    pcap_retention_days: int = 30
    #: Default capture duration/size caps (ADR-0023 §2). The engine clamps any
    #: request to MAX_DURATION_SECONDS (300) / MAX_SIZE_BYTES (50 MB).
    packet_capture_duration_seconds: int = 300
    packet_capture_size_bytes: int = 50 * 1024 * 1024

    #: packet-analysis sandbox runtime posture gate (ADR-0031 §2). The analysis
    #: worker asserts its OS-isolation posture (non-root effective UID, no
    #: CAP_NET_RAW in the permitted set, read-only root filesystem) before it
    #: spawns tshark, and refuses otherwise so a misconfigured deployment fails
    #: closed rather than silently running unconfined. ON by default
    #: (secure-by-default, opt-out only): set ``false`` ONLY for the eager
    #: unit-test/CI runner where the sandbox OS controls are not applied.
    packet_sandbox_posture_enforced: bool = True

    #: pcap-retention beat schedule (ADR-0023 §4): the UTC hour/minute the
    #: ``packet.purge_expired`` task fires at. Default 03:00 UTC.
    pcap_retention_hour: int = 3
    pcap_retention_minute: int = 0

    #: Raw-artifact retention (M5 hardening, ADR-0023 §4 parity). ``raw_artifacts``
    #: hold verbatim device CLI output captured during discovery — potentially
    #: credential-bearing text (D11). A beat job hard-deletes rows older than this
    #: window (the row *is* the sensitive payload, with no separate tombstone). A
    #: value of ``0`` disables the purge (keep-forever policy). Default 90 days,
    #: configurable per policy; fires daily at the UTC hour/minute below.
    raw_artifact_retention_days: int = 90
    raw_artifact_retention_hour: int = 4
    raw_artifact_retention_minute: int = 0

    #: OIDC / SSO identity federation (ADR-0028). OIDC is opt-in: with no
    #: configured issuer the platform stays local-only (CLAUDE.md local-first).
    #: Enabling it (a non-empty ``oidc_issuer``) fences the local-login path to
    #: break-glass admin only (ADR-0028 §5). Every field below is a
    #: per-deployment, admin-managed knob; the client secret and any IdP refresh
    #: token are vault ``credential_ref`` handles, NEVER inlined here (§6).
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    #: Vault credential_ref (NOT the value) of the confidential-client secret.
    oidc_client_secret_ref: str | None = None
    #: Redirect URI registered with the IdP (the platform callback endpoint).
    oidc_redirect_uri: str = "https://localhost/api/v1/auth/oidc/callback"
    #: Least scope set that still yields role-mapping group claims (§7).
    oidc_scopes: str = "openid profile email groups"
    #: Claim carrying the user's group/role membership (§4; Entra ``groups``).
    oidc_groups_claim: str = "groups"
    #: ``group -> platform role`` map (§4). Deny-default: a group absent from
    #: this map grants nothing; an empty map denies every federated user.
    oidc_group_role_map: dict[str, str] = Field(default_factory=dict)
    #: Opt-in for OIDC to grant ``admin`` (§4). Default false caps OIDC at
    #: ``engineer`` so production admin stays break-glass-only unless federated.
    oidc_allow_admin: bool = False
    #: JWKS cache TTL (seconds); one forced refresh on an unknown ``kid`` (§3).
    oidc_jwks_cache_ttl_secs: int = 600
    #: Bounded ``exp``/``iat``/``nbf`` leeway for IdP tokens (seconds, §3).
    oidc_clock_skew_secs: int = 120

    # -- Rate limiting + login throttle/lockout (W6-T6; PRODUCTION.md §5, ----
    # ADR-0028 §2, ADR-0008 Redis). Every knob is a per-deployment, operator-
    # managed dial with a secure default. The counters live on the shared Redis
    # (ADR-0008) so a limit holds across ``api`` replicas (D13), not in-process.
    # --------------------------------------------------------------------------

    #: Authenticated-API request budget per principal/token within
    #: :attr:`rate_limit_window_secs`. Keyed by ``user:<id>`` AND ``token:<jti>``
    #: so neither a single shared account nor a single leaked token can exceed
    #: it. The ``N+1``-th request inside the window gets ``429 + Retry-After``.
    rate_limit_requests: int = 120
    #: Fixed-window length (seconds) for the API request budget above.
    rate_limit_window_secs: int = 60

    #: Failed local break-glass logins (per account AND per source IP) allowed
    #: inside :attr:`login_lockout_window_secs` before the account/source pair is
    #: temporarily locked. Progressive: each failure inside the window counts;
    #: the ``threshold``-th trips the lockout.
    login_lockout_threshold: int = 5
    #: Sliding-window length (seconds) over which failed logins accumulate.
    login_lockout_window_secs: int = 300
    #: Temporary lockout duration (seconds) once the threshold is reached. The
    #: lock auto-expires — no operator action needed — but every lockout is
    #: audited + alerting-friendly (``auth.login_locked``).
    login_lockout_duration_secs: int = 900

    #: OIDC callback budget PER SOURCE IP within
    #: :attr:`oidc_callback_window_secs` (ADR-0028 §2): blunts ``code``/``state``
    #: flooding without blocking a legitimate single callback.
    oidc_callback_rate_limit: int = 30
    #: Fixed-window length (seconds) for the OIDC callback budget above.
    oidc_callback_window_secs: int = 60

    @property
    def oidc_enabled(self) -> bool:
        """OIDC is active only when an issuer + client id + secret-ref are set.

        With OIDC disabled the platform is purely local (ADR-0010); enabling it
        flips on the break-glass fence (ADR-0028 §5).
        """
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret_ref)

    def llm_profile_for_role(self, role: str) -> str:
        """Resolve an LLM *role* (``reasoning``/``fast``) to a configured profile.

        Each role maps to its own ``llm_role_<role>`` setting, falling back to
        the base :attr:`llm_profile` when unset — so a stock deployment runs
        every role on the local model.

        Raises
        ------
        ValueError
            When *role* is not one of the supported roles (``reasoning``,
            ``fast``). Callers in ``app/llm/providers.py`` translate this into a
            typed :class:`~app.llm.providers.LLMProfileError` before surfacing
            it to the API layer.
        """
        role_overrides = {
            "reasoning": self.llm_role_reasoning,
            "fast": self.llm_role_fast,
        }
        if role not in role_overrides:
            raise ValueError(
                f"unknown LLM role {role!r}; supported roles: {', '.join(role_overrides)}"
            )
        return role_overrides[role] or self.llm_profile

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
