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

    # -- api/worker -> Postgres mTLS (W4-T4, ADR-0039 §4) ----------------------
    # When the deployment mounts cert-manager-issued client material, the engine
    # presents a CLIENT certificate and verifies the SERVER (the ``verify-full``
    # class). All four are by-FILE references to mounted Secret keys — NEVER the
    # key bytes themselves (ADR-0039 §5: cert keys are mounted files, never inlined
    # or logged). Unset (the default) keeps the connection plaintext, unchanged —
    # mTLS is opt-in at the chart's ``mtls.postgres.enabled`` seam, which sets
    # these env. The asyncpg ``ssl`` connect-arg is built in ``app.db`` from them.
    # --------------------------------------------------------------------------

    #: libpq-class SSL mode for the DB link. ``verify-full`` (server identity +
    #: cert verified) is the ADR-0039 §4 target; ``verify-ca`` verifies the chain
    #: but not the hostname. ``None`` (default) = plaintext (no SSL connect-arg).
    db_ssl_mode: Literal["verify-ca", "verify-full"] | None = None

    #: Path to the CA bundle the client verifies the Postgres SERVER cert against
    #: (mounted ``ca.crt``). Required when :attr:`db_ssl_mode` is set — a verify
    #: mode with no trust anchor must fail closed, never silently downgrade.
    db_ssl_root_cert: Path | None = None

    #: Path to the CLIENT certificate the api/worker PRESENTS to Postgres (mounted
    #: ``tls.crt``); the server authenticates it via ``clientcert=verify-full``.
    db_ssl_cert: Path | None = None

    #: Path to the CLIENT private key for :attr:`db_ssl_cert` (mounted ``tls.key``).
    #: A mounted file only — never logged, serialized, or inlined (ADR-0039 §5).
    db_ssl_key: Path | None = None

    # -- Postgres HA: replica reads + synchronous audit commit (W1-T2, ADR-0042) --
    # The single-instance default keeps both knobs neutral: the reader URL falls
    # back to :attr:`database_url` (no second engine, no behaviour change), and the
    # audit sync-commit value is the ADR-0042 §2 ``remote_apply`` that only bites on
    # a real HA cluster with ``synchronous_standby_names`` populated (on a single
    # instance with no standbys, ``synchronous_commit`` degrades to local-durable —
    # no replica wait — so setting it is harmless there too).
    # --------------------------------------------------------------------------

    #: Async SQLAlchemy DSN for **read-only** queries routed to a streaming replica
    #: (ADR-0042 §5: replica read scale-out, pgvector verified on replicas). Points
    #: at the CloudNativePG read-only ``-ro`` service / a PgBouncer read pool in an
    #: HA deployment; ``None`` (default) routes reads at the PRIMARY via
    #: :attr:`database_url`, so a single-instance deployment is unchanged. WRITES
    #: always use :attr:`database_url` (the primary) — only explicitly read-only
    #: sessions may use this endpoint.
    database_reader_url: str | None = None

    #: ``synchronous_commit`` level the audit-writing transaction raises itself to
    #: via ``SET LOCAL`` (ADR-0042 §2/§4) so a committed ``audit_log`` row is durable
    #: on a quorum replica before ack. ``remote_apply`` (the ADR default) waits until
    #: the standby has REPLAYED the WAL; ``on``/``remote_write`` are the lighter
    #: durability levels. ``local``/``off`` would DISABLE the guarantee and are
    #: deliberately NOT offered here — this knob only ever raises durability for the
    #: audit path. The value is from a fixed ``Literal`` allowlist (never free text),
    #: so it can be interpolated into ``SET LOCAL synchronous_commit`` with no
    #: injection surface. Applied per-transaction (transaction-mode pooling safe),
    #: PostgreSQL-only; on SQLite the writer skips it. See ADR-0042 §2 for why this
    #: raises the WHOLE audit-writing (caller) transaction, preserving action↔audit
    #: atomicity.
    audit_synchronous_commit: Literal["remote_apply", "on", "remote_write"] = "remote_apply"

    #: Celery broker/result backend + cache (ADR-0008). With the redisSentinel HA
    #: tier the Helm chart renders a ``sentinel://h0:26379;h1:26379;h2:26379/<db>``
    #: URL here (ADR-0044 §1); ``app.core.redis.create_redis_client`` and the
    #: Celery broker transport options handle that scheme.
    redis_url: str = "redis://redis:6379/0"

    #: Redis AUTH password (``NETOPS_REDIS_PASSWORD``). Never embedded in
    #: ``redis_url`` — the URL carries only non-secret coordinates (ADR-0044 §1);
    #: empty means no AUTH (the compose/GA default).
    redis_password: str = ""

    #: Sentinel master name clients pass as ``master_name`` when ``redis_url`` is
    #: a ``sentinel://`` URL (``NETOPS_REDIS_SENTINEL_MASTER``; mirrors the
    #: chart's ``redisSentinel.sentinel.masterName`` default).
    redis_sentinel_master: str = "netops-redis"

    #: TCP port the worker exposes its Prometheus ``/metrics`` exposition on
    #: (W3-T0, ADR-0015 §2). The Celery worker has no HTTP server, so a tiny
    #: ``prometheus_client`` HTTP server is started in the worker process at boot
    #: (``app.workers.celery_app``) to serve the same default-REGISTRY series the
    #: api ``/metrics`` route exposes. The K8s worker Deployments scrape this port.
    worker_metrics_port: int = 9808

    #: Celery-beat interval (seconds) for the ``system.sample_queue_depths`` task
    #: that refreshes the ``netops_celery_queue_depth`` saturation gauge from each
    #: work queue's Redis backlog (W3-T0, ADR-0015 §2 / ADR-0046 §1/§5).
    queue_depth_sample_seconds: float = 15.0

    #: Neo4j topology/knowledge graph (ADR-0005).
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"

    #: Node cap for ``GET /topology/graph`` (audit Wave 5, G-SCA): when the
    #: subgraph that would be returned has more nodes than this, the API
    #: refuses with a 413 problem instead of streaming an unbounded payload;
    #: ``0`` disables the guard. Scoped reads (``?site=`` and
    #: ``/topology/graph/neighborhood``) are the intended path at scale.
    topology_max_nodes: int = 5000

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

    # -- KMS backend selection + prod-grade gating (W6-T2, ADR-0032 §2) ---------
    # Config-only swap (ADR-0032 Consequences): switching AWS<->Azure<->Vault is
    # this one selector + the provider-scoped block below. The credential service
    # never branches on the backend (D11). All auth is referenced indirectly — IAM
    # role / managed identity / a vault ``credential_ref`` handle — NEVER a token,
    # key, or secret inlined here (ADR-0032 §2/§6).
    # --------------------------------------------------------------------------

    #: Active KEK backend (``core/crypto.get_key_provider``). ``env``/``file`` are
    #: the local in-process fallbacks (non-production); ``aws``/``azure``/``vault``
    #: are the production KMS backends (W6-T2). ``None`` keeps the legacy
    #: kek/kek_file selection so an existing local deployment is unchanged.
    vault_key_provider: Literal["env", "file", "aws", "azure", "vault"] | None = None

    #: Production posture gate (ADR-0032 §2, secure-by-default opt-out). When
    #: ``True`` the credential service REFUSES to start on a local Env/File KEK
    #: provider — a non-production KEK can never hide behind a green prod deploy.
    #: Defaults to ``env == "prod"`` unless set explicitly.
    is_prod: bool | None = None

    # AWS KMS (``vault_key_provider=aws``): the key is referenced by ARN only;
    # auth is IRSA / IAM role from the pod's ambient credential chain — no static
    # access keys (ADR-0032 §2). ``aws_region`` is optional (boto3 resolves it
    # from the environment / instance metadata when unset).
    aws_kms_key_arn: str | None = None
    aws_region: str | None = None

    # Azure Key Vault (``vault_key_provider=azure``): the key is referenced by
    # vault URI + key name; auth is the managed identity via DefaultAzureCredential
    # — no client secret inlined. ``wrapKey``/``unwrapKey`` has no native AAD, so
    # the row-id is bound by a local AESGCM inner layer (ADR-0032 §1, see crypto).
    azure_key_vault_uri: str | None = None
    azure_key_name: str | None = None

    # HashiCorp Vault Transit (``vault_key_provider=vault``): the transit key is
    # referenced by mount + key name; ``vault_credential_ref`` is the INDIRECT
    # handle (k8s-auth role / AppRole id) the credential layer resolves into a
    # short-lived, auto-renewed token — never a token value inlined here.
    vault_addr: str | None = None
    vault_transit_mount: str = "transit"
    vault_transit_key: str | None = None
    vault_credential_ref: str | None = None

    @property
    def production(self) -> bool:
        """Effective production posture: explicit :attr:`is_prod` else ``env == 'prod'``."""
        return self.env == "prod" if self.is_prod is None else self.is_prod

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

    #: packet-analysis executor-split sandbox tuning (ADR-0049). The dispatcher
    #: forwards these to the self-confining ``python -m app.engines.packet.executor``
    #: child, which applies them as rlimits BEFORE loading the seccomp filter (fail
    #: closed). ``RLIMIT_CPU`` is derived from ``packet_analysis_timeout_seconds``
    #: (the wedged-tshark backstop) and ``RLIMIT_CORE`` is fixed at 0, so neither is
    #: exposed here. ``deny_action`` selects the child's seccomp default action:
    #: ``"errno"`` (v1 — a denied syscall returns ``EPERM``) or ``"kill_process"``
    #: (``SCMP_ACT_KILL_PROCESS``, SIGSYS-kill — the follow-up once the Linux
    #: green-path is proven on CI; ADR-0049 blocker 8). Defaults mirror the
    #: fallbacks in ``app.engines.packet.executor``.
    packet_sandbox_rlimit_as_bytes: int = 2 * 1024 * 1024 * 1024
    packet_sandbox_rlimit_fsize_bytes: int = 64 * 1024 * 1024
    packet_sandbox_rlimit_nofile: int = 256
    #: CAUTION — ``RLIMIT_NPROC`` is a PER-UID limit, not a per-process-tree one:
    #: the kernel enforces it against uid-10001's TOTAL task count host-wide
    #: (processes AND threads, across uvicorn's threadpool, celery prefork, beat,
    #: the dispatcher, and every other uid-10001 container on the node). A value
    #: sized to "this job's tree" (e.g. 64) makes tshark's fork() fail EAGAIN
    #: under ordinary platform load — intermittent, load-correlated analysis
    #: failures. 512 aligns with the container-level compose ``pids_limit`` (512),
    #: which is the PRIMARY fork-bomb bound; this rlimit is only a defence-in-depth
    #: backstop. Do not tune it back down below the platform's steady-state
    #: uid-10001 task count.
    packet_sandbox_rlimit_nproc: int = 512
    packet_sandbox_seccomp_deny_action: str = "errno"

    #: Hard cap on the bytes the dispatcher reads from the executor child's stdout
    #: (ADR-0049 marshalling must-address). The child prints only a small,
    #: findings-shaped ``PacketFindings`` JSON, but a popped dissector could emit
    #: arbitrary output, so the dispatcher bounds it at a TIGHT findings-sized
    #: limit — deliberately NOT the 64 MB raw-tshark cap the child applies to
    #: tshark's own output — and pydantic-validates the result (list/string caps)
    #: before anything reaches the DB / audit / API. Default 256 KiB: ~50x the
    #: largest realistic findings document, ~256x below the raw cap.
    packet_findings_max_bytes: int = 256 * 1024

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

    # -- Audit -> SIEM export pipeline (P3 W3-T1, ADR-0045) ---------------------
    # The export streams every committed audit_log row to the customer SIEM
    # at-least-once, in seq order, over a vendor-neutral transport (syslog/CEF over
    # TLS or HTTPS/JSON). Opt-in: with no ``audit_export_format`` the exporter is a
    # warned no-op (a deployment with no SIEM is unchanged). All transports are
    # TLS-only (ADR-0045 §1); the endpoint credential is a token, never logged.
    # --------------------------------------------------------------------------

    #: Active SIEM export transport (ADR-0045 §1). ``syslog``/``cef`` use the
    #: RFC5425 TLS syslog sink (``audit_export_host``/``_port``); ``https-json`` POSTs
    #: to ``audit_export_endpoint``. ``None`` (default) DISABLES the exporter so a
    #: deployment with no SIEM is unchanged (a warned no-op, never a silent drop).
    audit_export_format: Literal["syslog", "cef", "https-json"] | None = None

    #: SIEM syslog/CEF collector host + port for the TLS syslog sink (``syslog``/
    #: ``cef`` formats). Required when the format is ``syslog`` or ``cef``.
    audit_export_host: str | None = None
    audit_export_port: int = 6514

    #: SIEM HTTPS/JSON collector endpoint (the ``https-json`` format). Required when
    #: the format is ``https-json``; an ``https://`` URL (TLS-only, ADR-0045 §1).
    audit_export_endpoint: str | None = None

    #: Vault credential_ref / bearer token for the HTTPS sink Authorization header.
    #: A ``SecretStr`` so it never appears in a repr/log; only the sink reads it.
    audit_export_bearer_token: SecretStr | None = None

    #: TLS material for the export egress (ADR-0045 §1 — TLS-only). The CA bundle
    #: verifying the SIEM server cert (system trust when None); an optional client
    #: cert/key pair for mutual TLS (both-or-neither — fail-closed, ADR-0039 §4).
    audit_export_ca_cert: Path | None = None
    audit_export_client_cert: Path | None = None
    audit_export_client_key: Path | None = None

    #: Bounded read-batch size per export cycle (ADR-0045 §3 — bounded memory). A
    #: long SIEM outage grows the durable audit_log backlog + the lag gauge, never
    #: unbounded memory: at most this many rows are held in flight per cycle. Must be
    #: >= 1: a batch size of 0 would ``read_unexported(limit=0)`` → export nothing
    #: (silent audit loss, no ACK ever advances the cursor).
    audit_export_batch_size: int = Field(default=500, gt=0)

    #: Seconds the exporter sleeps between cycles when caught up (no new rows). A
    #: short interval keeps the export near-real-time for the p95 < 60 s SLO (§6). Must
    #: be > 0: a non-positive interval busy-spins the caught-up loop (CPU burn, no wait).
    audit_export_poll_seconds: float = Field(default=2.0, gt=0)

    #: Capped backoff (seconds) the exporter waits after a sink failure before
    #: retrying the SAME un-advanced batch (ADR-0045 §3 — buffer + retry, never drop).
    #: Must be > 0: a non-positive backoff busy-spins the retry loop against a down sink.
    audit_export_retry_backoff_seconds: float = Field(default=5.0, gt=0)

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

    # -- JunOS commit-confirmed window (Wave 3 / ADR-0026 Option A) ------------
    # Minutes for ``commit confirmed <N>``. Under Option A the unconfirmed window
    # must cover apply → verify-after → confirming ``commit``. Verify-after is
    # one ``show configuration | display set`` + normalize/diff (seconds); bump
    # for large configs / slow control planes. Floor 1 (JunOS minute unit);
    # cap 60 to block fat-fingered multi-hour unconfirmed windows.
    # --------------------------------------------------------------------------

    #: JunOS ``commit confirmed <N>`` timer in minutes (``NETOPS_JUNOS_COMMIT_CONFIRMED_MINUTES``).
    junos_commit_confirmed_minutes: int = Field(default=2, ge=1, le=60)

    # -- SSH host-key verification (Wave 3 H7) ---------------------------------
    # Default ON (secure by default). Lab-only opt-out via NETOPS_SSH_STRICT=false
    # restores AutoAddPolicy with a logged warning. Per-host pins ride
    # DeviceCredential.params["host_key_fingerprints"][host] (shared-cred safe).
    # --------------------------------------------------------------------------

    #: When true (default), SSH sessions use strict host-key checking + system
    #: known_hosts (``NETOPS_SSH_STRICT``). Set false only in isolated labs.
    ssh_strict: bool = True

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
        """Secure by default: the baked-in dev key must never sign prod tokens.

        Keyed off the effective :attr:`production` posture (``NETOPS_IS_PROD``
        else ``env == 'prod'``), not the raw ``env``, so explicitly setting
        ``NETOPS_IS_PROD=true`` also bars the dev key — a prod deploy can never
        sign tokens with the insecure default regardless of how the posture was
        declared.
        """
        if self.production and self.secret_key == _DEV_ONLY_SECRET_KEY:
            raise ValueError(
                "NETOPS_SECRET_KEY must be set to a strong unique value in production "
                "(NETOPS_ENV=prod or NETOPS_IS_PROD=true)"
            )
        return self

    @model_validator(mode="after")
    def _require_export_target(self) -> Settings:
        """Fail closed when an ENABLED exporter has no transport target (ADR-0045 §1).

        The exporter is opt-in: ``audit_export_format is None`` DISABLES it (a warned
        no-op), so a deployment with no SIEM needs no target and stays valid. But once a
        format IS set the exporter arms, and each format has a mandatory target:

        * ``https-json`` POSTs to ``audit_export_endpoint`` — which must be non-None AND
          an ``https://`` URL. A missing endpoint would arm with nowhere to POST; a
          ``http://`` (or scheme-less) URL would send the audit payload + bearer token
          over cleartext (TLS-only export, ADR-0045 §1).
        * ``syslog``/``cef`` use the TLS syslog sink at ``audit_export_host`` — which
          must be non-None or the exporter arms with no collector.

        Fail closed at config time so a targetless/cleartext SIEM exporter can never be
        armed, rather than silently mis-configuring (or leaking on the first cycle).
        """
        if self.audit_export_format == "https-json":
            if self.audit_export_endpoint is None:
                raise ValueError(
                    "NETOPS_AUDIT_EXPORT_ENDPOINT must be set for the 'https-json' "
                    "export format (the HTTPS/JSON collector target, ADR-0045 §1)"
                )
            scheme = self.audit_export_endpoint.split("://", 1)[0].lower()
            if scheme != "https":
                raise ValueError(
                    "NETOPS_AUDIT_EXPORT_ENDPOINT must be an https:// URL for the "
                    "'https-json' export format (TLS-only export, ADR-0045 §1) — a "
                    "non-https endpoint would send the audit payload + bearer token "
                    "over cleartext"
                )
        elif self.audit_export_format in ("syslog", "cef") and self.audit_export_host is None:
            raise ValueError(
                "NETOPS_AUDIT_EXPORT_HOST must be set for the "
                f"'{self.audit_export_format}' export format (the TLS syslog collector "
                "host, ADR-0045 §1)"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide cached :class:`Settings` instance.

    Tests construct :class:`Settings` directly (or clear this cache) instead of
    mutating the returned instance.
    """
    return Settings()
