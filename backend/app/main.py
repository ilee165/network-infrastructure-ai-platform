"""FastAPI application factory — composition root for the ``api`` container.

Run locally with::

    uvicorn app.main:app --reload

Per REPO-STRUCTURE §3.2 row 14, this module imports only ``core`` and ``api``
(plus ``db`` for the engine-disposal shutdown hook, and ``services.rate_limit``
to bind the shared Redis-backed rate limiter on ``app.state`` at startup so a
limit holds across ``api`` replicas — W6-T6).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app import db
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import (
    bind_request_id,
    configure_logging,
    get_logger,
    new_request_id,
    reset_request_id,
)

API_V1_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application.

    Args:
        settings: Optional explicit settings (tests inject these); defaults to
            the cached environment-backed :func:`get_settings`.
    """
    app_settings = settings if settings is not None else get_settings()
    configure_logging(app_settings)
    logger = get_logger("app.main")

    @asynccontextmanager
    async def lifespan(app_: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "startup",
            env=app_settings.env,
            llm_profile=app_settings.llm_profile,
        )
        # W6-T6: bind the shared Redis-backed rate limiter so the API budget +
        # login lockout hold across ``api`` replicas (ADR-0008, D13). The client
        # is lazy (no connection opened until the first command), so this is safe
        # even when Redis is briefly unreachable at boot; the API limiter then
        # fails open and the login lockout fails closed, per design.
        from redis.asyncio import from_url

        from app.services.agent_stream import (
            RedisAgentStreamFanout,
            RedisStreamTicketStore,
        )
        from app.services.rate_limit import RedisRateLimiter

        # One Sentinel-aware client (W1-T4 wires ``redis_url`` at the Sentinel
        # service, so no static host pin) shared by the rate limiter and the
        # stateless agent-session fan-out + ticket store (ADR-0044 §2).
        redis_client = from_url(app_settings.redis_url)
        app_.state.rate_limiter = RedisRateLimiter(redis_client)
        # W2-T2: externalize WebSocket session state to Redis so any ``api``
        # replica serves any session — the pub/sub fan-out for live frames and the
        # shared single-use stream-ticket store (redeemable cross-replica).
        app_.state.stream_fanout = RedisAgentStreamFanout(redis_client)
        app_.state.stream_ticket_store = RedisStreamTicketStore(redis_client)
        # P1 W6-T1/T2 (ADR-0032 §2/§5): select the active KEK provider, enforce the
        # prod-grade gate, surface its posture on the startup banner + /metrics, and
        # audit ``kek.provider.select`` (identifiers/versions only, never key bytes).
        import asyncio

        from app.core import metrics
        from app.core.crypto import (
            get_key_provider,
            is_production_grade,
            require_production_grade,
        )
        from app.services import credentials as credentials_service

        # A KMS backend (aws|azure|vault) is a PRODUCTION KEK selection: if its
        # build fails (missing ARN, absent SDK extra, unreachable backend at boot)
        # startup MUST crash loudly — swallowing it would silently start with no
        # KEK provider and defeat the ADR-0032 §2 refuse-to-start gate. Only an
        # unset/local selector (None|env|file) in a NON-prod run may degrade to
        # "no provider built" (a bare dev run; the credential paths fail closed in
        # their own right). In prod, get_key_provider's own KekConfigurationError
        # propagates so a misconfigured local KEK also crashes boot.
        kms_backend_selected = app_settings.vault_key_provider in ("aws", "azure", "vault")
        try:
            provider = get_key_provider(app_settings)
        except Exception:  # noqa: BLE001
            if kms_backend_selected or app_settings.production:
                raise  # never hide a broken prod-KEK build behind a green deploy
            provider = None
        app_.state.key_provider = provider
        if provider is not None:
            # ADR-0032 §2 prod gate: refuse to start on a local provider in prod —
            # this RuntimeError is intentionally NOT swallowed so a non-production
            # KEK can never run behind a green prod deploy.
            require_production_grade(provider, is_prod=app_settings.production)
            production_grade = is_production_grade(provider)
            metrics.set_provider_production_grade(production_grade=production_grade)
            # The provider's health() is a synchronous boto3/hvac/azure network
            # round-trip; offload it to a worker thread (matching the readiness
            # probe) so the blocking SDK call never stalls the async event loop at
            # boot. The readiness probe refreshes this gauge on every poll.
            healthy = await asyncio.to_thread(lambda: provider.health().available)
            metrics.set_provider_healthy(healthy=healthy)
            # CR6 (secure-by-default refuse-to-start): a selected PRODUCTION KMS
            # that reports unhealthy at boot must FAIL startup, not merely record a
            # 0 gauge and continue serving — a credential write/read would then
            # fail closed on every request behind a "green" deploy. A local
            # (non-production) provider is always reachable in-process, so this only
            # gates real KMS backends.
            if production_grade and not healthy:
                raise RuntimeError(
                    "selected production KEK provider "
                    f"{type(provider).__name__!r} is unhealthy at startup; "
                    "refusing to start (ADR-0032 §4 fail-closed)"
                )
            # Startup banner: the active KEK backend + its production posture.
            logger.info(
                "kek.provider.banner",
                provider=type(provider).__name__,
                kek_version=provider.kek_version,
                production_grade=production_grade,
                is_prod=app_settings.production,
            )
            try:
                await credentials_service.audit_provider_select(
                    db.get_sessionmaker(), provider, actor="system:startup"
                )
            except Exception as exc:  # noqa: BLE001  (boot best-effort: never crash on audit)
                logger.warning("kek.provider.select.audit_skipped", reason_class=type(exc).__name__)
        # M1 placeholder hook: initialize the shared async DB engine pool and
        # run a startup connectivity check once domain models land.
        # M2 placeholder hook: initialize the shared Neo4j driver (knowledge/).
        yield
        # M2 placeholder hook: close the shared Neo4j driver.
        await db.dispose_engine()
        logger.info("shutdown")

    app = FastAPI(
        title="AI Network Operations Platform",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = app_settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_id_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Bind a request id (inbound ``X-Request-ID`` or fresh) for log correlation."""
        request_id = request.headers.get("X-Request-ID") or new_request_id()
        token = bind_request_id(request_id)
        try:
            response = await call_next(request)
        finally:
            reset_request_id(token)
        response.headers["X-Request-ID"] = request_id
        return response

    register_exception_handlers(app)
    app.include_router(api_router, prefix=API_V1_PREFIX)
    return app


#: ASGI entrypoint used by uvicorn and the api container.
app = create_app()
