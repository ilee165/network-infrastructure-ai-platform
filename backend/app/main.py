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

        from app.services.rate_limit import RedisRateLimiter

        app_.state.rate_limiter = RedisRateLimiter(from_url(app_settings.redis_url))
        # P1 W6-T1 (ADR-0032 §5): audit the active KEK provider/backend chosen at
        # startup as ``kek.provider.select`` — identifiers/versions only, never key
        # material. Best-effort: a misconfigured/unreachable KEK or DB at boot must
        # not crash the api; the credential paths fail closed in their own right.
        from app.core.crypto import get_key_provider
        from app.services import credentials as credentials_service

        try:
            provider = get_key_provider(app_settings)
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
