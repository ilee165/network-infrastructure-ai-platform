"""FastAPI application factory — composition root for the ``api`` container.

Run locally with::

    uvicorn app.main:app --reload

Per REPO-STRUCTURE §3.2 row 14, this module imports only ``core`` and ``api``
(plus ``db`` for the engine-disposal shutdown hook).
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
from app.core.logging import bind_request_id, configure_logging, get_logger, new_request_id
from app.core.logging import reset_request_id

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
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "startup",
            env=app_settings.env,
            llm_profile=app_settings.llm_profile,
        )
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
