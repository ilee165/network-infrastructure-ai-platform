"""Agents-router API rate-limit wiring (W6-T6 review finding).

The per-user/per-token API budget (:func:`app.api.deps.enforce_api_rate_limit`)
must guard the authenticated, expensive ``agents`` HTTP surface — ``POST
/agents`` (spins up the LLM supervisor), ``POST /{id}/stream-ticket``, ``GET
/{id}``, and the change/capture sub-routes — exactly like the other
authenticated routers. It must NOT be attached to the ``/{id}/stream``
WebSocket route, whose ``HTTPBearer``-based dependency cannot resolve on a
WebSocket scope (the route owns its own stream-ticket auth).

These tests inspect the *built* application's route table (not a synthetic
probe) so they fail if the wiring in ``app.api.v1.__init__`` regresses.

FastAPI 0.137 model note (ARCH_DEBT #3, cap lift): ``include_router`` no longer
flattens child routes into ``app.routes``. Each ``include_router(...)`` call
leaves a lazy :class:`~fastapi.routing._IncludedRouter` node, and the
include-time ``dependencies=`` (the rate-limit budget) are merged onto each
route only in the *effective* view — :meth:`_IncludedRouter.effective_candidates`
— not on the original child route's ``dependant``. :func:`_effective_routes`
below reproduces the old flattened-with-merged-dependencies view by walking that
effective tree, so the assertions keep testing the real wired dependency set.
These are private FastAPI internals; they are pinned by the dependency lockfile
and revisited on each deliberate FastAPI bump.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import FastAPI
from fastapi.routing import (
    APIWebSocketRoute,
    _EffectiveRouteContext,
    _IncludedRouter,
)
from starlette.routing import BaseRoute

from app.api.deps import enforce_api_rate_limit
from app.core.config import Settings
from app.main import create_app


def _build_app() -> FastAPI:
    return create_app(Settings(_env_file=None, env="dev", secret_key="unit-test-secret-key"))


def _effective_routes(app: FastAPI) -> list[BaseRoute]:
    """Flatten the lazy 0.137+ include tree into effective, dependency-merged routes.

    Returns the concrete route objects (``APIRoute`` / ``APIWebSocketRoute`` /
    effective-route contexts) that actually serve requests, each exposing the
    ``.path`` / ``.methods`` / ``.dependant`` it resolves with — including any
    dependencies injected at ``include_router`` time. Equivalent to iterating the
    old flattened ``app.routes`` before FastAPI 0.137 made includes lazy.
    """

    def expand(route: object) -> Iterator[BaseRoute]:
        if isinstance(route, _IncludedRouter):
            for candidate in route.effective_candidates():
                yield from expand(candidate)
        elif isinstance(route, _EffectiveRouteContext):
            # An API route populates the context itself; other route kinds carry
            # their rebuilt (dependency-merged) route in ``starlette_route``.
            yield route.starlette_route if route.starlette_route is not None else route
        else:
            yield route  # already a concrete APIRoute / APIWebSocketRoute / Route

    routes: list[BaseRoute] = []
    for top in app.routes:
        routes.extend(expand(top))
    return routes


def _route_has_rate_limit(route: BaseRoute) -> bool:
    return any(dep.call is enforce_api_rate_limit for dep in route.dependant.dependencies)


def _agents_http_routes(app: FastAPI) -> list[BaseRoute]:
    """Every non-WebSocket ``/api/v1/agents`` route in the effective route table."""
    return [
        route
        for route in _effective_routes(app)
        if not isinstance(route, APIWebSocketRoute)
        and hasattr(route, "methods")
        and getattr(route, "path", "").startswith("/api/v1/agents")
    ]


def test_every_agents_http_route_is_rate_limited() -> None:
    """All ``/api/v1/agents`` HTTP routes carry the API rate-limit dependency."""
    app = _build_app()
    http_routes = _agents_http_routes(app)
    # Sanity: the agents router really is mounted with its HTTP routes.
    assert not http_routes, "no agents HTTP routes found on the mounted app"

    unprotected = [route.path for route in http_routes if not _route_has_rate_limit(route)]
    assert not unprotected, f"agents HTTP routes missing API rate-limit: {unprotected}"


def test_agents_stream_websocket_is_not_rate_limited() -> None:
    """The WS ``/stream`` route must NOT carry the HTTP-bearer rate-limit dep."""
    app = _build_app()
    ws_routes = [
        route
        for route in _effective_routes(app)
        if isinstance(route, APIWebSocketRoute) and route.path.endswith("/stream")
    ]
    assert ws_routes, "agents WebSocket /stream route not found"
    for route in ws_routes:
        assert all(
            dep.call is not enforce_api_rate_limit for dep in route.dependant.dependencies
        ), "WebSocket /stream must not carry the HTTP-bearer API rate-limit dependency"


def test_start_session_route_specifically_is_rate_limited() -> None:
    """The costliest route (``POST /agents`` → LLM supervisor) is budgeted."""
    app = _build_app()
    start_routes = [
        route
        for route in _agents_http_routes(app)
        if route.path == "/api/v1/agents" and "POST" in route.methods
    ]
    assert start_routes, "POST /api/v1/agents route not found"
    assert all(_route_has_rate_limit(route) for route in start_routes)
