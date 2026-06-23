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
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute

from app.api.deps import enforce_api_rate_limit
from app.core.config import Settings
from app.main import create_app


def _build_app() -> FastAPI:
    return create_app(Settings(_env_file=None, env="dev", secret_key="unit-test-secret-key"))


def _route_has_rate_limit(route: APIRoute) -> bool:
    return any(dep.call is enforce_api_rate_limit for dep in route.dependant.dependencies)


def test_every_agents_http_route_is_rate_limited() -> None:
    """All ``/api/v1/agents`` HTTP routes carry the API rate-limit dependency."""
    app = _build_app()
    http_routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1/agents")
    ]
    # Sanity: the agents router really is mounted with its HTTP routes.
    assert http_routes, "no agents HTTP routes found on the mounted app"

    unprotected = [route.path for route in http_routes if not _route_has_rate_limit(route)]
    assert not unprotected, f"agents HTTP routes missing API rate-limit: {unprotected}"


def test_agents_stream_websocket_is_not_rate_limited() -> None:
    """The WS ``/stream`` route must NOT carry the HTTP-bearer rate-limit dep."""
    app = _build_app()
    ws_routes = [
        route
        for route in app.routes
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
        for route in app.routes
        if isinstance(route, APIRoute)
        and route.path == "/api/v1/agents"
        and "POST" in route.methods
    ]
    assert start_routes, "POST /api/v1/agents route not found"
    assert all(_route_has_rate_limit(route) for route in start_routes)
