"""HTTP metrics middleware + ``/metrics`` exposition (P3 W3-T0, ADR-0015 §2).

This is the FastAPI-facing seam over :mod:`app.core.metrics`: a Starlette HTTP
middleware that times every request and records
``netops_http_requests_total`` / ``netops_http_request_duration_seconds``, plus a
``render_metrics`` helper that serializes the default ``prometheus_client``
``REGISTRY`` for a served ``/metrics`` endpoint (api + worker).

Cardinality discipline is the load-bearing rule (ADR-0015 §2, ADR-0046 §1 §90):
the ``route`` label is the **templated** route pattern resolved from the matched
Starlette route (``/api/v1/devices/{id}``), NEVER the raw request path — so a
request to ``/api/v1/devices/abc-123`` records ``route="/api/v1/devices/{id}"``
and a per-id label can never explode Prometheus cardinality. A request that
matches no route (404) is bucketed under a single ``__unmatched__`` route so an
attacker probing random paths cannot create unbounded series either.

Lives in ``app.core`` (not ``app.api``) so it imports nothing app-internal beyond
:mod:`app.core.metrics` (import-linter REPO-STRUCTURE §3.2 row 1): the only other
imports are the external ``starlette``/``prometheus_client`` packages. The
observation is O(1) and touches no I/O, so it never blocks the request path
(W3-T0 requirement 5).
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core import metrics

#: Route label for a request that matched no Starlette route (404 / unrouted).
#: Bucketing all unmatched paths here keeps the ``route`` label bounded even
#: under random-path probing — never the raw probed path.
UNMATCHED_ROUTE = "__unmatched__"

#: Prometheus text exposition content type (set lazily so the module imports on a
#: slim install without ``prometheus_client``).
_DEFAULT_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def templated_route(request: Request) -> str:
    """Return the matched route's TEMPLATED path pattern, never the raw path.

    Starlette stamps the matched :class:`~starlette.routing.Route` on
    ``request.scope["route"]`` during routing; its ``.path`` is the template with
    ``{param}`` placeholders intact (``/api/v1/devices/{id}``). When no route
    matched (a 404), there is no templated pattern, so the request is bucketed
    under :data:`UNMATCHED_ROUTE` rather than leaking the raw probed path — the
    cardinality guard the W3-T0 test bites on.
    """
    route = request.scope.get("route")
    path_format = getattr(route, "path_format", None) or getattr(route, "path", None)
    if isinstance(path_format, str) and path_format:
        return path_format
    return UNMATCHED_ROUTE


async def metrics_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Time the request and record the ``netops_http_*`` series (O(1), no I/O).

    Records on BOTH the success and the exception path: a handler that raises is
    still a served request whose 5xx must count against availability. The
    ``route`` label is resolved AFTER ``call_next`` so the matched route is on the
    scope. Status 500 is attributed when the handler raises before producing a
    response, then the exception is re-raised unchanged so the app's own handlers
    still run.
    """
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration = time.perf_counter() - start
        metrics.observe_http_request(
            method=request.method,
            route=templated_route(request),
            status_code=status_code,
            duration_seconds=duration,
        )


def render_metrics() -> tuple[bytes, str]:
    """Serialize the default ``REGISTRY`` to Prometheus text + its content type.

    Returns an empty body with the default text content type when
    ``prometheus_client`` is absent (a slim install), so a wired ``/metrics`` route
    degrades to ``200`` with no series rather than crashing on import.
    """
    if not metrics._PROM_ENABLED:  # noqa: SLF001 - shared module-level flag
        return b"", _DEFAULT_CONTENT_TYPE
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    return generate_latest(), CONTENT_TYPE_LATEST


def add_metrics_route(app: ASGIApp) -> None:
    """Register ``GET /metrics`` on *app* serving :func:`render_metrics`.

    Used by the api app factory and the worker metrics server. The endpoint is
    unauthenticated and exposes only the registered series (no payload/secret),
    consistent with the ADR-0015 §4 health-endpoint posture.
    """
    from fastapi import FastAPI

    assert isinstance(app, FastAPI)  # noqa: S101 - narrow for the route decorator

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        body, content_type = render_metrics()
        return Response(content=body, media_type=content_type)
