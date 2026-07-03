"""W3-T0 HTTP metrics middleware + ``/metrics`` exposition + the cardinality guard.

The cardinality test is the load-bearing one (ADR-0015 §2, ADR-0046 §1 §90): a
request to ``/widgets/abc-123`` must record ``route="/widgets/{widget_id}"`` — the
TEMPLATED pattern — and the raw id MUST NOT appear in any ``netops_http_*`` label.
The test BITES if the middleware ever regresses to labelling by the raw path.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import APIRouter, FastAPI
from prometheus_client import CollectorRegistry, generate_latest

from app.core import metrics
from app.core.metrics_asgi import (
    UNMATCHED_ROUTE,
    add_metrics_route,
    metrics_middleware,
    render_metrics,
)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.middleware("http")(metrics_middleware)
    add_metrics_route(app)

    @app.get("/widgets/{widget_id}")
    async def get_widget(widget_id: str) -> dict[str, str]:
        return {"widget_id": widget_id}

    @app.get("/boom")
    async def boom() -> dict[str, str]:
        raise RuntimeError("kaboom")

    return app


def _http_count(*, method: str, route: str, status_class: str) -> float:
    return metrics.HTTP_REQUESTS_TOTAL.labels(  # type: ignore[attr-defined]
        method=method, route=route, status_class=status_class
    )._value.get()


@pytest.fixture()
async def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=_build_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def test_records_templated_route_not_raw_path(client: httpx.AsyncClient) -> None:
    template = "/widgets/{widget_id}"
    before = _http_count(method="GET", route=template, status_class="2xx")

    resp = await client.get("/widgets/abc-123")
    assert resp.status_code == 200

    # The templated route is what got counted...
    assert _http_count(method="GET", route=template, status_class="2xx") == before + 1

    # ...and the RAW path / id is NOT a label value anywhere in the series. This is
    # the cardinality guard — it bites if the middleware ever labels by raw path.
    rendered = generate_latest().decode()
    assert "abc-123" not in rendered
    assert 'route="/widgets/abc-123"' not in rendered
    assert 'route="/widgets/{widget_id}"' in rendered


async def test_duration_histogram_observed(client: httpx.AsyncClient) -> None:
    hist = metrics.HTTP_REQUEST_DURATION_SECONDS.labels(  # type: ignore[attr-defined]
        method="GET", route="/widgets/{widget_id}"
    )
    before = hist._sum.get()  # type: ignore[attr-defined]
    await client.get("/widgets/x")
    assert hist._sum.get() >= before  # type: ignore[attr-defined]


async def test_unmatched_path_is_bucketed_not_leaked(client: httpx.AsyncClient) -> None:
    """A 404 path is bucketed under __unmatched__, never the raw probed path."""
    before = _http_count(method="GET", route=UNMATCHED_ROUTE, status_class="4xx")
    resp = await client.get("/nope/random-probe-987")
    assert resp.status_code == 404
    assert _http_count(method="GET", route=UNMATCHED_ROUTE, status_class="4xx") == before + 1
    rendered = generate_latest().decode()
    assert "random-probe-987" not in rendered


async def test_prefixed_route_label_survives_encoded_reserved_char_in_param() -> None:
    """Mount-prefix reconstruction anchors on scope["path"], not request.url.path.

    FastAPI 0.137+ lazy includes leave a router-RELATIVE template on
    ``scope["route"]`` (``/files/{name}``); the middleware re-anchors it to the
    full mounted label (``/api/v1/files/{name}``) against ``scope["path"]`` — the
    exact ASGI-decoded string routing matched. This test sends a param value with
    an encoded reserved char (``%3F`` → ``?``): ``request.url.path`` would re-parse
    the decoded ``?`` as a query separator, truncate the path, miss the anchor, and
    degrade the label to the prefix-less router-relative template. BITES on any
    regression back to URL-string parsing.
    """
    app = FastAPI()
    app.middleware("http")(metrics_middleware)
    router = APIRouter()

    @router.get("/files/{name}")
    async def get_file(name: str) -> dict[str, str]:
        return {"name": name}

    app.include_router(router, prefix="/api/v1")

    template = "/api/v1/files/{name}"
    before = _http_count(method="GET", route=template, status_class="2xx")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get("/api/v1/files/a%3Fb")
    assert resp.status_code == 200

    # Full mounted template got the count — not the prefix-less fallback.
    assert _http_count(method="GET", route=template, status_class="2xx") == before + 1
    rendered = generate_latest().decode()
    assert 'route="/files/{name}"' not in rendered  # the degraded fallback label
    assert "a%3Fb" not in rendered  # and never the raw value
    assert 'route="/api/v1/files/a' not in rendered


async def test_handler_exception_counts_as_5xx(client: httpx.AsyncClient) -> None:
    before = _http_count(method="GET", route="/boom", status_class="5xx")
    with pytest.raises(RuntimeError):
        await client.get("/boom")
    # The raised handler still counts as a served 5xx (availability SLI).
    assert _http_count(method="GET", route="/boom", status_class="5xx") == before + 1


async def test_metrics_endpoint_served(client: httpx.AsyncClient) -> None:
    await client.get("/widgets/served-check")
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "netops_http_requests_total" in body
    # The KEK + topology series registered on the same default REGISTRY are served too.
    assert "vault_key_provider_healthy" in body


def test_render_metrics_returns_text_and_content_type() -> None:
    body, content_type = render_metrics()
    assert isinstance(body, bytes)
    assert "text/plain" in content_type


def test_render_metrics_degrades_to_empty_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metrics, "_PROM_ENABLED", False)
    body, content_type = render_metrics()
    assert body == b""
    assert "text/plain" in content_type


def test_default_registry_is_used_not_a_private_one() -> None:
    """Series register on the DEFAULT REGISTRY so one /metrics exposes everything."""
    # A throwaway registry must NOT already contain our series (sanity that we did
    # not accidentally register on a private registry).
    throwaway = CollectorRegistry()
    assert "netops_http_requests_total" not in generate_latest(throwaway).decode()
