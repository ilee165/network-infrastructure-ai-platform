"""App-factory tests: routing prefix, request-id correlation, CORS wiring."""

from __future__ import annotations

import base64
import os

import httpx
import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import Settings
from app.core.crypto import KekConfigurationError, LocalKeyProviderInProductionError
from app.main import create_app


async def test_api_mounted_under_api_v1(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    # The unprefixed path must not exist.
    response = await client.get("/health/live")
    assert response.status_code == 404


async def test_response_carries_generated_request_id(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")
    assert response.headers.get("X-Request-ID")


async def test_metrics_endpoint_served_on_api(client: httpx.AsyncClient) -> None:
    """W3-T0: the api serves the default-REGISTRY series on a root ``/metrics``."""
    # Drive one request so the HTTP series has a sample, then scrape.
    await client.get("/api/v1/health/live")
    response = await client.get("/metrics")
    assert response.status_code == 200
    body = response.text
    assert "netops_http_requests_total" in body
    # The templated route is what is labelled (the /metrics scrape itself or the
    # health probe), never a raw id (cardinality discipline, ADR-0046 §1).
    assert 'route="/api/v1/health/live"' in body


async def test_metrics_route_label_is_templated_not_raw(client: httpx.AsyncClient) -> None:
    """A request to a parametrized route records the TEMPLATED pattern, not the id."""
    # Hit a known templated API route with a concrete id; 401/404 is fine — the
    # middleware still records the matched route template.
    await client.get("/api/v1/agents/00000000-0000-0000-0000-000000000000")
    body = (await client.get("/metrics")).text
    assert "00000000-0000-0000-0000-000000000000" not in body
    assert 'route="/api/v1/agents/{session_id}"' in body


async def test_inbound_request_id_is_preserved(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live", headers={"X-Request-ID": "trace-me-12345"})
    assert response.headers["X-Request-ID"] == "trace-me-12345"


def test_cors_configured_from_settings(app: FastAPI) -> None:
    cors = next(
        (mw for mw in app.user_middleware if mw.cls is CORSMiddleware),
        None,
    )
    assert cors is not None
    assert cors.kwargs["allow_origins"] == ["http://testserver"]


async def test_cors_preflight_exposes_only_enumerated_methods_and_headers(
    client: httpx.AsyncClient,
) -> None:
    """Audit PRODUCTION_READINESS #9: no wildcard allow_methods/allow_headers.

    A CORS preflight must echo back the enumerated method/header allowlist the
    frontend (frontend/src/api/client.ts) actually sends — never ``*``.
    """
    response = await client.options(
        "/api/v1/health/live",
        headers={
            "Origin": "http://testserver",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert response.status_code == 200
    allow_methods = {m.strip() for m in response.headers["access-control-allow-methods"].split(",")}
    assert allow_methods == {"GET", "POST", "PATCH", "DELETE"}
    allow_headers = {
        h.strip().lower() for h in response.headers["access-control-allow-headers"].split(",")
    }
    # Starlette's CORSMiddleware always unions the configured allow_headers with
    # the CORS-safelisted simple headers (accept/accept-language/content-language
    # /content-type) regardless of what is passed — so those four plus our one
    # explicit addition (authorization) is the full expected set; there must be
    # no wildcard and nothing beyond this fixed list.
    assert allow_headers == {
        "authorization",
        "content-type",
        "accept",
        "accept-language",
        "content-language",
    }


async def test_cors_preflight_rejects_disallowed_method_and_header(
    client: httpx.AsyncClient,
) -> None:
    """The restriction must actually bite: a preflight for a method or header
    outside the enumerated allowlist is refused (Starlette answers 400 and
    never echoes the disallowed value back)."""
    response = await client.options(
        "/api/v1/health/live",
        headers={
            "Origin": "http://testserver",
            "Access-Control-Request-Method": "PUT",
        },
    )
    assert response.status_code == 400
    assert "PUT" not in response.headers.get("access-control-allow-methods", "")

    response = await client.options(
        "/api/v1/health/live",
        headers={
            "Origin": "http://testserver",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-not-allowed",
        },
    )
    assert response.status_code == 400
    assert "x-not-allowed" not in response.headers.get("access-control-allow-headers", "").lower()


# ---------------------------------------------------------------------------
# Prod-grade KEK gating at startup (P1 W6-T2, ADR-0032 §2)
# ---------------------------------------------------------------------------


def _prod_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "_env_file": None,
        "env": "prod",
        "secret_key": "a-strong-unique-prod-secret",
        "is_prod": True,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


async def test_startup_refuses_local_provider_in_production() -> None:
    """is_prod + a local Env KEK ⇒ lifespan raises the refuse-to-start RuntimeError."""
    kek = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    app_ = create_app(_prod_settings(kek=kek))
    with pytest.raises(LocalKeyProviderInProductionError) as excinfo:
        async with app_.router.lifespan_context(app_):
            pass  # pragma: no cover - the gate raises before this body runs
    message = str(excinfo.value)
    assert "EnvKeyProvider" in message
    assert "not permitted in production" in message
    assert "D11/ADR-0032 §2" in message


async def test_startup_allows_kms_provider_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """is_prod + a production-grade KMS provider ⇒ lifespan starts and sets metrics."""
    from app.core import crypto, metrics

    fake = crypto.FakeKmsKeyProvider()
    monkeypatch.setattr(crypto, "get_key_provider", lambda settings: fake)

    grade: dict[str, bool] = {}
    monkeypatch.setattr(
        metrics,
        "set_provider_production_grade",
        lambda *, production_grade: grade.update(value=production_grade),
    )

    app_ = create_app(_prod_settings(vault_key_provider="aws", aws_kms_key_arn="arn:x"))
    async with app_.router.lifespan_context(app_):
        # lifespan entered without the prod gate tripping; the built provider is
        # stashed on app.state for the readiness probe to reuse (not rebuilt per poll).
        assert app_.state.key_provider is fake
    assert grade["value"] is True


async def test_startup_refuses_unhealthy_production_kms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR6: a production-grade KMS reporting unhealthy at boot must CRASH startup.

    Secure-by-default refuse-to-start (ADR-0032 §4): an unreachable prod KMS at
    boot must not merely set a 0 gauge and keep serving — every credential op would
    then fail closed behind a green deploy. The lifespan raises a RuntimeError.
    """
    from app.core import crypto

    unhealthy = crypto.FakeKmsKeyProvider(available=False)
    monkeypatch.setattr(crypto, "get_key_provider", lambda settings: unhealthy)

    app_ = create_app(_prod_settings(vault_key_provider="aws", aws_kms_key_arn="arn:x"))
    with pytest.raises(RuntimeError, match="unhealthy at startup"):
        async with app_.router.lifespan_context(app_):
            pass  # pragma: no cover - the gate raises before this body runs


async def test_startup_crashes_when_kms_backend_unbuildable_in_prod() -> None:
    """A prod KMS backend whose build fails must CRASH startup, never silently start.

    ADR-0032 §2 refuse-to-start: selecting VAULT_KEY_PROVIDER=aws in prod but
    failing to build it (here: no key ARN) must NOT be swallowed into provider=None
    — that would start the platform with no KEK and defeat the gate. The
    KekConfigurationError propagates out of the lifespan.
    """
    app_ = create_app(_prod_settings(vault_key_provider="aws"))  # no aws_kms_key_arn
    with pytest.raises(KekConfigurationError):
        async with app_.router.lifespan_context(app_):
            pass  # pragma: no cover - the build raises before this body runs


async def test_startup_unconfigured_kek_in_dev_starts_without_provider() -> None:
    """A bare dev run (no KEK, not prod) degrades to no provider — does NOT crash."""
    app_ = create_app(
        Settings(_env_file=None, env="dev", secret_key="t", is_prod=False)  # type: ignore[arg-type]
    )
    async with app_.router.lifespan_context(app_):
        assert app_.state.key_provider is None


async def test_shutdown_closes_shared_redis_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lifespan shutdown closes the shared Redis client (2026-07-01 audit, W1).

    The lifespan opens ONE redis client shared by the rate limiter, the stream
    fan-out, and the ticket store; before this fix it was abandoned to GC on
    shutdown (leaked sockets on rolling restarts / dev reload). The client must
    be explicitly ``aclose()``d when the lifespan exits.
    """
    import redis.asyncio as redis_asyncio

    class _FakeRedisClient:
        def __init__(self) -> None:
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    fake = _FakeRedisClient()
    monkeypatch.setattr(redis_asyncio, "from_url", lambda url: fake)

    app_ = create_app(
        Settings(_env_file=None, env="dev", secret_key="t", is_prod=False)  # type: ignore[arg-type]
    )
    async with app_.router.lifespan_context(app_):
        assert not fake.closed  # still open while serving
    assert fake.closed is True
