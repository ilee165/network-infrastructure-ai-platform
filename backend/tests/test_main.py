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
