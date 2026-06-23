"""Health endpoint tests (canonical M0 contract).

Readiness probes are monkeypatched — no real Postgres/Neo4j/Redis is touched.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.api.v1 import health
from app.core.config import Settings

EXPECTED_DEPENDENCIES = {"postgres", "neo4j", "redis"}


async def _failing_probe(settings: Settings) -> None:
    raise ConnectionError("dependency unreachable")


async def _ok_probe(settings: Settings) -> None:
    return None


def _patch_all_probes(monkeypatch: pytest.MonkeyPatch, probe: health.Probe) -> None:
    for name in list(health._PROBES):
        monkeypatch.setitem(health._PROBES, name, probe)


async def test_live_returns_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_live_has_no_dependency_checks(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Liveness must stay green even when every dependency is down."""
    _patch_all_probes(monkeypatch, _failing_probe)
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_ready_reports_ok_when_all_probes_pass(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_all_probes(monkeypatch, _ok_probe)
    response = await client.get("/api/v1/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert set(body["dependencies"]) == EXPECTED_DEPENDENCIES
    for dependency in body["dependencies"].values():
        assert dependency["status"] == "ok"
        assert dependency["error"] is None
        assert dependency["latency_ms"] >= 0


async def test_ready_degrades_gracefully_when_all_dependencies_down(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Readiness must report per-dependency errors and never raise."""
    _patch_all_probes(monkeypatch, _failing_probe)
    response = await client.get("/api/v1/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert set(body["dependencies"]) == EXPECTED_DEPENDENCIES
    for dependency in body["dependencies"].values():
        assert dependency["status"] == "error"
        assert "ConnectionError" in dependency["error"]
        assert dependency["latency_ms"] >= 0


async def test_ready_degrades_when_one_dependency_down(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_all_probes(monkeypatch, _ok_probe)
    monkeypatch.setitem(health._PROBES, "redis", _failing_probe)
    response = await client.get("/api/v1/health/ready")
    body = response.json()
    assert body["status"] == "degraded"
    assert body["dependencies"]["redis"]["status"] == "error"
    assert body["dependencies"]["postgres"]["status"] == "ok"
    assert body["dependencies"]["neo4j"]["status"] == "ok"


async def test_ready_times_out_hung_probe(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hung dependency is reported as an error within the probe budget."""

    async def hung_probe(settings: Settings) -> None:
        await asyncio.sleep(5)

    _patch_all_probes(monkeypatch, _ok_probe)
    monkeypatch.setitem(health._PROBES, "postgres", hung_probe)
    monkeypatch.setattr(health, "PROBE_TIMEOUT_SECONDS", 0.05)
    response = await client.get("/api/v1/health/ready")
    body = response.json()
    assert body["status"] == "degraded"
    assert body["dependencies"]["postgres"]["status"] == "error"
    assert "TimeoutError" in body["dependencies"]["postgres"]["error"]


# ---------------------------------------------------------------------------
# KEK-provider readiness gate (P1 W6-T2, ADR-0032 §4)
# ---------------------------------------------------------------------------


async def test_ready_omits_kek_probe_when_no_provider_configured(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare dev run (no KEK configured) keeps exactly the data-store deps."""
    _patch_all_probes(monkeypatch, _ok_probe)
    response = await client.get("/api/v1/health/ready")
    body = response.json()
    assert set(body["dependencies"]) == EXPECTED_DEPENDENCIES
    assert "kek_provider" not in body["dependencies"]


def _settings_with_kek() -> Settings:
    import base64
    import os

    kek = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    return Settings(_env_file=None, env="dev", secret_key="t", kek=kek)


async def test_ready_includes_kek_probe_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A configured KEK provider adds a ``kek_provider`` readiness dependency."""
    from app.main import create_app

    _patch_all_probes(monkeypatch, _ok_probe)
    app_ = create_app(_settings_with_kek())
    transport = httpx.ASGITransport(app=app_)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        response = await test_client.get("/api/v1/health/ready")
    body = response.json()
    assert "kek_provider" in body["dependencies"]
    assert body["dependencies"]["kek_provider"]["status"] == "ok"
    assert body["status"] == "ok"


async def test_ready_degrades_when_kek_provider_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreachable KMS makes readiness degrade and sets the healthy gauge to 0.

    Liveness is unaffected (this endpoint is readiness only) — the replica stays
    LIVE while being pulled from rotation (ADR-0032 §4).
    """
    _patch_all_probes(monkeypatch, _ok_probe)

    recorded: dict[str, bool] = {}

    def _record(*, healthy: bool) -> None:
        recorded["healthy"] = healthy

    monkeypatch.setattr("app.core.metrics.set_provider_healthy", _record)

    async def _down_kek(settings: Settings) -> None:
        from app.core import metrics

        metrics.set_provider_healthy(healthy=False)
        raise ConnectionError("key provider unreachable")

    monkeypatch.setitem(health._PROBES, "kek_provider", _down_kek)

    from app.main import create_app

    app_ = create_app(_settings_with_kek())
    transport = httpx.ASGITransport(app=app_)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        ready_resp = await test_client.get("/api/v1/health/ready")
        live_resp = await test_client.get("/api/v1/health/live")
    body = ready_resp.json()
    assert body["status"] == "degraded"
    assert body["dependencies"]["kek_provider"]["status"] == "error"
    assert recorded["healthy"] is False
    # Liveness stays OK — the replica is pulled from rotation but not killed.
    assert live_resp.status_code == 200
    assert live_resp.json() == {"status": "ok"}
