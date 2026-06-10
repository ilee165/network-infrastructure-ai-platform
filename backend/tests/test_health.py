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
