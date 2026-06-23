"""Liveness and readiness endpoints (canonical M0 contract; ADR-0015).

- ``GET /api/v1/health/live``  — process is up; touches no dependencies.
- ``GET /api/v1/health/ready`` — probes Postgres, Neo4j, and Redis with a
  ~2 s timeout each and reports per-dependency ``{status, latency_ms, error}``.
  Overall status is ``"ok"`` or ``"degraded"``; the endpoint **never raises**
  when a dependency is down (HTTP 200 either way — orchestrators inspect the
  body, and compose/K8s probes are configured against it in deploy/).

Health endpoints are unauthenticated and expose no version/config detail
beyond per-dependency up/down (ADR-0015 hardening choice).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import text

from app import db
from app.core.config import Settings

router = APIRouter(prefix="/health", tags=["health"])

#: Per-dependency probe budget. Readiness responds in roughly this bound even
#: when every dependency is unreachable (probes run concurrently).
PROBE_TIMEOUT_SECONDS = 2.0

Probe = Callable[[Settings], Awaitable[None]]


class DependencyStatus(BaseModel):
    """Health of one external dependency as seen from this process."""

    status: Literal["ok", "error"]
    latency_ms: float
    error: str | None = None


class ReadinessReport(BaseModel):
    """Aggregate readiness: degraded if any dependency probe fails."""

    status: Literal["ok", "degraded"]
    dependencies: dict[str, DependencyStatus]


async def _probe_postgres(settings: Settings) -> None:
    """``SELECT 1`` through a throwaway async engine (never reuses app pools)."""
    engine = db.create_engine(settings)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    finally:
        await engine.dispose()


async def _probe_neo4j(settings: Settings) -> None:
    """Verify bolt connectivity with the configured credentials."""
    from neo4j import AsyncGraphDatabase  # local import: keep module import light

    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )
    try:
        await driver.verify_connectivity()
    finally:
        await driver.close()


async def _probe_redis(settings: Settings) -> None:
    """PING the Redis broker/cache."""
    import redis.asyncio as aioredis  # local import: keep module import light

    client = aioredis.from_url(settings.redis_url)
    try:
        await client.ping()
    finally:
        await client.aclose()


async def _probe_kek_provider(settings: Settings) -> None:
    """Drive the fail-closed KEK-provider readiness gate (ADR-0032 §4, W6-T2).

    Builds the configured :class:`~app.core.crypto.KeyProvider` and asks for its
    ``health()``; an unreachable KMS makes this probe fail so the replica is
    pulled from rotation (readiness → degraded) while it stays *live* (liveness is
    unaffected) and alerts fire. The 0/1 ``vault_key_provider_healthy`` gauge is
    refreshed from the result either way. The provider build itself runs in a
    worker thread so a blocking SDK call cannot stall the event loop.
    """
    from app.core import crypto, metrics

    def _check() -> bool:
        provider = crypto.get_key_provider(settings)
        return provider.health().available

    available = await asyncio.to_thread(_check)
    metrics.set_provider_healthy(healthy=available)
    if not available:
        raise ConnectionError("key provider unreachable")


def _kek_provider_configured(settings: Settings) -> bool:
    """Whether a KEK provider is configured (so the readiness probe applies).

    With no provider configured (a bare dev run) the KEK probe is omitted — the
    credential vault is simply unused — so readiness stays exactly the data-store
    set. Any KMS backend or local KEK turns the probe on.
    """
    return bool(settings.vault_key_provider or settings.kek or settings.kek_file)


#: Probe registry — tests monkeypatch entries to simulate outages. The KEK probe
#: is added per-request only when a provider is configured (see :func:`ready`).
_PROBES: dict[str, Probe] = {
    "postgres": _probe_postgres,
    "neo4j": _probe_neo4j,
    "redis": _probe_redis,
}


async def _run_probe(probe: Probe, settings: Settings) -> DependencyStatus:
    """Run one probe under the timeout budget; failures become statuses, never raise."""
    start = time.perf_counter()
    try:
        await asyncio.wait_for(probe(settings), timeout=PROBE_TIMEOUT_SECONDS)
    except Exception as exc:  # readiness must degrade gracefully, never 500
        latency_ms = (time.perf_counter() - start) * 1000.0
        detail = str(exc) or "unreachable"
        return DependencyStatus(
            status="error", latency_ms=latency_ms, error=f"{type(exc).__name__}: {detail}"
        )
    latency_ms = (time.perf_counter() - start) * 1000.0
    return DependencyStatus(status="ok", latency_ms=latency_ms)


@router.get("/live")
async def live() -> dict[str, str]:
    """Liveness: the process and event loop are responsive. No dependencies."""
    return {"status": "ok"}


@router.get("/ready", response_model=ReadinessReport)
async def ready(request: Request) -> ReadinessReport:
    """Readiness: probe postgres/neo4j/redis (+ the KEK provider) concurrently."""
    settings: Settings = request.app.state.settings
    probes = dict(_PROBES)
    if _kek_provider_configured(settings):
        # ADR-0032 §4: an unreachable KMS pulls this replica from rotation.
        probes["kek_provider"] = _PROBES.get("kek_provider", _probe_kek_provider)
    names = list(probes)
    results = await asyncio.gather(*(_run_probe(probes[name], settings) for name in names))
    dependencies = dict(zip(names, results, strict=True))
    overall: Literal["ok", "degraded"] = (
        "ok" if all(dep.status == "ok" for dep in dependencies.values()) else "degraded"
    )
    return ReadinessReport(status=overall, dependencies=dependencies)
