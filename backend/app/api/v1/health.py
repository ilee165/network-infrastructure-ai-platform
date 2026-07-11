"""Liveness and readiness endpoints (canonical M0 contract; ADR-0015).

- ``GET /api/v1/health/live``  — process is up; touches no dependencies.
- ``GET /api/v1/health/ready`` — probes Postgres, schema (Alembic), Neo4j, and
  Redis with a ~2 s timeout each and reports per-dependency
  ``{status, latency_ms, error}``. Overall status is ``"ok"`` or ``"degraded"``;
  the endpoint **never raises** when a dependency is down (HTTP 200 either way
  — orchestrators inspect the body, and compose/K8s probes are configured
  against it in deploy/).

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


async def _probe_schema(settings: Settings) -> None:
    """Confirm Alembic has been applied (``alembic_version`` row readable).

    Distinct from :func:`_probe_postgres`: the DB can answer ``SELECT 1`` while
    migrations were never run (login then 503s on missing ``users``). Fails with
    a clear message so readiness is ``degraded`` until ``alembic upgrade head``.
    """
    engine = db.create_engine(settings)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1 FROM alembic_version LIMIT 1"))
    except Exception as exc:
        # Normalize to a short, operator-facing message (no DSN / SQL dump).
        msg = str(exc).lower()
        if "does not exist" in msg or "undefinedtable" in type(exc).__name__.lower():
            raise ConnectionError("schema not applied — run alembic upgrade head") from exc
        raise
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
    from app.core.redis import create_redis_client  # local import: keep module import light

    client = create_redis_client(settings)
    try:
        await client.ping()
    finally:
        await client.aclose()


def _make_kek_probe(provider: object) -> Probe:
    """Build a readiness probe over an ALREADY-BUILT KEK provider (ADR-0032 §4, W6-T2).

    The provider is constructed ONCE at startup (``app.state.key_provider``,
    main.py) and reused here — the probe never re-builds the SDK client per poll
    (which would re-login to Vault / re-run DefaultAzureCredential + a KeyClient
    round-trip on every ``/ready`` and risk PROBE_TIMEOUT flapping). It calls
    ``provider.health()`` on the cached instance; the blocking SDK round-trip is
    offloaded to a worker thread so it cannot stall the event loop. An unreachable
    KMS makes the probe fail so the replica is pulled from rotation (readiness →
    degraded) while it stays *live* (liveness is unaffected) and alerts fire. The
    0/1 ``vault_key_provider_healthy`` gauge is refreshed from the result either way.
    """

    async def _probe(settings: Settings) -> None:
        from app.core import metrics

        available = await asyncio.to_thread(lambda: provider.health().available)  # type: ignore[attr-defined]
        metrics.set_provider_healthy(healthy=available)
        if not available:
            raise ConnectionError("key provider unreachable")

    return _probe


#: Probe registry — tests monkeypatch entries to simulate outages. The KEK probe
#: is added per-request only when a provider is cached on app.state (see :func:`ready`).
_PROBES: dict[str, Probe] = {
    "postgres": _probe_postgres,
    "schema": _probe_schema,
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


async def build_readiness_report(request: Request) -> ReadinessReport:
    """Probe postgres/schema/neo4j/redis (+ KEK) and return the readiness report.

    Shared by the public ``GET /health/ready`` probe and the admin Settings
    platform-health panel so both surfaces stay in lockstep. Never raises when
    a dependency is down — failures become per-dependency ``error`` statuses.
    """
    settings: Settings = request.app.state.settings
    probes = dict(_PROBES)
    # ADR-0032 §4: an unreachable KMS pulls this replica from rotation. The probe
    # runs against the provider BUILT ONCE at startup (app.state.key_provider) —
    # never re-constructed per poll. When no provider is cached (a bare dev run
    # with no KEK configured) the probe is omitted; tests may inject a "kek_provider"
    # override into _PROBES to simulate outages without a real provider.
    cached_provider = getattr(request.app.state, "key_provider", None)
    if "kek_provider" in _PROBES:
        probes["kek_provider"] = _PROBES["kek_provider"]
    elif cached_provider is not None:
        probes["kek_provider"] = _make_kek_probe(cached_provider)
    names = list(probes)
    results = await asyncio.gather(*(_run_probe(probes[name], settings) for name in names))
    dependencies = dict(zip(names, results, strict=True))
    overall: Literal["ok", "degraded"] = (
        "ok" if all(dep.status == "ok" for dep in dependencies.values()) else "degraded"
    )
    return ReadinessReport(status=overall, dependencies=dependencies)


@router.get("/ready", response_model=ReadinessReport)
async def ready(request: Request) -> ReadinessReport:
    """Readiness: probe postgres/schema/neo4j/redis (+ the KEK provider) concurrently."""
    return await build_readiness_report(request)
