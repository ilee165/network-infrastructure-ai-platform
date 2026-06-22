"""Topology-RTO Prometheus metrics for the Neo4j rebuild path (P1 W5-T3).

Neo4j has **no backup**: DR is a full re-projection from Postgres, never a graph
dump/restore (ADR-0005 D5, ADR-0030 §2). The *time* that re-projection takes is
the topology-RTO — the G-REL reliability number the W5-T3 rebuild-drill asserts
``< topology-RTO`` (ADR-0030 §2/§6). This module owns the three metrics the drill
(and the live operator rebuild) emit so the number is a gate-checkable series on
``/metrics``, not just a log line:

  * ``topology_rebuild_seconds`` — Histogram of the wall-clock re-projection time.
  * ``topology_rebuild_nodes``   — Gauge of the node count of the last rebuild.
  * ``topology_rebuild_edges``   — Gauge of the edge count of the last rebuild.

Registration is **graceful**: ``prometheus_client`` is an optional observability
dependency (D15). When it is importable the metrics register on the default
``REGISTRY`` (so the api/worker ``/metrics`` endpoint exposes them); when it is
not, the helpers become safe no-ops so importing this module — and the rebuild
path that wraps it — never hard-fails on a slim install. The structured
``DRILL ...`` line the drill prints is independent of Prometheus, so the
pass/fail evidence survives either way.

The wrapper :func:`timed_rebuild` mirrors the existing engine convention of a thin
instrumentation seam over the pure ``engines/topology`` rebuild path: it calls the
unchanged :func:`app.engines.topology.rebuild.rebuild`, times it with a monotonic
clock, and records the histogram + gauges from the rebuild's own node/edge summary.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

import structlog

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Awaitable, Callable

logger = structlog.get_logger(__name__)

__all__ = [
    "REBUILD_EDGES",
    "REBUILD_NODES",
    "REBUILD_SECONDS",
    "observe_rebuild",
    "timed_rebuild",
]

# Histogram buckets in SECONDS. The topology-RTO target is PROPOSED at < 30 min
# (1800s) at 5,000 devices (ADR-0030 §2/§6); the buckets straddle that target so
# the histogram resolves both a fast seeded-fixture rebuild (CI dry-run) and the
# certified-scale run near the RTO boundary (P2/lab). Parameterized target lives
# in the drill env, NOT baked here.
_BUCKETS = (1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0, 1800.0, 3600.0)

try:  # Optional observability dependency (D15) — degrade to no-ops if absent.
    from prometheus_client import Gauge, Histogram

    REBUILD_SECONDS: Any = Histogram(
        "topology_rebuild_seconds",
        "Wall-clock seconds for a full Neo4j topology re-projection from Postgres "
        "(the topology-RTO; G-REL). Drill pass/fail is value < topology-RTO.",
        buckets=_BUCKETS,
    )
    REBUILD_NODES: Any = Gauge(
        "topology_rebuild_nodes",
        "Node count of the most recent full topology re-projection.",
    )
    REBUILD_EDGES: Any = Gauge(
        "topology_rebuild_edges",
        "Edge count of the most recent full topology re-projection.",
    )
    _PROM_ENABLED = True
except Exception:  # pragma: no cover - exercised only on a slim install
    # No prometheus_client: keep the symbols present (callers reference them) but
    # inert. The DRILL line + the returned summary remain the source of truth.
    REBUILD_SECONDS = None
    REBUILD_NODES = None
    REBUILD_EDGES = None
    _PROM_ENABLED = False


def observe_rebuild(*, seconds: float, nodes: int, edges: int) -> None:
    """Record one rebuild's RTO + node/edge counts onto the Prometheus series.

    No-op when ``prometheus_client`` is unavailable (the metrics are ``None``);
    the caller's structured output still carries the numbers either way.
    """
    if not _PROM_ENABLED:
        return
    REBUILD_SECONDS.observe(seconds)
    REBUILD_NODES.set(nodes)
    REBUILD_EDGES.set(edges)


async def timed_rebuild(
    run_id: UUID | None = None,
    *,
    rebuild_fn: Callable[[UUID | None], Awaitable[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Run the full Postgres -> Neo4j re-projection and record the RTO metric.

    Thin instrumentation seam over the unchanged
    :func:`app.engines.topology.rebuild.rebuild`: times the call with a monotonic
    clock, records ``topology_rebuild_seconds`` + the node/edge gauges, and
    returns the rebuild summary augmented with ``seconds``. ``rebuild_fn`` is an
    injection point for tests (defaults to the real rebuild).
    """
    if rebuild_fn is None:
        from app.engines.topology.rebuild import rebuild  # noqa: PLC0415

        rebuild_fn = rebuild

    started = time.monotonic()
    summary = await rebuild_fn(run_id)
    seconds = time.monotonic() - started

    nodes = int(summary.get("nodes", 0))
    edges = int(summary.get("edges", 0))
    observe_rebuild(seconds=seconds, nodes=nodes, edges=edges)

    summary = {**summary, "seconds": seconds}
    logger.info(
        "topology.rebuild_timed",
        seconds=round(seconds, 3),
        nodes=nodes,
        edges=edges,
        prometheus=_PROM_ENABLED,
    )
    return summary
