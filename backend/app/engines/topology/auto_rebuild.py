"""Operator CLI for the AUTOMATED Neo4j rebuild reconciler (P3 W1-T3).

Run as a module (the K8s `neo4j-auto-rebuild` CronJob / post-rollout Job does)::

    python -m app.engines.topology.auto_rebuild \
        --metrics-textfile /var/lib/node_exporter/textfile/topology_rebuild_seconds.prom \
        --staleness-seconds 300

Neo4j is a PURE projection of Postgres — it holds NO un-rebuildable state
(ADR-0005 D5). Neo4j Community has no clustering, so the HA/recovery story is a
full RE-PROJECTION from Postgres, never a graph restore. When the Neo4j pod's
liveness probe fails the kubelet RECREATES the container and the data PVC may come
up EMPTY or STALE; this reconciler closes that loop with NO manual step.

It is a thin orchestration seam over the EXISTING metric-emitting rebuild path
(:func:`app.engines.topology.metrics.timed_rebuild` -> ``rebuild()`` ->
``projector.full_rebuild``) — the projection logic itself is unchanged. On each
invocation it:

  1. reads the graph's freshness signal (node count + newest ``last_projected_at``,
     the property the projector stamps on every node/edge);
  2. RE-PROJECTS when the graph is EMPTY (the post-recreate state) or STALER than
     ``--staleness-seconds`` (``0`` forces an unconditional rebuild) — otherwise it
     is a NO-OP, so a healthy steady-state tick is cheap;
  3. WRITES the rebuild DURATION (and node/edge counts + graph age) to a
     node_exporter TEXTFILE ``.prom`` — the scrapable topology-RTO the W4-T4
     destroy-and-rebuild drill compares against and the G-OBS topology-freshness
     SLO reads (a Job pod is not itself scrapable; the file survives the pod for
     the agent to collect — the established no-pushgateway pattern), and
  4. prints one structured ``REBUILD neo4j_auto ...`` line for log-based alerting.

A rebuild failure exits non-zero so the Job is marked Failed (the loud signal).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
import time
from datetime import datetime
from typing import Any

import structlog

from app.core.config import get_settings
from app.engines.topology.metrics import observe_rebuild, timed_rebuild
from app.knowledge.neo4j_client import Neo4jClient, create_client
from app.models.mixins import utcnow

logger = structlog.get_logger(__name__)

__all__ = ["main", "reconcile", "graph_freshness"]


async def graph_freshness(client: Neo4jClient) -> tuple[int, datetime | None]:
    """Return ``(node_count, newest_last_projected_at)`` for the projected graph.

    The projector stamps ``last_projected_at`` on every node (ADR-0005 §3); the
    newest such value is the projection's freshness, and a zero node count is the
    post-recreate EMPTY state. Both come from one read transaction.
    """

    async def _read(tx: Any) -> tuple[int, datetime | None]:
        result = await tx.run(
            "MATCH (n) RETURN count(n) AS nodes, max(n.last_projected_at) AS newest"
        )
        record = await result.single()
        if record is None:
            return 0, None
        newest = record["newest"]
        # neo4j returns a DateTime; normalize to a stdlib datetime when present.
        newest_dt = newest.to_native() if hasattr(newest, "to_native") else newest
        return int(record["nodes"]), newest_dt

    return await client.execute_read(_read)


def _is_stale(
    nodes: int, newest: datetime | None, *, staleness_seconds: float, now: datetime
) -> bool:
    """True when the graph must be re-projected (empty, never-projected, or stale)."""
    if nodes == 0 or newest is None:
        return True  # post-recreate EMPTY graph: re-project.
    if staleness_seconds <= 0:
        return True  # 0 (or negative) forces an unconditional rebuild each tick.
    age_seconds = (now - newest).total_seconds()
    return age_seconds >= staleness_seconds


def _write_textfile(
    path: str, *, seconds: float, nodes: int, edges: int, age_seconds: float
) -> None:
    """Atomically write the node_exporter textfile metric (the scrapable RTO).

    Written to a temp file in the same dir then ``os.replace``d so a scraper never
    reads a half-written ``.prom`` (textfile-collector best practice).
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    body = (
        "# HELP topology_rebuild_seconds Wall-clock seconds of the last Neo4j "
        "re-projection from Postgres (the topology-RTO; G-REL/G-OBS).\n"
        "# TYPE topology_rebuild_seconds gauge\n"
        f"topology_rebuild_seconds {seconds:.6f}\n"
        "# HELP topology_rebuild_nodes Node count of the most recent re-projection.\n"
        "# TYPE topology_rebuild_nodes gauge\n"
        f"topology_rebuild_nodes {nodes}\n"
        "# HELP topology_rebuild_edges Edge count of the most recent re-projection.\n"
        "# TYPE topology_rebuild_edges gauge\n"
        f"topology_rebuild_edges {edges}\n"
        "# HELP topology_graph_age_seconds Age of the projected graph at reconcile "
        "time (the topology-freshness SLO input; G-OBS).\n"
        "# TYPE topology_graph_age_seconds gauge\n"
        f"topology_graph_age_seconds {age_seconds:.6f}\n"
        "# HELP topology_rebuild_completed_timestamp_seconds Unix time the reconcile "
        "finished.\n"
        "# TYPE topology_rebuild_completed_timestamp_seconds gauge\n"
        f"topology_rebuild_completed_timestamp_seconds {time.time():.0f}\n"
    )
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".topology_rebuild_", suffix=".prom")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, path)
    except BaseException:
        # Never leave a stray temp file behind on failure.
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


async def reconcile(*, metrics_textfile: str, staleness_seconds: float) -> dict[str, Any]:
    """Re-project the topology iff the graph is empty/stale; emit the RTO metric.

    Returns a JSON-safe summary (whether it rebuilt, the duration, node/edge
    counts, the pre-reconcile graph age). Always writes the textfile so the
    topology-RTO + freshness are scrapable even on a no-op tick.
    """
    settings = get_settings()
    client = create_client(settings)
    now = utcnow()
    try:
        nodes_before, newest = await graph_freshness(client)
        age_seconds = 0.0 if newest is None else max(0.0, (now - newest).total_seconds())
        stale = _is_stale(nodes_before, newest, staleness_seconds=staleness_seconds, now=now)

        if stale:
            # The metric-emitting full re-projection (records topology_rebuild_seconds
            # + node/edge gauges on the in-process registry, ADR-0005 D5).
            summary = await timed_rebuild()
            seconds = float(summary.get("seconds", 0.0))
            nodes = int(summary.get("nodes", 0))
            edges = int(summary.get("edges", 0))
            rebuilt = True
        else:
            # Healthy steady-state: no re-projection. Record a 0s "rebuild" so the
            # series stays continuous (and the graph age reflects freshness).
            seconds = 0.0
            nodes = nodes_before
            edges = 0
            rebuilt = False
            observe_rebuild(seconds=seconds, nodes=nodes, edges=edges)
    finally:
        await client.close()

    _write_textfile(
        metrics_textfile,
        seconds=seconds,
        nodes=nodes,
        edges=edges,
        age_seconds=age_seconds,
    )

    result: dict[str, Any] = {
        "ok": True,
        "rebuilt": rebuilt,
        "seconds": seconds,
        "nodes": nodes,
        "edges": edges,
        "graph_age_seconds": age_seconds,
        "staleness_seconds": staleness_seconds,
    }
    logger.info("topology.auto_rebuild_complete", **result)
    return result


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.engines.topology.auto_rebuild",
        description=(
            "Re-project the Neo4j topology from Postgres when the graph is empty/"
            "stale (the automated post-recreate recovery), and emit the rebuild-"
            "duration metric (the topology-RTO)."
        ),
    )
    parser.add_argument(
        "--metrics-textfile",
        required=True,
        help="path of the node_exporter textfile (.prom) to write the topology-RTO to.",
    )
    parser.add_argument(
        "--staleness-seconds",
        type=float,
        default=0.0,
        help=(
            "re-project only when the newest projection is older than this many "
            "seconds (0 forces an unconditional rebuild each tick; an EMPTY graph "
            "always rebuilds)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry: parse args, run the reconcile, return a process exit code."""
    args = _parse_args(argv)
    try:
        summary = asyncio.run(
            reconcile(
                metrics_textfile=args.metrics_textfile,
                staleness_seconds=args.staleness_seconds,
            )
        )
    except Exception as exc:  # the loud signal — a non-zero exit fails the Job.
        logger.error("topology.auto_rebuild_failed", error=str(exc))
        return 1
    print(
        "REBUILD neo4j_auto "
        f"rebuilt={str(summary['rebuilt']).lower()} "
        f"seconds={summary['seconds']:.3f} "
        f"nodes={summary['nodes']} edges={summary['edges']} "
        f"graph_age_seconds={summary['graph_age_seconds']:.0f} result=PASS",
        flush=True,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - module execution shim
    raise SystemExit(main())
