"""Neo4j rebuild-drill entrypoint — reproject-then-assert (ADR-0030 §2/§5.2).

The K8s ``neo4j-rebuild-drill-job.yaml`` invokes this module as the assertion step.
In P1 (no hardware / no live stores, P1-PLAN.md §6) it runs against the seeded
fixture so the gate is a GREEN dry-run; the P2 quarterly run drops/recreates the
real Neo4j graph and re-projects from Postgres via
:func:`app.engines.topology.metrics.timed_rebuild`, then runs the SAME assertions
against the live counts.

It runs the two ADR-0030 §5.2 assertions (topology-RTO within target, rebuilt
node/edge counts match the pre-wipe projection), records the
``topology_rebuild_seconds`` + node/edge gauges onto Prometheus (G-REL/G-OBS), and
emits the composite contract line:
  ``DRILL neo4j_rebuild seconds=<n> nodes=<n> edges=<n> result=PASS|FAIL``
plus one ``DRILL neo4j_rebuild <assertion>=PASS|FAIL`` per assertion. It exits
non-zero on the first failure (fail closed).

Run:  python -m topology_rebuild.run_drill --rto-seconds 1800
      (wired via PYTHONPATH=/app:/app/drills inside the Job image).
"""

from __future__ import annotations

import argparse
import io
import os
import sys
from collections.abc import Sequence
from typing import TextIO

from .assertions import (
    DRILL_TAG,
    DrillError,
    RebuildDrillResult,
    assert_counts_match,
    assert_rto_within_target,
    emit_line,
)
from .fixture import build_seeded_projection, run_rebuild

# The PROPOSED topology-RTO default (seconds): < 30 min at 5,000 devices (ADR-0030
# §2/§6). PARAMETERIZED — the Job passes --rto-seconds / TOPOLOGY_RTO_SECONDS so it
# re-bases on the Consultant §12 answer from one source of truth. 1800s = 30 min.
DEFAULT_RTO_SECONDS = 1800.0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="topology_rebuild.run_drill")
    parser.add_argument(
        "--rto-seconds",
        type=float,
        default=float(os.environ.get("TOPOLOGY_RTO_SECONDS", DEFAULT_RTO_SECONDS)),
        help="PROPOSED topology-RTO target in seconds (drill fails if rebuild >= this).",
    )
    parser.add_argument(
        "--count-tolerance",
        type=int,
        default=int(os.environ.get("TOPOLOGY_COUNT_TOLERANCE", "0")),
        help="allowed absolute node/edge count drift vs the pre-wipe projection.",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def _record_metric(seconds: float, nodes: int, edges: int) -> bool:
    """Record the rebuild onto the engine's Prometheus metrics (best-effort).

    Returns whether the Prometheus series was actually updated (False on a slim
    install without ``prometheus_client``). The ``DRILL ...`` line is the source of
    truth either way, so a metrics import failure never fails the drill.
    """
    try:
        from app.engines.topology.metrics import observe_rebuild  # noqa: PLC0415

        observe_rebuild(seconds=seconds, nodes=nodes, edges=edges)
        from app.engines.topology import metrics  # noqa: PLC0415

        return bool(getattr(metrics, "_PROM_ENABLED", False))
    except Exception:  # pragma: no cover - app package not importable in some CI
        return False


def run(argv: Sequence[str] | None = None, *, stream: TextIO | None = None) -> int:
    """Run the rebuild-drill against the seeded fixture; return a process exit code.

    Returns ``0`` if every assertion PASSED, ``1`` on the first failure (fail
    closed). The composite ``DRILL neo4j_rebuild ...`` line is emitted either way so
    the W5-T5 collector always sees a result.
    """
    args = _parse_args(argv)
    seed = build_seeded_projection()

    # P1 dry-run: a healthy drop-and-reproject reproduces the seed exactly. (P2
    # swaps this for app.engines.topology.metrics.timed_rebuild against live stores.)
    seconds, rebuilt_nodes, rebuilt_edges = run_rebuild(seed)

    # Record the topology-RTO + node/edge gauges so the number is a checkable series
    # on /metrics, not just a log line (G-REL/G-OBS). Best-effort; never gates.
    _record_metric(seconds, rebuilt_nodes, rebuilt_edges)

    try:
        assert_rto_within_target(
            seconds=seconds,
            target_seconds=args.rto_seconds,
            stream=stream,
        )
        assert_counts_match(
            expected_nodes=seed.nodes,
            expected_edges=seed.edges,
            rebuilt_nodes=rebuilt_nodes,
            rebuilt_edges=rebuilt_edges,
            tolerance=args.count_tolerance,
            stream=stream,
        )
        # Negative self-check (proves the count assertion BITES): a DELIBERATELY
        # truncated rebuild MUST fail the count assertion. A guard that does not
        # raise here is itself a failed drill (the invariant is too weak —
        # ADR-0030 Negative). Run on a throwaway sink so the collector never sees it.
        _assert_count_guard_bites(seed, tolerance=args.count_tolerance)
    except DrillError as exc:
        emit_line(
            RebuildDrillResult(seconds, rebuilt_nodes, rebuilt_edges, passed=False).line(),
            stream=stream,
        )
        emit_line(f"{DRILL_TAG} OUTCOME=FAIL failed_assertion={exc.assertion}", stream=stream)
        return 1

    emit_line(
        RebuildDrillResult(seconds, rebuilt_nodes, rebuilt_edges, passed=True).line(),
        stream=stream,
    )
    emit_line(f"{DRILL_TAG} OUTCOME=PASS assertions=2", stream=stream)
    return 0


def _assert_count_guard_bites(seed, *, tolerance: int) -> None:
    """The count assertion MUST raise when the rebuild drops topology.

    Forces a truncated rebuild (one fewer node/edge than the seed, beyond
    tolerance) and requires the count assertion to raise. If it does NOT, the
    invariant is too weak and the drill fails closed (ADR-0030 Negative).
    """
    _, short_nodes, short_edges = run_rebuild(seed, truncate=tolerance + 1)
    silent = io.StringIO()
    try:
        assert_counts_match(
            expected_nodes=seed.nodes,
            expected_edges=seed.edges,
            rebuilt_nodes=short_nodes,
            rebuilt_edges=short_edges,
            tolerance=tolerance,
            stream=silent,
        )
    except DrillError:
        return  # correct: the count guard bit on the truncated rebuild.
    raise DrillError(
        "count_guard_self_check",
        "the count assertion did NOT raise when the rebuild dropped topology — "
        "the rebuildable-projection invariant is too weak (ADR-0005 D5 / ADR-0030 Negative)",
    )


if __name__ == "__main__":  # pragma: no cover - exercised via the Job / test wrapper
    sys.exit(run())
