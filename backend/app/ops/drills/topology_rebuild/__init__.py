"""Neo4j rebuild-drill harness (P1 W5-T3, ADR-0030 §2/§5.2; ADR-0005 D5).

Neo4j has **no backup** — DR is a full re-projection from Postgres, never a graph
dump/restore (ADR-0005 D5). The K8s ``neo4j-rebuild-drill-job.yaml`` drops/recreates
the projected graph and runs the existing ``engines/topology`` full-rebuild over the
``normalized_*`` tables; this harness is the *assertion* half that turns "rebuildable"
into a checkable invariant (ADR-0005's contract):

  (1) topology-RTO   — ``topology_rebuild_seconds`` < the PROPOSED topology-RTO
                       (< 30 min at 5,000 devices; ADR-0030 §2/§6). The metric is
                       recorded onto Prometheus (G-REL/G-OBS) by
                       :mod:`app.engines.topology.metrics`.
  (2) count match    — the rebuilt node/edge counts equal the pre-wipe projection's
                       counts within tolerance; a mismatch is a FAILED drill (the
                       projection pipeline is incomplete — ADR-0030 Negative).

It emits, for the W5-T5 G-REL evidence collector, one composite contract line:
  ``DRILL neo4j_rebuild seconds=<n> nodes=<n> edges=<n> result=PASS|FAIL``
plus one ``DRILL neo4j_rebuild <assertion>=PASS|FAIL`` per assertion, and exits
non-zero on the first failure (fail closed).

In P1 (no hardware, P1-PLAN.md §6) the drill runs against a seeded in-memory
fixture so the gate is a GREEN dry-run; the P2 quarterly run points the same
assertions at a real drop-and-reproject through
:func:`app.engines.topology.metrics.timed_rebuild`.
"""

from __future__ import annotations

from .assertions import (
    DRILL_TAG,
    DrillError,
    RebuildDrillResult,
    assert_counts_match,
    assert_rto_within_target,
    emit_line,
)

__all__ = [
    "DRILL_TAG",
    "DrillError",
    "RebuildDrillResult",
    "assert_counts_match",
    "assert_rto_within_target",
    "emit_line",
]
