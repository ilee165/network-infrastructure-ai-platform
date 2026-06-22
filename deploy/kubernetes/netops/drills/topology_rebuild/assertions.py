"""Neo4j rebuild-drill assertions (P1 W5-T3, ADR-0030 §2/§5.2; ADR-0005 D5).

Two pass/fail checks express the "rebuildable projection" contract:

  * :func:`assert_rto_within_target` — ``topology_rebuild_seconds`` < the PROPOSED
    topology-RTO (the G-REL number; ADR-0030 §2/§6). The target is PARAMETERIZED
    (driven off the Job env), never a literal baked here.
  * :func:`assert_counts_match` — the rebuilt node/edge counts equal the pre-wipe
    projection's counts within an integer tolerance. A mismatch means the
    re-projection dropped or invented topology — the projection pipeline is
    incomplete (ADR-0030 Negative), which is a FAILED drill, not a passed one.

Each assertion emits one structured ``DRILL neo4j_rebuild <name>=PASS|FAIL`` line
and raises :class:`DrillError` on failure so the entrypoint can fail closed. The
checks are pure (no I/O), so they are unit-testable and the same code runs in the
P1 seeded dry-run and the P2 live quarterly run.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO

__all__ = [
    "DRILL_TAG",
    "DrillError",
    "RebuildDrillResult",
    "assert_counts_match",
    "assert_rto_within_target",
    "emit_line",
]

DRILL_TAG = "DRILL neo4j_rebuild"


class DrillError(Exception):
    """A rebuild-drill assertion failed. ``assertion`` names the failed check."""

    def __init__(self, assertion: str, message: str) -> None:
        super().__init__(message)
        self.assertion = assertion


def emit_line(line: str, *, stream: TextIO | None = None) -> None:
    """Write one structured drill line (default stdout) for the W5-T5 collector."""
    print(line, file=stream if stream is not None else sys.stdout, flush=True)


@dataclass(frozen=True)
class RebuildDrillResult:
    """The composite contract line the W5-T5 G-REL collector parses."""

    seconds: float
    nodes: int
    edges: int
    passed: bool

    def line(self) -> str:
        result = "PASS" if self.passed else "FAIL"
        return (
            f"{DRILL_TAG} seconds={self.seconds:.3f} nodes={self.nodes} "
            f"edges={self.edges} result={result}"
        )


def assert_rto_within_target(
    *,
    seconds: float,
    target_seconds: float,
    stream: TextIO | None = None,
) -> None:
    """The re-projection wall-clock must be < the PROPOSED topology-RTO (G-REL).

    ``target_seconds`` is parameterized off the Job env (``TOPOLOGY_RTO_SECONDS``);
    a non-positive target is itself a misconfiguration and fails the drill.
    """
    if target_seconds <= 0:
        emit_line(f"{DRILL_TAG} rto_within_target=FAIL", stream=stream)
        raise DrillError(
            "rto_within_target",
            f"topology-RTO target must be positive (got {target_seconds}s) — "
            "the drill cannot assert a non-positive budget (ADR-0030 §2)",
        )
    if seconds >= target_seconds:
        emit_line(f"{DRILL_TAG} rto_within_target=FAIL", stream=stream)
        raise DrillError(
            "rto_within_target",
            f"topology_rebuild_seconds={seconds:.3f} exceeds the topology-RTO "
            f"target {target_seconds:.0f}s (G-REL; ADR-0030 §2/§6)",
        )
    emit_line(f"{DRILL_TAG} rto_within_target=PASS", stream=stream)


def assert_counts_match(
    *,
    expected_nodes: int,
    expected_edges: int,
    rebuilt_nodes: int,
    rebuilt_edges: int,
    tolerance: int = 0,
    stream: TextIO | None = None,
) -> None:
    """Rebuilt node/edge counts must match the pre-wipe projection within tolerance.

    A drop-and-reproject of a pure projection must reconstruct the SAME multiset
    from Postgres alone (ADR-0005 D5). A count drift beyond ``tolerance`` proves
    the projection pipeline is incomplete (ADR-0030 Negative) → FAILED drill.
    """
    node_delta = abs(rebuilt_nodes - expected_nodes)
    edge_delta = abs(rebuilt_edges - expected_edges)
    if node_delta > tolerance or edge_delta > tolerance:
        emit_line(f"{DRILL_TAG} counts_match=FAIL", stream=stream)
        raise DrillError(
            "counts_match",
            f"rebuilt counts diverged from the pre-wipe projection beyond "
            f"tolerance {tolerance}: nodes {rebuilt_nodes} vs {expected_nodes} "
            f"(delta {node_delta}), edges {rebuilt_edges} vs {expected_edges} "
            f"(delta {edge_delta}) — the projection is incomplete (ADR-0005 D5)",
        )
    emit_line(f"{DRILL_TAG} counts_match=PASS", stream=stream)
