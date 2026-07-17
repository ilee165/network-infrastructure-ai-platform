"""Seeded fixture for the P1 Neo4j rebuild-drill dry-run (ADR-0030 §5.2).

In P1 there is no live Neo4j/Postgres (no hardware — P1-PLAN.md §6), so the drill
runs against a small, fixed in-memory projection: a known pre-wipe node/edge count
and a "rebuild" that re-derives the SAME counts. This makes the gate a GREEN
dry-run that still exercises the real assertion code path.

The P2 quarterly run replaces :func:`run_rebuild` with the real
:func:`app.engines.topology.metrics.timed_rebuild` (drop-and-reproject against the
restored/live Postgres), and the pre-wipe counts come from the live projection's
snapshot rather than this fixture. The ``truncate`` knob seeds a DELIBERATELY
incomplete rebuild so a test can prove the count assertion BITES (a rebuild that
drops topology must FAIL the drill, never silently pass).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "SeededProjection",
    "build_seeded_projection",
    "run_rebuild",
]


@dataclass(frozen=True)
class SeededProjection:
    """A fixed pre-wipe projection: the node/edge counts the rebuild must match."""

    nodes: int
    edges: int


# A small fixed inventory's projection (devices + interfaces + ip/subnet nodes and
# the has-interface / in-subnet / l3-adjacent edges between them). The exact values
# are arbitrary but FIXED so the dry-run is deterministic.
_SEED = SeededProjection(nodes=42, edges=57)


def build_seeded_projection() -> SeededProjection:
    """The pre-wipe projection counts for the seeded dry-run (deterministic)."""
    return _SEED


def run_rebuild(
    seed: SeededProjection,
    *,
    seconds: float = 2.0,
    truncate: int = 0,
) -> tuple[float, int, int]:
    """Simulate a drop-and-reproject of the seeded projection.

    Returns ``(seconds, rebuilt_nodes, rebuilt_edges)``. With ``truncate == 0`` the
    rebuild reproduces the seed exactly (the healthy path → counts match). A
    positive ``truncate`` drops that many nodes AND edges, modelling an INCOMPLETE
    projection so the count assertion fails — the trap the drill must catch
    (ADR-0030 Negative). ``seconds`` is the simulated RTO (well under the PROPOSED
    target for the dry-run).
    """
    rebuilt_nodes = seed.nodes - truncate
    rebuilt_edges = seed.edges - truncate
    return seconds, rebuilt_nodes, rebuilt_edges
