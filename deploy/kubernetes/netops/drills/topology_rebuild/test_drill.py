"""Neo4j rebuild-drill harness tests — positive PASS + a NEGATIVE per assertion.

These prove the assertions actually BITE (ADR-0030 Negative): a drill whose checks
are too weak silently passes an incomplete projection. For every property there is
a tampered-input case that MUST raise :class:`DrillError`:

  * counts-match — a rebuild that drops nodes/edges (truncated projection) fails.
  * topology-RTO — a rebuild slower than the target, and a non-positive target,
                   fail.

It also asserts the composite ``DRILL neo4j_rebuild ...`` contract line shape (the
W5-T5 collector consumer) and that the ``topology_rebuild_seconds`` metric is
registered on the Prometheus default registry exposed at ``/metrics`` (G-OBS), or
cleanly degrades when ``prometheus_client`` is absent.

Run (from the backend venv so ``app.*`` resolves):
  PYTHONPATH=backend:deploy/kubernetes/netops/drills \
    python -m pytest deploy/kubernetes/netops/drills/topology_rebuild/test_drill.py -q
"""

from __future__ import annotations

import io

import pytest

from topology_rebuild.assertions import (
    DRILL_TAG,
    DrillError,
    RebuildDrillResult,
    assert_counts_match,
    assert_rto_within_target,
)
from topology_rebuild.fixture import build_seeded_projection, run_rebuild
from topology_rebuild.run_drill import run

_SINK = io.StringIO  # fresh stream per assertion so emitted lines don't interleave.


# ---------------------------------------------------------------------------
# Structured-line contract (W5-T5 evidence consumer).
# ---------------------------------------------------------------------------


def test_composite_result_line_is_the_t5_contract() -> None:
    line = RebuildDrillResult(seconds=2.0, nodes=42, edges=57, passed=True).line()
    assert line == "DRILL neo4j_rebuild seconds=2.000 nodes=42 edges=57 result=PASS"


def test_composite_result_line_marks_failure() -> None:
    line = RebuildDrillResult(seconds=9.0, nodes=10, edges=12, passed=False).line()
    assert line.startswith(DRILL_TAG)
    assert "result=FAIL" in line


# ---------------------------------------------------------------------------
# topology-RTO assertion (G-REL): seconds < target.
# ---------------------------------------------------------------------------


def test_rto_within_target_passes_under_budget() -> None:
    sink = _SINK()
    assert_rto_within_target(seconds=2.0, target_seconds=1800.0, stream=sink)
    assert "rto_within_target=PASS" in sink.getvalue()


def test_rto_over_budget_fails() -> None:
    sink = _SINK()
    with pytest.raises(DrillError) as exc:
        assert_rto_within_target(seconds=1900.0, target_seconds=1800.0, stream=sink)
    assert exc.value.assertion == "rto_within_target"
    assert "rto_within_target=FAIL" in sink.getvalue()


def test_rto_non_positive_target_is_a_misconfiguration() -> None:
    with pytest.raises(DrillError):
        assert_rto_within_target(seconds=1.0, target_seconds=0.0, stream=_SINK())


# ---------------------------------------------------------------------------
# counts-match assertion (ADR-0005 D5): rebuilt counts == pre-wipe projection.
# ---------------------------------------------------------------------------


def test_counts_match_passes_on_exact_rebuild() -> None:
    sink = _SINK()
    assert_counts_match(
        expected_nodes=42,
        expected_edges=57,
        rebuilt_nodes=42,
        rebuilt_edges=57,
        stream=sink,
    )
    assert "counts_match=PASS" in sink.getvalue()


def test_truncated_rebuild_fails_count_assertion() -> None:
    """The trap the spec requires: a dropped-topology rebuild must FAIL the drill."""
    seed = build_seeded_projection()
    _, short_nodes, short_edges = run_rebuild(seed, truncate=3)
    sink = _SINK()
    with pytest.raises(DrillError) as exc:
        assert_counts_match(
            expected_nodes=seed.nodes,
            expected_edges=seed.edges,
            rebuilt_nodes=short_nodes,
            rebuilt_edges=short_edges,
            tolerance=0,
            stream=sink,
        )
    assert exc.value.assertion == "counts_match"
    assert "counts_match=FAIL" in sink.getvalue()


def test_counts_match_honors_tolerance() -> None:
    sink = _SINK()
    assert_counts_match(
        expected_nodes=42,
        expected_edges=57,
        rebuilt_nodes=41,
        rebuilt_edges=56,
        tolerance=1,
        stream=sink,
    )
    assert "counts_match=PASS" in sink.getvalue()


# ---------------------------------------------------------------------------
# Full entrypoint: the seeded dry-run is a GREEN PASS and emits the contract line.
# ---------------------------------------------------------------------------


def test_seeded_dry_run_passes_and_emits_contract_line() -> None:
    sink = _SINK()
    code = run(["--rto-seconds", "1800"], stream=sink)
    out = sink.getvalue()
    assert code == 0
    assert "rto_within_target=PASS" in out
    assert "counts_match=PASS" in out
    assert "result=PASS" in out
    assert f"{DRILL_TAG} OUTCOME=PASS assertions=2" in out


def test_entrypoint_fails_closed_on_impossible_rto() -> None:
    """A zero RTO budget makes the within-target check fail → non-zero exit."""
    sink = _SINK()
    code = run(["--rto-seconds", "0"], stream=sink)
    assert code == 1
    assert "result=FAIL" in sink.getvalue()


# ---------------------------------------------------------------------------
# Metric hook (G-OBS): topology_rebuild_seconds registered, or graceful no-op.
# ---------------------------------------------------------------------------


def test_metric_hook_registers_or_degrades_gracefully() -> None:
    from app.engines.topology import metrics

    # observe_rebuild must never raise, regardless of prometheus_client presence.
    metrics.observe_rebuild(seconds=1.5, nodes=42, edges=57)

    if metrics._PROM_ENABLED:
        from prometheus_client import REGISTRY

        # topology_rebuild_seconds is a Histogram → the _count series is on /metrics.
        value = REGISTRY.get_sample_value("topology_rebuild_seconds_count")
        assert value is not None and value >= 1
        nodes = REGISTRY.get_sample_value("topology_rebuild_nodes")
        assert nodes == 42
    else:
        assert metrics.REBUILD_SECONDS is None
