"""Full-platform DR drill tests — chain PASS + the collector's aggregation contract.

These prove:
  * the collector PARSES the real per-tier ``DRILL ...`` lines into the table and
    rolls them up to one end-to-end verdict (it never re-implements an assertion);
  * a missing tier rolls up to FAIL (a DR drill that skipped a tier is not green);
  * a per-tier FAIL line propagates to the end-to-end result;
  * the composite ``DRILL full_platform ...`` line carries the measured RPO/RTO/
    topology-RTO numbers the G-REL evidence doc records;
  * the seeded end-to-end dry-run is a GREEN PASS over all three tiers (the W5-T5
    exit criterion at seeded scale).

Run (from the backend venv so ``app.*`` resolves):
  PYTHONPATH=backend:deploy/kubernetes/netops/drills \
    python -m pytest deploy/kubernetes/netops/drills/full_platform/test_drill.py -q
"""

from __future__ import annotations

import io

from full_platform.collector import FULL_TAG, TIER_TAGS, collect, parse
from full_platform.run_drill import run

# Realistic per-tier output, copied from the live seeded dry-run of T2/T3/T4 so the
# parser is tested against the EXACT contract lines those harnesses emit.
_PG_LINES = [
    "DRILL postgres_pitr rpo_within_window=PASS duration_s=0.000",
    "DRILL postgres_pitr audit_log_immutable=PASS duration_s=0.001",
    "DRILL postgres_pitr credentials_fail_closed=PASS duration_s=0.000",
    "DRILL postgres_pitr pgbackrest_verify_clean=PASS duration_s=0.000",
    "DRILL postgres_pitr OUTCOME=PASS assertions=4",
]
_NEO_LINES = [
    "DRILL neo4j_rebuild rto_within_target=PASS",
    "DRILL neo4j_rebuild counts_match=PASS",
    "DRILL neo4j_rebuild seconds=2.000 nodes=42 edges=57 result=PASS",
    "DRILL neo4j_rebuild OUTCOME=PASS assertions=2",
]
_PCAP_LINES = [
    "DRILL pcap_spot_restore restore_authorized=PASS",
    "DRILL pcap_spot_restore sampled_sha256_matches=PASS",
    "DRILL pcap_spot_restore no_tombstoned_resurrection=PASS",
    "DRILL pcap_spot_restore sampled=abc sha256=MATCH tombstoned_resurrected=NO result=PASS",
    "DRILL pcap_spot_restore OUTCOME=PASS assertions=3",
]
_ALL = _PG_LINES + _NEO_LINES + _PCAP_LINES


# ---------------------------------------------------------------------------
# Collector aggregation (the W5-T5 "parse, don't re-implement" contract).
# ---------------------------------------------------------------------------


def test_collector_parses_all_three_tiers_to_pass() -> None:
    ev = parse(_ALL)
    assert {t.tier for t in ev.tiers} == set(TIER_TAGS)
    assert ev.passed is True
    assert ev.passed_count == 3
    # The Neo4j metric line's seconds becomes the measured topology-RTO.
    assert ev.topology_rto_seconds == 2.0


def test_collector_records_per_assertion_status() -> None:
    ev = parse(_ALL)
    pg = next(t for t in ev.tiers if t.tier == "postgres_pitr")
    assert pg.assertions["rpo_within_window"] == "PASS"
    assert pg.assertions["pgbackrest_verify_clean"] == "PASS"
    # The composite pcap line's `sha256=MATCH` must NOT be parsed as an assertion.
    pcap = next(t for t in ev.tiers if t.tier == "pcap_spot_restore")
    assert "sha256" not in pcap.assertions
    assert "sampled" not in pcap.assertions


def test_missing_tier_rolls_up_to_fail() -> None:
    """A DR drill that skipped a tier is NOT green (no silent partial pass)."""
    ev = parse(_PG_LINES + _NEO_LINES)  # pcap tier absent
    assert ev.passed is False
    table = ev.render_table()
    assert "MISSING" in table


def test_tier_fail_propagates_to_end_to_end() -> None:
    failed_pcap = [
        "DRILL pcap_spot_restore sampled=abc sha256=MISMATCH "
        "tombstoned_resurrected=NO result=FAIL",
        "DRILL pcap_spot_restore OUTCOME=FAIL failed_assertion=sampled_sha256_matches",
    ]
    ev = parse(_PG_LINES + _NEO_LINES + failed_pcap)
    assert ev.passed is False
    pcap = next(t for t in ev.tiers if t.tier == "pcap_spot_restore")
    assert pcap.status == "FAIL"
    assert pcap.failed_assertion == "sampled_sha256_matches"


def test_tier_with_no_terminal_outcome_is_a_fail() -> None:
    """A tier that emitted assertions but no OUTCOME line is a silent gap = FAIL."""
    truncated = ["DRILL pcap_spot_restore restore_authorized=PASS"]
    ev = parse(_PG_LINES + _NEO_LINES + truncated)
    assert ev.passed is False


def test_composite_line_carries_measured_numbers() -> None:
    ev = collect("\n".join(_ALL))
    ev.rpo_seconds = 12.5
    ev.rto_seconds = 34.0
    line = ev.composite_line()
    assert line.startswith(FULL_TAG)
    assert "result=PASS" in line
    assert "rpo_s=12.500" in line
    assert "rto_s=34.000" in line
    assert "topology_rto_s=2.000" in line


def test_over_budget_rto_fails_even_when_all_tiers_pass() -> None:
    """A chain that passed every tier but blew the end-to-end RTO budget is FAIL.

    Wires the --rto-minutes budget (ADR-0030 §6 G-REL): passing tiers is necessary
    but NOT sufficient — exceeding the measured RTO target fails the aggregate.
    """
    ev = collect("\n".join(_ALL))  # every tier OUTCOME=PASS
    assert ev.passed is True  # no budget set yet → tiers-only verdict
    # Measured chain RTO (3600s) exceeds a 60-minute (3600s) budget? equal passes;
    # make it strictly over.
    ev.rto_budget_seconds = 3600.0
    ev.rto_seconds = 3600.0
    assert ev.passed is True  # exactly at budget is allowed (<=)
    ev.rto_seconds = 3600.1  # one tick over budget
    assert ev.passed is False
    assert "result=FAIL" in ev.composite_line()


def test_within_budget_rto_still_passes() -> None:
    ev = collect("\n".join(_ALL))
    ev.rto_budget_seconds = 3600.0
    ev.rto_seconds = 12.0
    assert ev.passed is True


def test_no_budget_means_rto_not_enforced() -> None:
    """Back-compat: with no rto_budget_seconds, the RTO check is a no-op."""
    ev = collect("\n".join(_ALL))
    ev.rto_seconds = 999999.0  # absurd RTO, but no budget configured
    assert ev.rto_budget_seconds is None
    assert ev.passed is True


# ---------------------------------------------------------------------------
# End-to-end seeded dry-run: all three tiers PASS (W5-T5 exit criterion).
# ---------------------------------------------------------------------------


def test_seeded_chain_is_green_end_to_end() -> None:
    sink = io.StringIO()
    code = run(
        [
            "--rpo-window-minutes",
            "5",
            "--rto-minutes",
            "60",
            "--topology-rto-minutes",
            "30",
        ],
        stream=sink,
    )
    out = sink.getvalue()
    assert code == 0, out
    # Every tier's terminal OUTCOME=PASS appears.
    assert "DRILL postgres_pitr OUTCOME=PASS" in out
    assert "DRILL neo4j_rebuild OUTCOME=PASS" in out
    assert "DRILL pcap_spot_restore OUTCOME=PASS" in out
    # The composite end-to-end line is emitted with a PASS verdict.
    assert f"{FULL_TAG} tiers=3 passed=3" in out
    assert "result=PASS" in out


def test_chain_fails_when_rto_budget_is_exceeded_end_to_end() -> None:
    """End-to-end: --rto-minutes 0 makes the budget 0s, so any measured RTO blows it.

    Proves --rto-minutes is no longer a no-op: even with all three tiers green, an
    over-budget chain exits non-zero (the G-REL assertion the bot flagged).
    """
    sink = io.StringIO()
    code = run(
        [
            "--rpo-window-minutes",
            "5",
            "--rto-minutes",
            "0",  # 0-minute budget → 0s; the seeded chain's wall-clock exceeds it
            "--topology-rto-minutes",
            "30",
        ],
        stream=sink,
    )
    out = sink.getvalue()
    # Every tier still PASSED individually...
    assert "DRILL postgres_pitr OUTCOME=PASS" in out
    assert "DRILL neo4j_rebuild OUTCOME=PASS" in out
    assert "DRILL pcap_spot_restore OUTCOME=PASS" in out
    # ...but the over-budget end-to-end RTO fails the aggregate (non-zero exit).
    assert code == 1, out
    assert f"{FULL_TAG} tiers=3 passed=3" in out  # tiers all passed
    assert "result=FAIL" in out  # yet the rolled-up verdict is FAIL on RTO
