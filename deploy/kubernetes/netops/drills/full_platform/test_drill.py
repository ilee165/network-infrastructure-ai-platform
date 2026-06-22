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
