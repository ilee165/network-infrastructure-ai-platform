"""DR-runbook generator tests — deterministic render + the four-drill contract.

These prove the runbook generator is the dogfooding wiring the W5-T5 spec asks
for: it renders all four DR runbooks deterministically (no LLM), the output is
stable (re-running yields byte-identical content — "matches the source exactly by
construction"), and every runbook carries the GENERATED banner + the per-tier
`DRILL ...` contract lines so a reader can trace evidence back to the collector.

Run:  PYTHONPATH=backend:deploy/kubernetes/netops/drills \
        python -m pytest deploy/kubernetes/netops/drills/full_platform/test_runbook.py -q
"""

from __future__ import annotations

from full_platform.runbook import ALL_RUNBOOKS, generate


def test_four_runbooks_are_generated(tmp_path) -> None:
    written = generate(tmp_path)
    names = {p.name for p in written}
    assert names == {
        "dr-postgres-pitr.md",
        "dr-neo4j-rebuild.md",
        "dr-pcap-spot-restore.md",
        "dr-full-platform.md",
    }


def test_render_is_deterministic(tmp_path) -> None:
    """Re-rendering must be byte-identical (no LLM, no timestamps, no nonce)."""
    first = {rb.slug: rb.render() for rb in ALL_RUNBOOKS}
    second = {rb.slug: rb.render() for rb in ALL_RUNBOOKS}
    assert first == second


def test_every_runbook_marks_itself_generated_and_offline_honest() -> None:
    for rb in ALL_RUNBOOKS:
        md = rb.render()
        assert "GENERATED — do not edit by hand" in md
        # The honest LLM-offline note (W5-T5 spec: no fabricated generated output).
        assert "no fabricated generated output" in md


def test_full_platform_runbook_carries_the_composite_contract_line() -> None:
    full = next(rb for rb in ALL_RUNBOOKS if rb.slug == "full-platform")
    md = full.render()
    assert "DRILL full_platform tiers=3 passed=3" in md
    assert "result=PASS" in md
    # It references the aggregating collector + the evidence doc.
    assert "P1-W5-G-REL-evidence.md" in md


def test_per_tier_runbooks_carry_their_drill_tags() -> None:
    tags = {
        "postgres-pitr": "DRILL postgres_pitr OUTCOME=PASS",
        "neo4j-rebuild": "DRILL neo4j_rebuild OUTCOME=PASS",
        "pcap-spot-restore": "DRILL pcap_spot_restore OUTCOME=PASS",
    }
    by_slug = {rb.slug: rb.render() for rb in ALL_RUNBOOKS}
    for slug, tag in tags.items():
        assert tag in by_slug[slug]
