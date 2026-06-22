"""Evidence collector — parse the per-tier ``DRILL ...`` lines into a results table.

This is the W5-T5 aggregation layer (ADR-0030 §5.3 requirement 2: "aggregate,
don't re-implement"). It consumes the structured lines the three per-tier drills
already emit (W5-T2/T3/T4) and renders them into the single source of measured
numbers the G-REL evidence doc records. It performs NO assertion logic of its own
— a tier's PASS/FAIL is whatever that tier's harness decided; the collector only
parses, tabulates, and rolls the per-tier OUTCOMEs up into one end-to-end verdict.

The per-tier contract lines this parses (authored by T2/T3/T4, never duplicated):

  * Postgres PITR (W5-T2):
      ``DRILL postgres_pitr <assertion>=PASS|FAIL duration_s=<n>``
      ``DRILL postgres_pitr OUTCOME=PASS|FAIL assertions=<n>``
  * Neo4j rebuild (W5-T3):
      ``DRILL neo4j_rebuild <assertion>=PASS|FAIL``
      ``DRILL neo4j_rebuild seconds=<n> nodes=<n> edges=<n> result=PASS|FAIL``
      ``DRILL neo4j_rebuild OUTCOME=PASS|FAIL assertions=<n>``
  * pcap spot-restore (W5-T4):
      ``DRILL pcap_spot_restore <assertion>=PASS|FAIL``
      ``DRILL pcap_spot_restore sampled=<id> sha256=MATCH|MISMATCH
        tombstoned_resurrected=NO|YES result=PASS|FAIL``
      ``DRILL pcap_spot_restore OUTCOME=PASS|FAIL assertions=<n>``

The collector also emits its OWN composite end-to-end line for the evidence doc:

  ``DRILL full_platform tiers=<n> passed=<n> rpo_s=<n> rto_s=<n>
    topology_rto_s=<n> result=PASS|FAIL``

so the W5-T5 evidence doc has a single grep target for the rolled-up verdict and
the measured RPO / RTO / topology-RTO numbers (recorded against the PROPOSED
targets — never asserted here; the PROPOSED-vs-measured judgement lives in the
evidence doc + the per-tier RTO assertion).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import TextIO

#: The drill tags, in chain order, the collector recognizes.
TIER_TAGS: tuple[str, ...] = ("postgres_pitr", "neo4j_rebuild", "pcap_spot_restore")

#: Human labels for the evidence table (chain order).
TIER_LABELS: dict[str, str] = {
    "postgres_pitr": "Postgres PITR (object-store-alone restore)",
    "neo4j_rebuild": "Neo4j rebuild (re-project over RESTORED Postgres)",
    "pcap_spot_restore": "pcap spot-restore (retention-honoring)",
}

#: Composite end-to-end tag the collector emits.
FULL_TAG = "DRILL full_platform"

# Matches a tier's terminal verdict: ``DRILL <tier> OUTCOME=PASS assertions=<n>``.
_OUTCOME_RE = re.compile(
    r"^DRILL\s+(?P<tier>\w+)\s+OUTCOME=(?P<outcome>PASS|FAIL)(?:\s+assertions=(?P<n>\d+))?"
    r"(?:\s+failed_assertion=(?P<failed>\S+))?"
)
# Matches one per-assertion line: ``DRILL <tier> <name>=PASS|FAIL ...``.
_ASSERTION_RE = re.compile(r"^DRILL\s+(?P<tier>\w+)\s+(?P<name>\w+)=(?P<status>PASS|FAIL)\b")
# Neo4j composite metric line carries the measured topology-RTO seconds.
_NEO4J_METRIC_RE = re.compile(
    r"^DRILL\s+neo4j_rebuild\s+seconds=(?P<seconds>[\d.]+)\s+nodes=(?P<nodes>\d+)\s+"
    r"edges=(?P<edges>\d+)\s+result=(?P<result>PASS|FAIL)"
)


@dataclass
class TierResult:
    """One per-tier roll-up parsed from that tier's ``DRILL ...`` lines."""

    tier: str
    #: True iff the tier emitted a terminal ``OUTCOME=PASS``.
    passed: bool = False
    #: Whether the tier's terminal OUTCOME line was seen at all (a tier that
    #: produced no terminal verdict is a FAILED tier — a silent gap, not a pass).
    saw_outcome: bool = False
    #: Per-assertion name -> PASS|FAIL, in first-seen order.
    assertions: dict[str, str] = field(default_factory=dict)
    #: First failed assertion name, if the tier reported one.
    failed_assertion: str | None = None
    #: Measured topology-RTO seconds (Neo4j tier only).
    topology_rto_seconds: float | None = None

    @property
    def label(self) -> str:
        return TIER_LABELS.get(self.tier, self.tier)

    @property
    def status(self) -> str:
        return "PASS" if (self.passed and self.saw_outcome) else "FAIL"


@dataclass
class DrillEvidence:
    """The aggregated evidence table + the rolled-up end-to-end verdict.

    ``rpo_seconds`` / ``rto_seconds`` are the MEASURED end-to-end numbers recorded
    against the PROPOSED targets in the G-REL evidence doc (ADR-0030 §6); the
    collector measures and records them but does NOT assert them (the per-tier RTO
    assertion + the evidence doc own the PROPOSED-vs-measured judgement).
    """

    tiers: list[TierResult]
    rpo_seconds: float | None = None
    rto_seconds: float | None = None

    @property
    def topology_rto_seconds(self) -> float | None:
        for t in self.tiers:
            if t.topology_rto_seconds is not None:
                return t.topology_rto_seconds
        return None

    @property
    def passed(self) -> bool:
        """End-to-end PASS iff EVERY expected tier was seen AND passed.

        A missing tier (no lines at all) rolls up to FAIL — a DR drill that never
        ran a tier has not proven that tier, so it cannot be reported green.
        """
        seen = {t.tier for t in self.tiers}
        if not set(TIER_TAGS).issubset(seen):
            return False
        return all(t.status == "PASS" for t in self.tiers if t.tier in TIER_TAGS)

    @property
    def passed_count(self) -> int:
        return sum(1 for t in self.tiers if t.tier in TIER_TAGS and t.status == "PASS")

    def composite_line(self) -> str:
        """The single end-to-end ``DRILL full_platform ...`` line for the doc."""
        result = "PASS" if self.passed else "FAIL"
        rpo = _fmt(self.rpo_seconds)
        rto = _fmt(self.rto_seconds)
        topo = _fmt(self.topology_rto_seconds)
        return (
            f"{FULL_TAG} tiers={len(TIER_TAGS)} passed={self.passed_count} "
            f"rpo_s={rpo} rto_s={rto} topology_rto_s={topo} result={result}"
        )

    def render_table(self) -> str:
        """Render the evidence results table (Markdown) the G-REL doc embeds."""
        rows = [
            "| Tier | Assertions | Topology-RTO (s) | Result |",
            "|---|---|---|---|",
        ]
        for tier in TIER_TAGS:
            t = next((x for x in self.tiers if x.tier == tier), None)
            if t is None:
                rows.append(f"| {TIER_LABELS[tier]} | (no output) | — | **MISSING** |")
                continue
            asserts = ", ".join(f"{k}={v}" for k, v in t.assertions.items()) or "—"
            topo = _fmt(t.topology_rto_seconds) if t.topology_rto_seconds is not None else "—"
            rows.append(f"| {t.label} | {asserts} | {topo} | **{t.status}** |")
        return "\n".join(rows)


def _fmt(value: float | None) -> str:
    return f"{value:.3f}" if value is not None else "n/a"


def parse(lines: list[str]) -> DrillEvidence:
    """Parse a flat list of stdout lines into the aggregated evidence.

    Only ``DRILL ...`` lines are considered; everything else (echo banners, tier
    log noise) is ignored. The order of first appearance is preserved so the table
    reads in chain order when the tiers ran in order.
    """
    tiers: dict[str, TierResult] = {}

    def tier_of(name: str) -> TierResult:
        return tiers.setdefault(name, TierResult(tier=name))

    for raw in lines:
        line = raw.strip()
        if not line.startswith("DRILL "):
            continue

        metric = _NEO4J_METRIC_RE.match(line)
        if metric:
            t = tier_of("neo4j_rebuild")
            t.topology_rto_seconds = float(metric.group("seconds"))
            continue

        outcome = _OUTCOME_RE.match(line)
        if outcome:
            t = tier_of(outcome.group("tier"))
            t.saw_outcome = True
            t.passed = outcome.group("outcome") == "PASS"
            if outcome.group("failed"):
                t.failed_assertion = outcome.group("failed")
            continue

        # The pcap composite (sampled=.. result=..) and the neo4j metric line both
        # carry `result=`/`=`; they are not per-assertion PASS/FAIL lines, so guard
        # against treating `sha256=MATCH` etc. as an assertion. Only single-token
        # ``<name>=PASS|FAIL`` lines are per-assertion rows.
        assertion = _ASSERTION_RE.match(line)
        if assertion and "OUTCOME" not in line:
            t = tier_of(assertion.group("tier"))
            t.assertions.setdefault(assertion.group("name"), assertion.group("status"))

    ordered = [tiers[name] for name in TIER_TAGS if name in tiers]
    # any tier that appeared out-of-order or unexpectedly is appended after.
    ordered += [t for n, t in tiers.items() if n not in TIER_TAGS]
    return DrillEvidence(tiers=ordered)


def collect(text: str) -> DrillEvidence:
    """Parse a captured stdout blob (the chained tiers' combined output)."""
    return parse(text.splitlines())


def write_report(evidence: DrillEvidence, *, stream: TextIO | None = None) -> None:
    """Emit the human report + the composite line to ``stream`` (default stdout)."""
    out = stream if stream is not None else sys.stdout
    print("== Full-platform DR drill — aggregated evidence ==", file=out)
    print(evidence.render_table(), file=out)
    print("", file=out)
    print(evidence.composite_line(), file=out, flush=True)
