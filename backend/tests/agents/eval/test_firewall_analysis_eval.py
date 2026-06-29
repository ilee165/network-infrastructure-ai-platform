"""Firewall-policy-analysis precision/recall eval gate (P2 W5-T1).

This is the **deterministic, CI-blocking** proof that the W3 Security-Agent
analysis service (:mod:`app.engines.security.firewall`) detects shadowed /
redundant / overly-permissive rules and posture violations *correctly* and
*reproducibly*, scored against the held-out labelled corpus in
:mod:`tests.agents.eval.firewall_corpus`.

Which layer proves what
-----------------------
There is exactly ONE layer here, and that is by design (ADR-0037 §2). The scored
path is **rule-based, not LLM judgment**: every finding is a set/predicate over
already-normalized fields, so precision/recall is fully reproducible and there is
**no real-LLM gate for this task** — unlike the routing (M3) / RAG / injection-ED6
evals, nothing in the scored path needs a model, so a manual real-model gate
would prove nothing the deterministic suite does not. The Security Agent only
*narrates* these findings; its narration is out of scope here (it is exercised by
the W3 agent tests and the W5-T2 routing re-run). Live analysis against real
firewall hardware is **deferred-accepted** (no lab hardware — same posture as
M4/M5/P1); the corpus is the fixture-grounded proof of the analysis logic.

What is scored
--------------
For each :class:`~tests.agents.eval.firewall_corpus.LabelledCase` the suite runs BOTH
deterministic entry points over the whole policy at once —
``analyze_firewall_rules`` (shadowed / redundant / overly-permissive) and
``analyze_security_posture`` (posture) — collapses the produced findings to their
``(category, rule_name)`` identity, and compares against the ground-truth labels.
A produced finding not in the labels is a **false positive**; a labelled finding
not produced is a **false negative**. Precision/recall is then computed per
finding class and asserted against the floors below.

Thresholds (Requirement 2 / Exit criterion 2) — stated and justified
--------------------------------------------------------------------
``PRECISION_FLOOR = RECALL_FLOOR = 1.0`` for every class. This is **not** a gamed
floor tuned down until green; it is the only honest floor for a *deterministic*
analysis over a *labelled* corpus:

* The service has no inherent variance (ADR-0037 §2): a rule-based predicate over
  normalized fields returns the same findings every run. Any precision below 1.0
  means it flagged a clean negative (a false alarm that would draft a spurious
  ChangeRequest); any recall below 1.0 means it MISSED a known shadowed /
  redundant / overly-permissive / posture issue (a real security gap). Neither is
  acceptable noise — both are regressions the gate exists to bite on.
* Clean-negative cases in the corpus keep the precision floor honest: a
  flag-everything service cannot reach precision 1.0 (Requirement 3).

The floors are therefore set at the maximum and the suite **fails below them**
(bite verified by ``test_threshold_bites_on_a_missed_finding`` /
``test_threshold_bites_on_a_false_positive``, which perturb the *scored input* and
assert the same threshold logic drops below floor).

No-flake discipline (Requirement 5)
-----------------------------------
The scored path touches no database, network, clock, or RNG — it is a pure
function over frozen corpus fixtures — so it cannot flake on CI ordinals. The
``NullPool``-SQLite pin (W6 flaky-concurrency lesson) is honoured where it would
apply: this suite simply has no DB engine to pin, and ``test_determinism_*``
asserts byte-for-byte stable scores across repeated runs to lock that in.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.engines.security.firewall import (
    analyze_firewall_rules,
    analyze_security_posture,
)
from app.schemas.security import FindingCategory, SecurityFinding
from tests.agents.eval.firewall_corpus import (
    CORPUS,
    ExpectedFinding,
    LabelledCase,
    expected_by_class,
)

pytestmark = pytest.mark.eval

#: Per-class precision/recall floor. 1.0 is the justified maximum for a
#: deterministic analysis over a labelled corpus (see module docstring); the
#: suite FAILS below it.
PRECISION_FLOOR = 1.0
RECALL_FLOOR = 1.0

#: The four finding classes the corpus scores. Posture findings can fire from
#: either entry point; every class must carry at least one ground-truth positive
#: so the floors are meaningful (asserted by ``test_every_class_has_positives``).
SCORED_CLASSES: tuple[FindingCategory, ...] = (
    FindingCategory.SHADOWED,
    FindingCategory.REDUNDANT,
    FindingCategory.OVERLY_PERMISSIVE,
    FindingCategory.POSTURE,
)


def _run_service(case: LabelledCase) -> list[SecurityFinding]:
    """Run BOTH deterministic entry points over the whole policy (the scored path).

    This is the *real* W3 service — no mock, no LLM, no DB. The two entry points
    are unioned exactly as the Security Agent narrates them together.
    """
    return [
        *analyze_firewall_rules(case.rules),
        *analyze_security_posture(case.rules, case.acls),
    ]


def _produced_labels(findings: list[SecurityFinding]) -> set[ExpectedFinding]:
    """Collapse produced findings to their ACE-precise ``(category, rule_name, position)`` set.

    The produced identity carries ``rule_position`` (the engine populates it from a
    firewall ``position`` or an ACL ``sequence``), so a produced finding pins WHICH
    entry was flagged. Two findings on the same rule+category+position (e.g. an
    entry-point overlap) collapse to one label — the corpus scores *whether* a rule
    is correctly classified, not how many narration rows it yields.

    Matching against the ground truth is position-aware but back-compatible: an
    expected label with ``rule_position=None`` matches on ``(category, rule_name)``
    alone (every existing firewall-rule label), while a positional expected label
    requires the produced position to match (see :func:`_matches`).
    """
    return {
        ExpectedFinding(f.category, f.rule_name, rule_position=f.rule_position) for f in findings
    }


def _matches(expected: ExpectedFinding, produced: ExpectedFinding) -> bool:
    """True iff *produced* satisfies the *expected* label (position optional).

    Category and rule name must always match. The position is an OPTIONAL
    discriminator: an expected label with ``rule_position=None`` matches any
    produced position (the legacy ``(category, rule_name)`` identity), while a
    positional expected label requires the produced finding to carry exactly that
    position — so flagging the wrong ACE among entries sharing a ``rule_name`` is
    NOT a true positive.
    """
    if expected.category is not produced.category or expected.rule_name != produced.rule_name:
        return False
    return expected.rule_position is None or expected.rule_position == produced.rule_position


@dataclass(frozen=True)
class ClassScore:
    """Precision/recall and the raw TP/FP/FN counts for one finding class."""

    category: FindingCategory
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        # No positives produced AND none expected -> vacuously perfect (1.0): the
        # service correctly produced nothing to be wrong about.
        denom = self.true_positives + self.false_positives
        return 1.0 if denom == 0 else self.true_positives / denom

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return 1.0 if denom == 0 else self.true_positives / denom


def score_corpus(corpus: tuple[LabelledCase, ...]) -> dict[FindingCategory, ClassScore]:
    """Score the deterministic service over *corpus*, per finding class.

    Pure and side-effect-free: identical input -> identical scores (the property
    ``test_determinism_two_runs_identical`` locks in).
    """
    tp: dict[FindingCategory, int] = {c: 0 for c in SCORED_CLASSES}
    fp: dict[FindingCategory, int] = {c: 0 for c in SCORED_CLASSES}
    fn: dict[FindingCategory, int] = {c: 0 for c in SCORED_CLASSES}

    for case in corpus:
        produced = _produced_labels(_run_service(case))
        expected = set(case.expected)
        # Position-aware matching (NOT raw set intersection): an expected label with
        # rule_position=None matches on (category, rule_name); a positional one also
        # pins the ACE. A produced finding is a TP iff it satisfies some expected
        # label; else an FP. An expected label is recalled iff some produced finding
        # satisfies it; else an FN. So flagging the wrong ACE is BOTH an FP (the
        # produced label matches no expected) and an FN (the positional expected
        # label is unsatisfied) — the gate drops below floor.
        for p in produced:
            if any(_matches(e, p) for e in expected):
                tp[p.category] += 1
            else:
                fp[p.category] += 1
        for e in expected:
            if not any(_matches(e, p) for p in produced):
                fn[e.category] += 1

    return {
        c: ClassScore(
            category=c,
            true_positives=tp[c],
            false_positives=fp[c],
            false_negatives=fn[c],
        )
        for c in SCORED_CLASSES
    }


# ---------------------------------------------------------------------------
# Corpus shape guards (the floors are only meaningful with real labels behind
# them — Requirement 3, no empty / negatives-only class).
# ---------------------------------------------------------------------------


class TestCorpusShape:
    def test_every_class_has_positives(self) -> None:
        """Each scored class carries >=1 ground-truth positive (floors are real)."""
        counts = expected_by_class()
        for category in SCORED_CLASSES:
            assert counts[category] >= 1, f"corpus has no labelled positive for {category.value}"

    def test_corpus_has_clean_negatives(self) -> None:
        """At least one case expects ZERO findings (precision guard, Requirement 3)."""
        clean = [c for c in CORPUS if not c.expected]
        assert clean, "corpus needs >=1 clean-negative case so flag-everything fails precision"


# ---------------------------------------------------------------------------
# The gate: precision/recall per class >= floor (Exit criterion 2).
# ---------------------------------------------------------------------------


class TestPrecisionRecallThresholds:
    def test_precision_at_or_above_floor_per_class(self) -> None:
        scores = score_corpus(CORPUS)
        for category in SCORED_CLASSES:
            s = scores[category]
            assert s.precision >= PRECISION_FLOOR, (
                f"{category.value} precision {s.precision:.3f} < floor {PRECISION_FLOOR} "
                f"(tp={s.true_positives} fp={s.false_positives}) — the service flagged a "
                "clean negative (false positive)"
            )

    def test_recall_at_or_above_floor_per_class(self) -> None:
        scores = score_corpus(CORPUS)
        for category in SCORED_CLASSES:
            s = scores[category]
            assert s.recall >= RECALL_FLOOR, (
                f"{category.value} recall {s.recall:.3f} < floor {RECALL_FLOOR} "
                f"(tp={s.true_positives} fn={s.false_negatives}) — the service missed a "
                "labelled finding (false negative)"
            )

    def test_no_false_positives_or_negatives_overall(self) -> None:
        """Whole-corpus sanity: deterministic service is exact against the labels."""
        scores = score_corpus(CORPUS)
        assert all(s.false_positives == 0 for s in scores.values())
        assert all(s.false_negatives == 0 for s in scores.values())


# ---------------------------------------------------------------------------
# Threshold BITE: prove the gate fails below floor by perturbing the scored
# input, NOT by mutating the floor (Exit criterion 3, Risk "threshold gaming").
# ---------------------------------------------------------------------------


class TestThresholdBite:
    def test_threshold_bites_on_a_missed_finding(self) -> None:
        """Disable a labelled overly-permissive rule -> recall drops below floor.

        Perturbation is on the *corpus input*: disabling the any->any rule means
        the service no longer flags it, so the still-labelled finding becomes a
        false negative. The SAME threshold logic that gates CI must now fail — if
        it did not, the gate would be a no-op report.
        """
        case = next(c for c in CORPUS if c.name == "panos-overly-permissive-mixed")
        # Disable the labelled any->any rule so the service emits no finding for it.
        perturbed_rules = tuple(
            r.model_copy(update={"enabled": False}) if r.name == "permit-any-any" else r
            for r in case.rules
        )
        perturbed = LabelledCase(
            name=case.name,
            rules=perturbed_rules,
            acls=case.acls,
            expected=case.expected,  # label retained -> the missed flag is an FN
        )
        scores = score_corpus((perturbed,))
        op = scores[FindingCategory.OVERLY_PERMISSIVE]
        assert op.false_negatives >= 1
        assert op.recall < RECALL_FLOOR, "perturbed corpus must drop recall below floor"

    def test_threshold_bites_on_a_false_positive(self) -> None:
        """Drop a label -> the (still-produced) finding becomes a false positive.

        Same threshold logic, precision side: removing a true label from a clean
        case while the service still produces the finding turns it into an FP, and
        precision must drop below the floor.
        """
        case = next(c for c in CORPUS if c.name == "cisco-acl-permit-any-any-posture")
        # Same input, but pretend the any->any ACE is NOT a labelled finding.
        perturbed = LabelledCase(
            name=case.name,
            rules=case.rules,
            acls=case.acls,
            expected=frozenset(),  # service still flags OUTSIDE_IN -> now an FP
        )
        scores = score_corpus((perturbed,))
        posture = scores[FindingCategory.POSTURE]
        assert posture.false_positives >= 1
        assert posture.precision < PRECISION_FLOOR, "FP must drop precision below floor"


# ---------------------------------------------------------------------------
# Determinism / reproducibility (Exit criterion 4).
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_two_runs_identical(self) -> None:
        """Two scoring runs over the corpus are byte-for-byte identical."""
        first = score_corpus(CORPUS)
        second = score_corpus(CORPUS)
        assert first == second

    def test_findings_order_stable(self) -> None:
        """Re-running the service over a case returns identical ordered findings."""
        for case in CORPUS:
            assert _run_service(case) == _run_service(case)


# ---------------------------------------------------------------------------
# Secret-free corpus + findings (Requirement 4 / Exit criterion 4).
# ---------------------------------------------------------------------------


class TestSecretFree:
    #: Substrings that would indicate a credential / secret leaked into a fixture
    #: or a produced finding. The corpus is config metadata only (ADR-0034 §2), so
    #: none of these must appear anywhere in the evidence the service emits.
    _SECRET_MARKERS = (
        "password",
        "secret",
        "community",
        "snmp-server",
        "pre-shared",
        "psk",
        "private-key",
        "-----begin",
        "bearer ",
        "api_key",
        "apikey",
    )

    def test_no_finding_evidence_carries_a_secret(self) -> None:
        """Every produced finding's evidence is secret-free (ADR-0033 §3)."""
        for case in CORPUS:
            for finding in _run_service(case):
                blob = " ".join(
                    [
                        finding.rule_name,
                        finding.rationale,
                        finding.suggested_remediation,
                        repr(finding.evidence),
                    ]
                ).casefold()
                for marker in self._SECRET_MARKERS:
                    assert marker not in blob, (
                        f"finding on '{finding.rule_name}' in case '{case.name}' "
                        f"carries a secret-like token: {marker!r}"
                    )

    def test_corpus_fixtures_carry_no_secret_field(self) -> None:
        """The corpus inputs themselves are secret-free config metadata.

        Scans BOTH ``case.rules`` AND ``case.acls`` — the ACL rows feed
        ``analyze_security_posture`` (``_run_service``) and so are part of the
        scored input; a secret leaking through an ACL fixture would be just as real
        as one in a firewall rule, so both are asserted.
        """
        for case in CORPUS:
            for rule in case.rules:
                dumped = repr(rule.model_dump()).casefold()
                for marker in self._SECRET_MARKERS:
                    assert marker not in dumped, (
                        f"corpus rule '{rule.name}' in '{case.name}' carries {marker!r}"
                    )
            for acl in case.acls:
                dumped = repr(acl.model_dump()).casefold()
                for marker in self._SECRET_MARKERS:
                    assert marker not in dumped, (
                        f"corpus ACL '{acl.acl_name}' in '{case.name}' carries {marker!r}"
                    )
