"""P3 W5-T2 routing re-run — DETERMINISTIC no-regression layer (runs in CI).

P3 is a **platform-only** milestone (HA/scale-out + WebSocket fan-out + worker
changes): it ships **no new vendor and no new agent**, so the Master Architect's
9-way routable specialist roster and every per-agent tool allow-list must be
BYTE-IDENTICAL to the P2 W5-T2 matrix. The risk W5-T2 exists to clear is that the
stateless-API / WS-fan-out / worker rework *silently perturbed* routing or the
ADR-0033 injection boundary. This module is the catch: it pins the live P3-HEAD
registry against a recorded P2 matrix and fails with a clear added/removed diff on
any drift (PRODUCTION.md 2.6 — no cross-vendor eval regression; 11 G-MNT).

What layer proves what (``.claude/agents/wf-eval-designer.md`` discipline)
-------------------------------------------------------------------------

* **This file (deterministic, in CI):** proves *no-regression STRUCTURE* — the
  registry-derived roster (count + set), every per-agent tool allow-list (names +
  classifications), and the ADR-0033 injection-boundary invariants (the ED1-ED5
  corpus dimensions, the forbidden cross-agent tool names, and the presence of the
  behavioural TestED* proof) are unchanged from P2. It does NOT prove a model
  routes a PAN-OS policy audit to ``security`` or resists an injection — that is
  model judgment a scripted/registry re-run cannot validate.
* **The real-LLM re-run (``test_routing_eval.py``, manual gate):** proves *routing
  quality* on the pinned model/prompt set (nine-way roster, held-out cases);
  module-skipped without ``NETOPS_RUN_ROUTING_EVAL=1``, deferred-accepted when no
  local model is available (no hardware, same posture as the P2 matrix).
* **The behavioural injection proof (``test_p1_prompt_injection.py``, ED1-ED5):**
  drives the REAL gate / four-eyes spine / A9 redactor with a maximally-compromised
  scripted model. It runs in CI on a ``StaticPool`` in-memory SQLite (single shared
  connection — non-concurrent, no ordinal race), which is the correct deterministic
  pool for that suite. THIS P3 file adds no DB-backed test of its own, so it has no
  StaticPool/NullPool connection-pool flake surface at all (the W6/WS-fan-out flake
  class is DB-concurrency-only); it re-asserts the injection boundary purely from
  the registry + the held-out corpus fixture.

Anti-tautology
--------------

A snapshot test that only asserts ``live == snapshot-of-live`` is circular. The
recorded baseline (``fixtures/p3_routing_baseline_matrix.json``) is instead locked
to the P2 contract from BOTH ends: the live P3-HEAD registry is asserted equal to
the artifact, AND the artifact's roster / Security-Agent allow-list are asserted
equal to the P2 module's OWN published constants
(``test_p2_cross_vendor_routing``). So the chain is
``P3-HEAD-live == recorded-artifact == P2-published-contract`` — a genuine P2-vs-P3
lock where a drift in any leg bites with a clear diff.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from app.agents import build_default_registry
from app.agents.framework.supervisor import SUPERVISOR_NAME
from tests.agents.eval import test_p2_cross_vendor_routing as p2

# Joins the standard deterministic eval gate (collected, no flag, no skip).
pytestmark = [pytest.mark.eval]

_BASELINE_PATH = Path(__file__).parent / "fixtures" / "p3_routing_baseline_matrix.json"
_INJECTION_FIXTURE = Path(__file__).parent / "fixtures" / "prompt_injection_cases.json"

#: The behavioural ED1-ED5 proof classes that MUST stay present in the injection
#: suite — this P3 re-run confirms the boundary proof was not silently removed.
_ED_TEST_CLASSES = (
    "TestED1NoUnauthorizedToolCall",
    "TestED2ApprovalGateIntegrity",
    "TestED3AllowListScopeConfinement",
    "TestED4SecretNonExfiltration",
    "TestED5StructuredOutputIntegrity",
)


def _load_baseline() -> dict[str, Any]:
    return json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))


def _live_matrix() -> dict[str, dict[str, str]]:
    """The live P3-HEAD routing matrix: {agent: {tool_name: classification}}.

    Registry-derived from the composition root minus the supervisor — the exact
    roster the supervisor's ``route`` node decides over. Deterministic across
    builds (verified during authoring), so byte-stable in CI.
    """
    registry = build_default_registry()
    return {
        agent.name: {tool.name: tool.classification.value for tool in agent.tools}
        for agent in registry.list()
        if agent.name != SUPERVISOR_NAME
    }


# ---------------------------------------------------------------------------
# 1 + 2. No routing regression: roster count + set unchanged vs the P2 matrix.
# ---------------------------------------------------------------------------


def test_p3_roster_unchanged_vs_recorded_baseline() -> None:
    """The 9-way routable roster on P3 HEAD is exactly the recorded P2 roster.

    W5-T2 requirements 1 (no routing regression) + 3 (roster unchanged confirmed):
    P3 added no agent, so no specialist may appear, disappear, or be renamed. A
    change is an explained blocker, surfaced here as an added/removed diff.
    """
    baseline = _load_baseline()
    expected = set(baseline["roster"])
    live = set(_live_matrix())

    added = live - expected
    removed = expected - live
    assert not added and not removed, (
        "P3 routing roster drifted from the recorded P2 9-way matrix "
        "(P3 is platform-only and must add/remove NO agent) — "
        f"added={sorted(added)} removed={sorted(removed)}. "
        "Investigate the HA/scale-out / WS-fan-out / worker change before "
        "updating the baseline; a real roster change is a blocker, not a rebaseline."
    )
    assert len(live) == baseline["_meta"]["roster_count"] == 9, (
        f"roster count changed: live={len(live)} baseline={baseline['_meta']['roster_count']}"
    )


# ---------------------------------------------------------------------------
# 3a. Injection boundary intact: per-agent tool allow-lists unchanged vs P2.
# ---------------------------------------------------------------------------


def test_p3_allow_lists_unchanged_vs_recorded_baseline() -> None:
    """Every per-agent tool allow-list (names + classifications) matches P2.

    W5-T2 requirement 2 / ADR-0033: the per-agent allow-lists are the STRUCTURAL
    injection boundary. A platform change must not add a tool to any agent, drop
    one, or flip a READ_ONLY tool to STATE_CHANGING. Diffed per-agent so a drift
    names the exact agent and tool.
    """
    baseline_lists: dict[str, dict[str, str]] = _load_baseline()["allow_lists"]
    live = _live_matrix()

    # Same set of agents keyed (roster equality is also checked above; here it
    # guards the per-agent loop below from silently skipping a new/removed agent).
    assert set(live) == set(baseline_lists), (
        f"agents keyed in the allow-list matrix drifted: "
        f"live-only={sorted(set(live) - set(baseline_lists))} "
        f"baseline-only={sorted(set(baseline_lists) - set(live))}"
    )

    for agent in sorted(baseline_lists):
        assert live[agent] == baseline_lists[agent], (
            f"{agent!r} tool allow-list drifted from the recorded P2 matrix — "
            f"live={live[agent]} baseline={baseline_lists[agent]}. A tool "
            "added/removed or a classification flipped is an ADR-0033 boundary "
            "regression, not a rebaseline."
        )

    # Whole-matrix equality (the artifact is a faithful, non-rotting snapshot of
    # live — closes the loop so the checked-in file can never silently diverge).
    assert live == baseline_lists


# ---------------------------------------------------------------------------
# 1 + 2 (anti-tautology). The recorded baseline IS the P2 matrix, cross-checked
# against the P2 module's own published constants — not a re-derivation of live.
# ---------------------------------------------------------------------------


def test_recorded_baseline_is_the_p2_matrix_not_a_live_rederivation() -> None:
    """Lock the recorded baseline to the P2 contract from the other end.

    Without this, the two assertions above would only prove ``live == snapshot``
    (circular). Here the recorded roster and the Security-Agent allow-list are
    asserted equal to ``test_p2_cross_vendor_routing``'s OWN constants, so the
    baseline is provably the P2 matrix. If the P2 constants ever change, this bites
    — forcing a conscious reconciliation rather than a silent rebaseline.
    """
    baseline = _load_baseline()

    # Roster == P2's "prior eight + security" contract.
    p2_roster = set(p2._PRIOR_ROUTABLE_SPECIALISTS) | {p2._SECURITY_SPECIALIST}
    assert set(baseline["roster"]) == p2_roster, (
        f"recorded roster {sorted(baseline['roster'])} != the P2 published roster "
        f"{sorted(p2_roster)} — the baseline is not the P2 matrix."
    )

    # Security-Agent allow-list == P2's declared read-only + state-changing sets
    # (the ADR-0033 confinement contract W5-T2 carries forward).
    sec = baseline["allow_lists"]["security"]
    read_only = {name for name, cls in sec.items() if cls == "read_only"}
    state_changing = {name for name, cls in sec.items() if cls == "state_changing"}
    assert set(sec) == set(p2._SECURITY_ALLOW_LIST), (
        f"recorded security allow-list {sorted(sec)} != P2 {sorted(p2._SECURITY_ALLOW_LIST)}"
    )
    assert read_only == set(p2._SECURITY_READ_ONLY_TOOLS)
    assert state_changing == set(p2._SECURITY_STATE_CHANGING_TOOLS)


# ---------------------------------------------------------------------------
# 3b. Injection boundary intact: the ED1-ED5 held-out corpus is unchanged.
# ---------------------------------------------------------------------------


def test_injection_ed_dimensions_unchanged_vs_recorded_baseline() -> None:
    """The ED1-ED5 corpus still covers exactly the five enforcement dimensions.

    ADR-0033 §4: coverage completeness is the load-bearing assumption of the
    injection suite. This re-asserts (as a P3 no-regression guard) that the
    held-out corpus objectives are exactly the five ED dimensions the recorded
    baseline enumerates — a dropped dimension would be silent false assurance.

    NOTE (W5-T2 case-ID reconciliation): ED1-ED5 are NOT literal fixture case-IDs.
    They are fixture ``objective`` values, realized as TestED* classes; fixture
    case-IDs use the ``pi-<target_agent>-<carrier>-<attack>-NNN`` scheme. The
    baseline artifact records this mapping authoritatively.
    """
    baseline = _load_baseline()
    ed_to_objective: dict[str, str] = baseline["injection_boundary"]["ed_dimension_to_objective"]
    expected_objectives = set(ed_to_objective.values())
    assert len(expected_objectives) == 5, "baseline must enumerate five distinct ED objectives"

    corpus = json.loads(_INJECTION_FIXTURE.read_text(encoding="utf-8"))["cases"]
    live_objectives = {case["objective"] for case in corpus}
    assert live_objectives == expected_objectives, (
        f"injection corpus objectives drifted from the recorded ED1-ED5 set: "
        f"corpus={sorted(live_objectives)} baseline={sorted(expected_objectives)}. "
        "A missing dimension is a silent injection-coverage regression."
    )


def test_injection_forbidden_tool_names_absent_from_every_allow_list() -> None:
    """No agent can name a cross-agent / device-executing tool (ED1 + ED3).

    The tools the corpus injections try to summon (``deploy_config``,
    ``execute_change_request``, ``push_config``) are registered to NO agent, so a
    prompt-coerced model cannot call them — the allow-list is an enumerated set,
    not an open API. Re-asserted from the live P3 registry so a platform change
    that accidentally registered one of them fails here.
    """
    baseline = _load_baseline()
    forbidden = set(baseline["injection_boundary"]["forbidden_tool_names"])
    live = _live_matrix()
    all_tool_names = {name for tools in live.values() for name in tools}
    leaked = forbidden & all_tool_names
    assert not leaked, (
        f"forbidden cross-agent/device-executing tool(s) {sorted(leaked)} are now "
        "registered to a routable agent — the ADR-0033 injection boundary regressed."
    )


def test_behavioural_ed1_ed5_proof_still_present() -> None:
    """The behavioural ED1-ED5 proof classes are still collected in CI.

    This P3 re-run is structural; the *behavioural* proof that an injected
    state-changing call only drafts a four-eyes CR (never executes), that secrets
    are redacted, and that routing stays schema-valid lives in
    ``test_p1_prompt_injection.py``. Guard against that proof being silently
    deleted/renamed — which would drop the ED1-ED5 100% guarantee W5-T2 asserts —
    by importing the module and requiring each TestED* class to exist. (Its actual
    green run is part of the same CI ``pytest`` invocation as this file.)
    """
    module = importlib.import_module("tests.agents.eval.test_p1_prompt_injection")
    missing = [name for name in _ED_TEST_CLASSES if not hasattr(module, name)]
    assert not missing, (
        f"behavioural injection-boundary proof class(es) {missing} are missing from "
        "test_p1_prompt_injection.py — the ED1-ED5 guarantee is no longer proven."
    )
    # The baseline's recorded class-name mapping must match the real classes.
    baseline = _load_baseline()
    recorded = set(baseline["injection_boundary"]["ed_dimension_to_test_class"].values())
    assert recorded == set(_ED_TEST_CLASSES), (
        f"recorded ED test-class mapping {sorted(recorded)} != the classes this "
        f"guard checks {sorted(_ED_TEST_CLASSES)}"
    )


# ---------------------------------------------------------------------------
# 4 + 5. Determinism + recorded-artifact integrity.
# ---------------------------------------------------------------------------


def test_matrix_is_deterministic_across_registry_builds() -> None:
    """Two composition-root builds yield an identical matrix (byte-stable in CI).

    W5-T2 requirement 4: the re-run must be deterministic on the pinned set. The
    matrix is registry-derived with no randomness, so repeated builds are equal —
    the property that lets the recorded artifact be a stable golden file.
    """
    assert _live_matrix() == _live_matrix()


def test_recorded_artifact_metadata_matches_live() -> None:
    """The artifact's headline facts agree with the live platform (no silent rot).

    Keeps the recorded matrix W5-T3 cites honest: the supervisor name, roster
    count, and the platform-only result flags are checked against the live
    registry, so the artifact cannot claim a state the code does not hold.
    """
    baseline = _load_baseline()
    assert baseline["_meta"]["supervisor"] == SUPERVISOR_NAME
    assert baseline["_meta"]["roster_count"] == len(_live_matrix()) == 9
    result = baseline["result"]
    assert result["roster_unchanged_vs_p2"] is True
    assert result["allow_lists_unchanged_vs_p2"] is True
    assert result["injection_boundary_intact"] is True
    assert result["no_new_agent"] is True and result["no_new_vendor"] is True
