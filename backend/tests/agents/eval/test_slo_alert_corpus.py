"""SLO/alert-correctness eval corpus — coverage matrix + shape + floor bite (W5-T1).

This is the deterministic, byte-stable proof corpus the W5-T3 gate cites for
**G-OBS** (PRODUCTION.md §6 / §11 §385): it CONSOLIDATES the W3-T3 alert-as-test
cases and the W3-T5 fault-injection MTTD cases (``deploy/observability/*.test.yaml``)
into a **coverage matrix** over the authoritative §6 alert set and asserts three
properties that a green-at-setup corpus could otherwise fake:

* **Coverage (Requirement 1).** Every alert declared in
  ``slo-burn-rate.alerts.yaml`` — the §6 recording-rule + burn-rate alert set — has
  BOTH a firing case (``exp_alerts`` non-empty) AND a healthy case (``exp_alerts``
  empty) somewhere in the promtool corpus. The matrix FAILS (lists the gap) if any
  alert is uncovered, so a new alert without tests, or a deleted firing/healthy case,
  breaks CI.
* **Corpus shape (Requirement 3).** Every alert *class* (the ``slo`` label) has ≥1
  positive AND ≥1 negative case, so neither a fire-always analyzer (no negatives) nor
  a never-fire analyzer (no positives) could pass the corpus.
* **Fire-within-window (Requirement 2, the floor).** Every firing case's
  ``eval_time`` clears the alert's ``for:`` hold — the firing assertion is bound to a
  window, not a t0 fire (this module asserts that encoding deterministically). The
  *bite* that the window is not vacuous (a delayed breach MUST fail the firing
  assertion) can only be proven against the real Prometheus evaluator, so it lives in
  ``deploy/observability/run-slo-corpus-perturbation-bite.sh``, wired as a BLOCKING
  step in the CI ``observability`` job (a scripted-YAML parse cannot validate PromQL
  semantics — the honest floor-bite runs the real evaluator, not a re-implementation).
  ``test_perturbation_bite_is_wired_into_ci`` guards that wiring here. See the module
  docstrings of ``slo-corpus-perturbation.test.yaml`` and the bite script.

Grounding: all nine §6 SLI rows now have backing Prometheus series. The three
reconciliation-job rows (§6 rows 5/6/9) use the bounded reconciliation label and
are covered by the real-promtool firing, quiet, absent, stale, and mutation
fixtures in ``deploy/observability/reconciliation.alerts.test.yaml``.

No external services, no wall-clock: the corpus is synthetic compressed-minute series
parsed from committed YAML, so this runs deterministically in the backend pytest job
on every PR.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.eval

# ---------------------------------------------------------------------------
# Repository-relative paths (this file: backend/tests/agents/eval/…).
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[4]
_OBS = _REPO_ROOT / "deploy" / "observability"
_ALERTS_FILE = _OBS / "slo-burn-rate.alerts.yaml"
_RECORDING_FILE = _OBS / "slo-recording.rules.yaml"
_HELM_ALERTS_FILE = (
    _REPO_ROOT / "deploy/kubernetes/netops/templates/slo-burn-rate-prometheusrule.yaml"
)
_PERTURBATION_SCRIPT = _OBS / "run-slo-corpus-perturbation-bite.sh"
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "platform-gates.yml"


def test_reconciliation_checked_alerts_equal_deployed_helm_source() -> None:
    """The promtool-checked reconciliation group is exactly what Helm deploys."""
    checked = yaml.safe_load(_ALERTS_FILE.read_text(encoding="utf-8"))
    template_yaml = "spec:" + _HELM_ALERTS_FILE.read_text(encoding="utf-8").split("\nspec:", 1)[1]
    rendered_source = "\n".join(
        line for line in template_yaml.splitlines() if not line.lstrip().startswith("{{")
    )
    deployed = yaml.safe_load(rendered_source)
    checked_group = next(
        group for group in checked["groups"] if group["name"] == "netops-slo-reconciliation-burn"
    )
    deployed_group = next(
        group
        for group in deployed["spec"]["groups"]
        if group["name"] == "netops-slo-reconciliation-burn"
    )
    assert deployed_group == checked_group


#: The promtool alert-as-test corpus consolidated into the coverage matrix: the
#: W3-T3 firing/healthy cases, the W3-T5 fault-injection MTTD cases, the W4-T7
#: compressed soak, and the W5-T1 perturbation anchor. Recording-rule tests
#: (``slo-recording.rules.test.yaml``) carry no ``alert_rule_test`` and are excluded.
_CORPUS_FILES = (
    _OBS / "slo-burn-rate.alerts.test.yaml",
    _OBS / "slo-mttd.faultinjection.test.yaml",
    _OBS / "slo-compressed-soak.test.yaml",
    _OBS / "slo-corpus-perturbation.test.yaml",
    _OBS / "reconciliation.alerts.test.yaml",
)

# ---------------------------------------------------------------------------
# PRODUCTION.md §6 grounding (ADR-0046 §1). All nine §6 SLI rows are backed.
# ---------------------------------------------------------------------------
#: §6-row → ``slo`` label for all backed rows (the alert classes).
_SECTION6_BACKED_SLO_LABELS = frozenset(
    {
        "api_availability",  # §6 row 1
        "api_read_latency",  # §6 row 2
        "agent_first_token_latency",  # §6 row 3
        "discovery_success",  # §6 row 4
        "config_backup_completeness",  # §6 row 5
        "change_request_audit_completeness",  # §6 row 6
        "topology_projection_lag",  # §6 row 7
        "audit_siem_export_lag",  # §6 row 8
        "reasoning_trace_persistence",  # §6 row 9
    }
)

#: The seven ``record:`` SLI series names (ADR-0046 §1, one per backed §6 row; API
#: read latency contributes two — p95 and p99). A renamed/added/dropped rule bites.
_EXPECTED_RECORDING_RULES = frozenset(
    {
        "slo:netops_api_availability:ratio_rate5m",
        "slo:netops_api_read_latency:p95_5m",
        "slo:netops_api_read_latency:p99_5m",
        "slo:netops_agent_first_token_latency:p95_5m",
        "slo:netops_discovery_success:ratio_rate_run",
        "slo:netops_topology_projection_lag:seconds",
        "slo:netops_audit_siem_export_lag:seconds",
        "slo:netops_reconciliation:inconsistencies",
        "slo:netops_reconciliation:query_healthy",
        "slo:netops_reconciliation:age_seconds",
    }
)


# ---------------------------------------------------------------------------
# Parsing helpers (pure — no evaluation, just structural reads of the YAML).
# ---------------------------------------------------------------------------
def _load_yaml(path: Path) -> dict[str, Any]:
    assert path.exists(), f"expected observability file is missing: {path}"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} did not parse to a mapping"
    return data


def _duration_to_minutes(value: str) -> float:
    """Parse a promtool duration (``2m`` / ``90s`` / ``6h``) to minutes."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h)", value.strip())
    assert match is not None, f"unparseable duration: {value!r}"
    magnitude = float(match.group(1))
    unit = match.group(2)
    factor = {"ms": 1.0 / 60_000.0, "s": 1.0 / 60.0, "m": 1.0, "h": 60.0}[unit]
    return magnitude * factor


def _declared_alerts() -> dict[str, dict[str, Any]]:
    """Every alert in ``slo-burn-rate.alerts.yaml`` → its ``for`` hold + labels."""
    doc = _load_yaml(_ALERTS_FILE)
    alerts: dict[str, dict[str, Any]] = {}
    for group in doc["groups"]:
        for rule in group.get("rules", []):
            if "alert" not in rule:
                continue
            labels = rule.get("labels", {})
            alerts[rule["alert"]] = {
                "for": rule.get("for"),
                "slo": labels.get("slo"),
                "severity": labels.get("severity"),
                "tier": labels.get("tier"),
                "group": group["name"],
            }
    assert alerts, "no alerts parsed from the burn-rate rules file"
    return alerts


def _recording_rule_names() -> set[str]:
    doc = _load_yaml(_RECORDING_FILE)
    names: set[str] = set()
    for group in doc["groups"]:
        for rule in group.get("rules", []):
            if "record" in rule:
                names.add(rule["record"])
    return names


def _corpus_cases() -> tuple[dict[str, list[tuple[str, str]]], dict[str, list[tuple[str, str]]]]:
    """Return ``(firing, healthy)`` maps: alertname → list of ``(file, eval_time)``.

    A case is *firing* when its ``exp_alerts`` is non-empty (the alert must fire) and
    *healthy* when ``exp_alerts`` is empty (the alert must stay silent).
    """
    firing: dict[str, list[tuple[str, str]]] = defaultdict(list)
    healthy: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for path in _CORPUS_FILES:
        doc = _load_yaml(path)
        for test in doc.get("tests", []):
            for case in test.get("alert_rule_test", []):
                name = case["alertname"]
                eval_time = str(case.get("eval_time"))
                bucket = firing if (case.get("exp_alerts") or []) else healthy
                bucket[name].append((path.name, eval_time))
    return firing, healthy


def _uncovered_alerts(
    declared: dict[str, dict[str, Any]],
    firing: dict[str, list[tuple[str, str]]],
    healthy: dict[str, list[tuple[str, str]]],
) -> list[tuple[str, str]]:
    """Return ``(alert, missing_kind)`` for any alert lacking a firing or healthy case.

    Pure so the coverage assertion AND its own anti-vacuous self-bite share one
    implementation (``test_coverage_checker_is_not_vacuous``).
    """
    gaps: list[tuple[str, str]] = []
    for alert in sorted(declared):
        if not firing.get(alert):
            gaps.append((alert, "firing"))
        if not healthy.get(alert):
            gaps.append((alert, "healthy"))
    return gaps


# ===========================================================================
# Requirement 1 — every §6 alert covered (firing + healthy); matrix fails on a gap.
# ===========================================================================
def test_every_section6_alert_has_a_firing_and_a_healthy_case() -> None:
    """Coverage matrix: no §6 alert may be uncovered (the assertion BITES on a gap)."""
    declared = _declared_alerts()
    firing, healthy = _corpus_cases()

    gaps = _uncovered_alerts(declared, firing, healthy)
    matrix = "\n".join(
        f"  {alert:<40} firing={len(firing.get(alert, [])):<2} "
        f"healthy={len(healthy.get(alert, [])):<2}"
        for alert in sorted(declared)
    )
    assert not gaps, (
        "SLO alert coverage matrix has UNCOVERED alerts "
        f"(each §6 alert needs a firing AND a healthy case):\n{gaps}\n\nmatrix:\n{matrix}"
    )
    # Sanity: the corpus references no alert that is not declared in the rules file
    # (a stale test alertname would silently "cover" nothing real).
    referenced = set(firing) | set(healthy)
    unknown = referenced - set(declared)
    assert not unknown, f"corpus references undeclared alertnames (rule drift?): {sorted(unknown)}"


def test_coverage_matrix_is_grounded_in_production_section6() -> None:
    """The declared alert classes map 1:1 onto all nine backed §6 SLI rows.

    Bites on drift in either direction: a new alert class not tied to a §6 row, or a
    dropped §6 SLO. The seven recording-rule SLI series are asserted exactly, and the
    three reconciliation rows share the bounded aggregate recording series.
    """
    declared = _declared_alerts()
    classes = {meta["slo"] for meta in declared.values()}
    assert classes == set(_SECTION6_BACKED_SLO_LABELS), (
        "declared alert classes drifted from the nine backed PRODUCTION.md §6 SLI rows: "
        f"{sorted(classes)} != {sorted(_SECTION6_BACKED_SLO_LABELS)}"
    )

    assert _recording_rule_names() == set(_EXPECTED_RECORDING_RULES), (
        "recording-rule SLI series drifted from the ADR-0046 §1 set: "
        f"{sorted(_recording_rule_names())}"
    )


# ===========================================================================
# Requirement 3 — corpus-shape guards: every class has ≥1 positive AND ≥1 negative.
# ===========================================================================
def test_every_alert_class_has_a_positive_and_a_negative() -> None:
    """A fire-always (no negatives) or never-fire (no positives) analyzer cannot pass."""
    declared = _declared_alerts()
    firing, healthy = _corpus_cases()

    positives: dict[str, int] = defaultdict(int)
    negatives: dict[str, int] = defaultdict(int)
    for alert, meta in declared.items():
        slo = meta["slo"]
        positives[slo] += len(firing.get(alert, []))
        negatives[slo] += len(healthy.get(alert, []))

    for slo in _SECTION6_BACKED_SLO_LABELS:
        assert positives[slo] >= 1, f"alert class {slo!r} has no POSITIVE (firing) case"
        assert negatives[slo] >= 1, f"alert class {slo!r} has no NEGATIVE (healthy) case"


# ===========================================================================
# Requirement 2 — every firing case is bound to a WINDOW (eval clears the for hold).
# ===========================================================================
def test_every_firing_case_clears_its_for_window() -> None:
    """Each firing assertion's ``eval_time`` ≥ the alert's ``for:`` hold.

    An alert can only be *firing* after its ``for:`` hold elapses from the breach
    onset (t0 in the corpus). A firing case whose ``eval_time`` is below the hold could
    never fire — that would be a broken assertion. This encodes the expected
    fire-window for every firing case; the non-vacuousness of the window (a delayed
    breach must FAIL) is proven by the perturbation bite.
    """
    declared = _declared_alerts()
    firing, _ = _corpus_cases()

    for alert, cases in firing.items():
        hold = declared[alert]["for"]
        assert hold is not None, f"alert {alert} has no for: hold"
        hold_min = _duration_to_minutes(str(hold))
        for file_name, eval_time in cases:
            eval_min = _duration_to_minutes(eval_time)
            assert eval_min >= hold_min, (
                f"{alert} firing case in {file_name} evaluates at {eval_time} "
                f"(< its for:{hold} hold) — it could never fire (broken window)"
            )


# ===========================================================================
# Anti-vacuous self-bite — the coverage checker itself must catch a planted gap.
# ===========================================================================
def test_coverage_checker_is_not_vacuous() -> None:
    """The matrix checker reports a synthetic uncovered alert (it is not a no-op)."""
    declared = {
        "AlertFullyCovered": {"for": "2m", "slo": "x"},
        "AlertMissingHealthy": {"for": "2m", "slo": "x"},
        "AlertMissingFiring": {"for": "2m", "slo": "x"},
    }
    firing = {"AlertFullyCovered": [("f", "9m")], "AlertMissingHealthy": [("f", "9m")]}
    healthy = {"AlertFullyCovered": [("f", "9m")], "AlertMissingFiring": [("f", "9m")]}
    gaps = _uncovered_alerts(declared, firing, healthy)  # type: ignore[arg-type]
    assert ("AlertMissingHealthy", "healthy") in gaps
    assert ("AlertMissingFiring", "firing") in gaps
    assert ("AlertFullyCovered", "firing") not in gaps
    assert ("AlertFullyCovered", "healthy") not in gaps


# ===========================================================================
# Perturbation floor-bite — wired in CI, and exercised here when promtool is present.
# ===========================================================================
def test_perturbation_bite_is_wired_into_ci() -> None:
    """The perturbation-bite script + corpus exist and are a blocking CI step.

    Always-on guard (no promtool needed): the fire-within-window floor-bite must be
    referenced by the CI ``observability`` job, so removing the wiring — turning the
    floor vacuous in practice — breaks this test.
    """
    assert _PERTURBATION_SCRIPT.exists(), "perturbation bite script is missing"
    assert (_OBS / "slo-corpus-perturbation.test.yaml").exists(), "perturbation corpus is missing"
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    observability_steps = workflow["jobs"]["observability"]["steps"]
    bite_steps = [
        step
        for step in observability_steps
        if "run-slo-corpus-perturbation-bite.sh" in str(step.get("run", ""))
    ]
    assert len(bite_steps) == 1, (
        "the SLO-corpus perturbation bite is not wired as a `run:` step of the "
        "`observability` job in .github/workflows/platform-gates.yml — a bare mention in a "
        "comment or a step under another job would not run the floor as a blocking PR gate"
    )
    assert not bite_steps[0].get("continue-on-error", False), (
        "the SLO-corpus perturbation bite step is marked continue-on-error — the floor "
        "would be advisory, not a blocking PR gate"
    )
