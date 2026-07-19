"""Report-engine PrometheusRule chart render guards (PR #166 F5).

deploy/observability/report-engine.alerts.yaml was promtool-validated in CI
but nothing in the chart actually DEPLOYED it to a live cluster — the SLO
recording/burn-rate rule sets had an opt-in PrometheusRule template
(observability.prometheusRule.enabled), the report-engine alerts did not.
These pin:

  * OFF by default — no PrometheusRule object renders without the flag (the
    EXPOSE-DON'T-BUNDLE default, ADR-0015 alt.1 / ADR-0046 §4).
  * ON when the SAME flag the SLO rule templates use is set — one
    PrometheusRule per report-kind alert group, carrying every alert name from
    the promtool-gated source file (single-source-of-truth lockstep).
  * helm lint stays green with the template present.

helm is the authoritative renderer; the tests skip cleanly when it is absent
(the infra CI job runs helm lint / kubeconform / kube-linter / conftest).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHART_DIR = REPO_ROOT / "deploy" / "kubernetes" / "netops"
ALERTS_FILE = REPO_ROOT / "deploy" / "observability" / "report-engine.alerts.yaml"


def _helm() -> str | None:
    return shutil.which("helm")


def _template(*extra: str, show_only: str | None = None) -> subprocess.CompletedProcess[str]:
    helm = _helm()
    assert helm is not None
    argv = [
        helm,
        "template",
        "netops",
        str(CHART_DIR),
        "--namespace",
        "netops",
        "--kube-version",
        "1.29.0",
        *extra,
    ]
    if show_only is not None:
        argv += ["--show-only", show_only]
    return subprocess.run(argv, capture_output=True, text=True)  # noqa: S603 - trusted argv


def _alert_names() -> list[str]:
    """Every ``alert:`` name in the promtool-gated source file, in order."""
    text = ALERTS_FILE.read_text(encoding="utf-8")
    return re.findall(r"^\s*-\s*alert:\s*(\w+)\s*$", text, re.MULTILINE)


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_default_render_has_no_report_engine_prometheusrule() -> None:
    """EXPOSE-DON'T-BUNDLE: no --set renders NO report-engine PrometheusRule."""
    result = _template()
    assert result.returncode == 0, result.stderr
    assert "name: netops-report-engine" not in result.stdout
    assert "netops.ai/slo-rules: report-engine" not in result.stdout


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_prometheus_rule_enabled_renders_report_engine_rule() -> None:
    """observability.prometheusRule.enabled=true renders the PrometheusRule
    object with every alert name from the promtool-gated source file — the
    single-source-of-truth lockstep (PR #166 F5)."""
    result = _template(
        "--set",
        "observability.prometheusRule.enabled=true",
        show_only="templates/report-engine-prometheusrule.yaml",
    )
    assert result.returncode == 0, result.stderr
    rendered = result.stdout
    assert "kind: PrometheusRule" in rendered
    assert "name: netops-report-engine" in rendered
    assert "netops.ai/slo-rules: report-engine" in rendered

    source_alerts = _alert_names()
    assert source_alerts, "the promtool source file must name at least one alert"
    for alert_name in source_alerts:
        assert f"alert: {alert_name}" in rendered, (
            f"{alert_name!r} is in report-engine.alerts.yaml but missing from the "
            "rendered PrometheusRule — the two files have drifted out of lockstep"
        )

    # Every alert carries a resolving runbook_url (ADR-0046 §3).
    assert rendered.count("runbook_url:") == len(source_alerts)


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_prometheus_rule_off_still_lints() -> None:
    """helm lint stays green with the report-engine template present but unset."""
    helm = _helm()
    assert helm is not None
    result = subprocess.run(  # noqa: S603 - trusted argv
        [helm, "lint", str(CHART_DIR)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
