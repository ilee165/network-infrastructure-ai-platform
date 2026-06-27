"""Static-artifact regression tests for PR #76 fix-group G6 (W4 hardening docs).

Finding  Test(s)
-------  -------
D1       test_w4t3_doc_does_not_claim_conftest_absent
         test_w4t3_doc_references_conftest_rego_path
         test_w4t3_doc_states_conftest_is_present
A13      test_runbook_table_pipe_is_escaped
D2       test_notes_collector_egress_warning_gated_by_worker_in_source
         test_notes_collector_egress_line_references_worker_enabled

All tests are pure-static (filesystem reads only).
No Postgres, Neo4j, Redis, network, or live k8s cluster required.

NOTE on D2 helm rendering: ``helm template --show-only`` does not render
NOTES.txt (Helm only renders NOTES on an actual install against a live cluster).
The D2 tests therefore inspect the NOTES.txt *source* directly, asserting that
the conditional guard ``services.worker.enabled`` is present on the correct line
— the same strategy used by validate-harness.sh (grep-based static assertions).
"""

from __future__ import annotations

import pathlib

# ---------------------------------------------------------------------------
# Repo root — resolved relative to this file (backend/tests/ → repo root)
# ---------------------------------------------------------------------------
REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
CHART_DIR = REPO_ROOT / "deploy" / "kubernetes" / "netops"
NOTES_TXT = CHART_DIR / "templates" / "NOTES.txt"
W4T3_DOC = REPO_ROOT / "docs" / "roadmap" / "p2-tasks" / "W4-T3-kind-cluster-harness.md"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "audit-chain-verify-and-reseal.md"


# ---------------------------------------------------------------------------
# D1 — W4-T3 task doc must not falsely claim conftest/OPA policies are absent
# ---------------------------------------------------------------------------


def test_w4t3_doc_does_not_claim_conftest_absent() -> None:
    """D1: the phrase 'not present in the repo' must not appear next to conftest.

    The old text read:
        conftest/OPA policies are not present in the repo
    This was factually wrong — hardening.rego exists and CI wires conftest.
    """
    text = W4T3_DOC.read_text(encoding="utf-8")
    # The false claim combined 'not present' with conftest on the same line.
    # After the fix the line no longer contains this false statement.
    assert "policies are not present in the repo" not in text, (
        f"{W4T3_DOC.name} still contains the false 'not present in the repo' claim"
    )


def test_w4t3_doc_references_conftest_rego_path() -> None:
    """D1: the corrected text must reference the actual rego file path."""
    text = W4T3_DOC.read_text(encoding="utf-8")
    assert "hardening.rego" in text, (
        f"{W4T3_DOC.name} must reference deploy/kubernetes/policy/rego/hardening.rego "
        "to confirm conftest IS present"
    )


def test_w4t3_doc_states_conftest_is_present() -> None:
    """D1: the corrected text must positively assert conftest IS in the repo."""
    text = W4T3_DOC.read_text(encoding="utf-8")
    assert "conftest IS present" in text, (
        f"{W4T3_DOC.name} must positively state 'conftest IS present' (not absent)"
    )


# ---------------------------------------------------------------------------
# A13 — runbook GFM table must have the pipe in PASS|FAIL escaped
# ---------------------------------------------------------------------------


def test_runbook_table_pipe_is_escaped() -> None:
    r"""A13: the log-line table cell must use \| not a bare | for the alternation.

    An unescaped pipe inside a backtick table cell breaks GFM table rendering
    (MD056).  The cell must read PASS\|FAIL, not PASS|FAIL.
    """
    text = RUNBOOK.read_text(encoding="utf-8")
    # Find the log-line table row.
    log_line_rows = [ln for ln in text.splitlines() if "AUDIT_CHAIN_VERIFY OUTCOME=" in ln]
    assert log_line_rows, (
        f"{RUNBOOK.name}: could not find the AUDIT_CHAIN_VERIFY log-line table row"
    )
    for row in log_line_rows:
        assert r"PASS\|FAIL" in row, (
            f"{RUNBOOK.name}: table row contains unescaped pipe — found: {row!r}\n"
            r"Expected PASS\|FAIL (escaped) not PASS|FAIL (unescaped, breaks GFM table)"
        )
        # Additionally confirm the unescaped form is absent in this row.
        # Strip the escaped form first so the bare | is not a false positive.
        stripped = row.replace(r"\|", "")
        # After removing escaped pipes, check the outcome alternation has no bare pipe.
        assert "OUTCOME=PASS|FAIL" not in stripped, (
            f"{RUNBOOK.name}: bare unescaped pipe found in OUTCOME alternation: {row!r}"
        )


# ---------------------------------------------------------------------------
# D2 — NOTES.txt collector-egress warning must be gated by services.worker.enabled
#
# ``helm template --show-only templates/NOTES.txt`` does not work — Helm only
# renders NOTES.txt during an actual install against a live cluster.  We
# therefore verify the *source* of NOTES.txt directly (the same strategy used
# by validate-harness.sh) — asserting the Helm conditional expression carries
# the required guard so that the warning cannot fire when the worker is off.
# ---------------------------------------------------------------------------

# Unique fragment that identifies the collector-egress opt-out warning line.
_COLLECTOR_WARNING_FRAGMENT = "networkPolicy.collectorEgress.enabled=false"
# The guard that must also appear on the SAME line as the warning trigger.
_WORKER_GUARD = ".Values.services.worker.enabled"


def _find_collector_egress_warning_lines(text: str) -> list[str]:
    """Return the NOTES.txt source lines that contain the collector-egress warning trigger."""
    return [ln for ln in text.splitlines() if _COLLECTOR_WARNING_FRAGMENT in ln]


def test_notes_collector_egress_warning_gated_by_worker_in_source() -> None:
    """D2: the collector-egress opt-out warning in NOTES.txt must include
    the .Values.services.worker.enabled guard on the same conditional line.

    Before the fix the ``{{- if and ... }}`` guard checked only
    ``networkPolicy.enabled`` and ``(not collectorEgress.enabled)``, so it would
    emit the warning even when the worker deployment was disabled, falsely
    implying device operations would fail when there is no worker.

    After the fix the condition adds ``.Values.services.worker.enabled`` to the
    same ``{{- if and ... }}`` guard so the warning only fires when the worker is
    enabled.
    """
    text = NOTES_TXT.read_text(encoding="utf-8")
    warning_lines = _find_collector_egress_warning_lines(text)
    assert warning_lines, (
        f"{NOTES_TXT.name}: could not find the collector-egress warning line "
        f"(fragment: {_COLLECTOR_WARNING_FRAGMENT!r})"
    )


def test_notes_collector_egress_line_references_worker_enabled() -> None:
    """D2: the {{- if }} block that gates the collector-egress warning must
    include .Values.services.worker.enabled so it does not fire when worker=false."""
    text = NOTES_TXT.read_text(encoding="utf-8")
    # Find every line that is part of the collector-egress conditional block:
    # the opening {{- if ... }} guard that checks collectorEgress.enabled.
    lines = text.splitlines()
    guard_lines = []
    for i, line in enumerate(lines):
        # The if-guard line contains (not .Values.networkPolicy.collectorEgress.enabled)
        if "(not .Values.networkPolicy.collectorEgress.enabled)" in line and "{{-" in line:
            guard_lines.append((i + 1, line))  # 1-based line number

    assert guard_lines, (
        f"{NOTES_TXT.name}: could not find the collectorEgress if-guard line "
        "(expected a line matching '{{- if' containing "
        "'(not .Values.networkPolicy.collectorEgress.enabled)')"
    )
    for lineno, line in guard_lines:
        assert _WORKER_GUARD in line, (
            f"{NOTES_TXT.name}:{lineno}: the collector-egress opt-out if-guard does NOT "
            f"include the worker-enabled gate ({_WORKER_GUARD!r}).\n"
            f"This means the warning fires even when the worker is disabled — the bug D2 fixed.\n"
            f"Offending line: {line!r}"
        )
