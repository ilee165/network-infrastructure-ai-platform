"""Credential-rotation CronJob render guards (W4-T2: ADR-0040 §1 L3/L5).

The spec's load-bearing CronJob risk is the P1-W4 L3 trap: a ``$(VAR)`` in a k8s
exec argv runs against a literal (K8s does not substitute it), so the rotation job
would run against an empty DSN. These tests assert the rendered CronJob wraps its
env expansion in ONE ``sh -c`` script (L3) and applies ``set -o pipefail`` +
``test -s`` (L5) — and that the DB password is referenced, never inlined.

The test renders the chart with ``helm`` when available; it skips cleanly when
helm is not installed (the manifest gates — helm lint / kubeconform / kube-linter
/ conftest — are the authoritative CI gate, run in the infra job). A fast static
fallback also asserts the same guards directly on the template source so the L3/L5
discipline is pinned even without helm.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHART_DIR = REPO_ROOT / "deploy" / "kubernetes" / "netops"
TEMPLATE = CHART_DIR / "templates" / "credential-rotation-cronjob.yaml"
VALUES = CHART_DIR / "values.yaml"
NOTES = CHART_DIR / "templates" / "NOTES.txt"


def test_template_source_applies_l3_and_l5_guards() -> None:
    """The template source wraps env expansion in sh -c (L3) + pipefail/test -s (L5)."""
    src = TEMPLATE.read_text(encoding="utf-8")
    # L3: a single `sh -c` command, NOT a raw exec argv doing its own $(VAR).
    assert "- sh" in src
    assert "- -c" in src
    # The DSN is assembled from ${VAR} shell expansions inside the sh -c script.
    assert 'export NETOPS_DATABASE_URL="postgresql+asyncpg://${NETOPS_POSTGRES_USER}' in src
    # L5: pipefail + a non-empty guard on the summary file.
    assert "set -euo pipefail" in src
    assert 'test -s "${CREDENTIAL_ROTATION_SUMMARY_DIR}/credential_rotation.prom"' in src
    # The password is BY-REFERENCE (secretKeyRef), never an inlined literal value.
    assert "secretKeyRef:" in src
    assert "postgresPassword" in src
    # Disjoint from W6-T3 KEK rotation: the device-secret module, not re_wrap_keys.
    assert "python -m app.workers.tasks.credential_rotation" in src
    assert "re_wrap_keys" not in src


def test_scheduled_rotation_is_disabled_by_default() -> None:
    """CR C1+C4: the scheduled rotation CronJob is shipped OFF by default.

    The scheduled pass stages+verifies a NEW secret while ADR-0040 §4 defers the
    on-device change, so an enabled job degrades every credential each run. The
    chart must therefore default ``credentials.rotation.enabled=false`` and the
    template gate must key off that value so NOTHING renders by default.
    """
    values = VALUES.read_text(encoding="utf-8")
    # Isolate the credentials.rotation block (from `  rotation:` to the next
    # top-level `key:` at column 0) so the `enabled:` assertion is scoped to it and
    # cannot be satisfied by another tier's `enabled: true` elsewhere in the file.
    block = re.search(r"\n  rotation:\n((?:    .*\n|\n)*)", values)
    assert block is not None, "credentials.rotation block not found in values.yaml"
    rotation_block = block.group(1)
    # The rotation block's own `enabled:` key defaults to false (CR C1+C4).
    assert re.search(r"^    enabled: false\b", rotation_block, re.MULTILINE), (
        "credentials.rotation.enabled must default to false (CR C1+C4)"
    )
    assert not re.search(r"^    enabled: true\b", rotation_block, re.MULTILINE)
    # The template only renders when the tier is explicitly enabled.
    src = TEMPLATE.read_text(encoding="utf-8")
    assert "{{- if .Values.credentials.rotation.enabled }}" in src


def test_template_documents_deferred_on_device_change() -> None:
    """CR C1+C4: the disabled-by-default rationale (ADR-0040 §4) is documented in-tree."""
    src = TEMPLATE.read_text(encoding="utf-8")
    assert "DISABLED BY DEFAULT" in src
    assert "ADR-0040 §4" in src
    assert "on-device" in src
    # The on-demand service path is preserved (not removed) — named in the note.
    assert "rotate_device_secret()" in src


def test_notes_warns_when_scheduled_rotation_is_enabled() -> None:
    """CR C1+C4: the NOTES warning fires on ENABLE (the dangerous state), not disable."""
    notes = NOTES.read_text(encoding="utf-8")
    # The opt-IN warning gates on enabled (true), inverting the old opt-out warning.
    assert "{{- if .Values.credentials.rotation.enabled }}" in notes
    assert "credentials.rotation.enabled=true" in notes
    # The old opt-out copy (warning when disabled) is gone.
    assert "credentials.rotation.enabled=false — the device-credential rotation" not in notes


def _helm() -> str | None:
    return shutil.which("helm")


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_rendered_cronjob_invokes_rotation_module_via_sh_c() -> None:
    """A real helm render produces a CronJob whose container runs the rotation module.

    The tier is disabled by default (CR C1+C4), so this explicitly opts IN
    (``--set credentials.rotation.enabled=true``) to render and assert the manifest
    shape that DOES render when an operator turns scheduled rotation on.
    """
    helm = _helm()
    assert helm is not None
    result = subprocess.run(  # noqa: S603 - fixed, trusted argv (no shell)
        [
            helm,
            "template",
            "netops",
            str(CHART_DIR),
            "--namespace",
            "netops",
            "--kube-version",
            "1.29.0",
            "--set",
            "credentials.rotation.enabled=true",
            "--show-only",
            "templates/credential-rotation-cronjob.yaml",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    rendered = result.stdout
    assert "kind: CronJob" in rendered
    assert "name: netops-credential-rotation" in rendered
    assert "python -m app.workers.tasks.credential_rotation" in rendered
    # The hardened security context flows through (runAsNonRoot, drop ALL).
    assert "runAsNonRoot: true" in rendered
    assert "readOnlyRootFilesystem: true" in rendered
