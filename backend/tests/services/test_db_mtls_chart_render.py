"""DB-link mTLS chart-posture render guards (PR#76 fix group G5).

These pin the W4-T4 mTLS hardening findings on the rendered Helm manifests:

  * M7  — DB-link mTLS is ON BY DEFAULT (values default + the cert-manager CRs and
          the api/worker client cert mount render with NO --set).
  * M2  — the pg_hba auth method is HARDCODED scram-sha-256 (a weaker override like
          `trust` FAILS the render, never silently weakens the password layer).
  * M4  — the dev/CI fallback fails CLOSED: it never emits empty cert material (the
          render carries non-empty PEM under data:).
  * M5  — the CA certificate outlives the leaf certs by a wide margin (a separate,
          much longer caDuration knob).
  * P2net — an EMPTY collector-egress managementCidrs FAILS the render rather than
          emitting an empty-`to` (allow-all) NetworkPolicy rule (fail-open).

helm is the authoritative renderer; the tests skip cleanly when it is absent (the
infra job runs helm lint / kubeconform / kube-linter / conftest as the CI gate).
A few static-source asserts pin the values defaults without helm.
"""

from __future__ import annotations

import base64
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHART_DIR = REPO_ROOT / "deploy" / "kubernetes" / "netops"
VALUES = CHART_DIR / "values.yaml"
NOTES = CHART_DIR / "templates" / "NOTES.txt"
CHART_README = CHART_DIR / "README.md"


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


# --------------------------------------------------------------------------- M7
def test_mtls_enabled_default_in_values() -> None:
    """M7: mtls.postgres.enabled defaults to true (static, no helm)."""
    values = VALUES.read_text(encoding="utf-8")
    block = re.search(r"\nmtls:\n  postgres:\n((?:    .*\n|\n)*)", values)
    assert block is not None, "mtls.postgres block not found"
    postgres_block = block.group(1)
    # The FIRST `enabled:` under mtls.postgres is the tier toggle.
    first_enabled = re.search(r"^    enabled: (\w+)\b", postgres_block, re.MULTILINE)
    assert first_enabled is not None
    assert first_enabled.group(1) == "true", "M7: mtls.postgres.enabled must default to true"


def test_ca_outlives_leaf_in_values() -> None:
    """M5: caDuration is set and far exceeds the leaf duration (static, no helm)."""
    values = VALUES.read_text(encoding="utf-8")
    assert re.search(r"^      caDuration: 87600h\b", values, re.MULTILINE), (
        "M5: a long-lived caDuration knob must exist"
    )
    assert re.search(r"^      duration: 2160h\b", values, re.MULTILINE), (
        "the 90d leaf duration must remain"
    )


def test_notes_documents_mtls_posture_and_opt_out() -> None:
    """M7: NOTES.txt carries the cert-manager-required banner + the warned opt-out."""
    notes = NOTES.read_text(encoding="utf-8")
    # banner mentions the DB-link mTLS posture + cert-manager dependency.
    assert "DB-link mTLS" in notes
    assert "cert-manager" in notes
    # the documented opt-out warning (plaintext) fires when disabled.
    assert "mtls.postgres.enabled=false" in notes
    assert "PLAINTEXT" in notes
    # the dev-fallback warning fires when cert-manager is off but mTLS is on.
    assert "mtls.postgres.certManager.enabled=false" in notes


def test_readme_documents_cert_manager_dependency() -> None:
    """M7: the chart README documents cert-manager as a required dependency + opt-out."""
    readme = CHART_README.read_text(encoding="utf-8")
    assert "mtls.postgres.enabled" in readme
    # cert-manager is named as REQUIRED by default for the DB link.
    assert "DB-link mTLS" in readme or "DB-link" in readme
    assert "cert-manager" in readme


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_default_render_is_mtls_on() -> None:
    """M7: the DEFAULT render (no --set) wires DB-link mTLS end to end."""
    result = _template()
    assert result.returncode == 0, result.stderr
    rendered = result.stdout
    # cert-manager CRs for the DB CA + server + client certs.
    assert "name: netops-db-ca" in rendered
    assert "name: netops-postgres-server" in rendered
    assert "name: netops-db-client" in rendered
    # the pg_hba refusal ConfigMap + the api/worker client cert mount.
    assert "clientcert=verify-full" in rendered
    assert "name: db-tls-client" in rendered


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_mtls_off_render_omits_mtls(  # the documented opt-out still works
) -> None:
    """M7 opt-out: mtls.postgres.enabled=false renders NO mTLS CR / mount / pg_hba."""
    result = _template("--set", "mtls.postgres.enabled=false")
    assert result.returncode == 0, result.stderr
    rendered = result.stdout
    # the pg_hba refusal ConfigMap is absent (check the rendered object name, not
    # comment text that mentions clientcert).
    assert "name: netops-postgres-tls-config" not in rendered
    # the api/worker/cronjob client cert mount + cert-manager client cert are absent.
    assert "name: db-tls-client" not in rendered
    assert "name: netops-db-client" not in rendered


# --------------------------------------------------------------------------- M2
@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_pg_hba_method_hardcoded_scram() -> None:
    """M2: the rendered pg_hba uses scram-sha-256 (the hardcoded password layer)."""
    result = _template(show_only="templates/postgres-tls-configmap.yaml")
    assert result.returncode == 0, result.stderr
    assert "scram-sha-256 clientcert=verify-full" in result.stdout


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_pg_hba_weak_method_override_fails_render() -> None:
    """M2 BITE: overriding hbaAuthMethod to `trust` FAILS the render (fail closed)."""
    result = _template("--set", "mtls.postgres.hbaAuthMethod=trust")
    assert result.returncode != 0, "render must FAIL when hbaAuthMethod is weakened"
    assert "scram-sha-256" in (result.stderr + result.stdout)


# --------------------------------------------------------------------------- M4
@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_dev_fallback_emits_nonempty_cert_material() -> None:
    """M4: the dev/CI fallback fails closed — non-empty cert PEM under data:.

    certManager.enabled=false takes the self-signed fallback path that GENERATES the
    triple; the rendered client Secret must carry non-empty tls.crt/tls.key (never an
    empty/zero-byte cert that would fail open).
    """
    result = _template(
        "--set",
        "mtls.postgres.enabled=true",
        "--set",
        "mtls.postgres.certManager.enabled=false",
        show_only="templates/mtls-postgres.yaml",
    )
    assert result.returncode == 0, result.stderr
    rendered = result.stdout
    # Find the client Secret block and assert its tls.crt is a non-empty base64 PEM.
    m = re.search(
        r"name: netops-db-client-tls.*?tls\.crt:\s*(\S+)",
        rendered,
        re.DOTALL,
    )
    assert m is not None, "client TLS Secret tls.crt not found in dev-fallback render"
    decoded = base64.b64decode(m.group(1))
    assert decoded, "M4: dev-fallback tls.crt must be NON-EMPTY (fail closed)"
    assert b"BEGIN CERTIFICATE" in decoded


# ------------------------------------------------------------------------- P2net
@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_empty_management_cidrs_fails_render() -> None:
    """P2net (CRITICAL): empty collectorEgress.managementCidrs FAILS the render.

    An empty CIDR list would render `to:` empty with `ports:` set => a NetworkPolicy
    that ALLOWS egress to ALL destinations on those ports (fail-open). The template
    must refuse to render rather than emit the empty-`to` allow-all rule.
    """
    result = _template("--set-json", "networkPolicy.collectorEgress.managementCidrs=[]")
    assert result.returncode != 0, "render must FAIL on empty managementCidrs (fail-open guard)"
    assert "managementCidrs is EMPTY" in (result.stderr + result.stdout)


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_empty_string_cidr_fails_render() -> None:
    """P2net hardening: a list containing an empty-string CIDR also FAILS the render."""
    result = _template("--set-json", 'networkPolicy.collectorEgress.managementCidrs=[""]')
    assert result.returncode != 0, "render must FAIL on an empty-string CIDR entry"
    assert "EMPTY CIDR" in (result.stderr + result.stdout)
