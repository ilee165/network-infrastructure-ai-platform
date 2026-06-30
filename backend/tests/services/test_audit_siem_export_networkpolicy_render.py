"""Audit -> SIEM exporter NetworkPolicy egress render guards (W3-T1, ADR-0045 §5 / ADR-0041 §1).

The exporter pod (component ``audit-siem-export``) is READ-only against ``audit_log``
and advances its own ``audit_export_cursor`` row, so under the default-deny floor it
MUST be granted egress to in-cluster ``postgres:5432`` *in addition to* the external
SIEM-CIDR allow. The §2 data-store allows in ``networkpolicies.yaml`` are scoped by
component (``allow-worker-egress`` -> worker, ``allow-audit-egress`` -> audit, ...)
and do NOT cover ``audit-siem-export``; without its own allow the exporter cannot read
``audit_log`` or advance its cursor under an enforcing CNI and exports nothing.

These tests pin that the exporter gets its OWN Postgres egress allow, and that when
the CloudNativePG tier is enabled the exporter is in the ``allow-cnpg-pooler-ingress``
``from`` list — the exact default-deny gap the W3-T1 review finding closed.

The render tests use ``helm`` when available and skip cleanly otherwise (the manifest
gates — helm lint / kubeconform / kube-linter / conftest — are the authoritative CI
gate, run in the infra job). A static source fallback pins the same wiring without helm.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHART_DIR = REPO_ROOT / "deploy" / "kubernetes" / "netops"
EXPORT_NP = CHART_DIR / "templates" / "audit-siem-export-networkpolicy.yaml"
NETPOL = CHART_DIR / "templates" / "networkpolicies.yaml"


def test_export_np_source_emits_postgres_egress_for_exporter() -> None:
    """The exporter template source defines a Postgres-egress allow for the exporter pod."""
    src = EXPORT_NP.read_text(encoding="utf-8")
    # A dedicated policy granting the exporter the in-cluster Postgres read path.
    assert "allow-audit-siem-export-postgres-egress" in src
    # It selects the exporter pods and targets the postgres component on its port.
    assert '"component" "audit-siem-export"' in src
    assert ".Values.networkPolicy.postgres.podSelectorLabels" in src
    assert ".Values.networkPolicy.postgres.port" in src
    # The misleading "allow-worker-egress covers it" claim is gone — the header now
    # states the §2 worker allow does NOT cover the exporter, which gets its OWN allow.
    assert "needs its OWN Postgres allow" in src
    # And the header no longer claims allow-worker-egress grants the exporter's DB read.
    assert "-allow-worker-egress\nfor the in-cluster Postgres it reads" not in src


def test_cnpg_pooler_ingress_source_includes_exporter() -> None:
    """networkpolicies.yaml adds the exporter to the CNPG pooler-ingress from-list."""
    src = NETPOL.read_text(encoding="utf-8")
    # Gated on audit.export.enabled, selecting the exporter component.
    assert ".Values.audit.export.enabled" in src
    assert '"component" "audit-siem-export"' in src


def _helm() -> str | None:
    return shutil.which("helm")


def _render(show_only: str, *sets: str) -> str:
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
        "--show-only",
        show_only,
    ]
    for s in sets:
        argv += ["--set", s]
    result = subprocess.run(  # noqa: S603 - fixed, trusted argv (no shell)
        argv,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


_EXPORT_ON = (
    "audit.export.enabled=true",
    "audit.export.format=https-json",
    "audit.export.httpsEndpoint=https://siem.example.com/ingest",
)


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_rendered_exporter_has_postgres_egress_allow() -> None:
    """A real render emits a Postgres-egress NetworkPolicy bound to the exporter pod."""
    rendered = _render("templates/audit-siem-export-networkpolicy.yaml", *_EXPORT_ON)
    assert "name: netops-allow-audit-siem-export-postgres-egress" in rendered
    # Bound to the exporter pods, egress to postgres:5432.
    assert "app.kubernetes.io/component: audit-siem-export" in rendered
    assert "app.kubernetes.io/component: postgres" in rendered
    assert "port: 5432" in rendered


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_exporter_postgres_egress_absent_when_export_disabled() -> None:
    """With the exporter off, no exporter Postgres-egress policy renders (secure default)."""
    helm = _helm()
    assert helm is not None
    # The whole template is guarded; helm reports it yields no manifest.
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
            "--show-only",
            "templates/audit-siem-export-networkpolicy.yaml",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "allow-audit-siem-export-postgres-egress" not in result.stdout


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_cnpg_pooler_ingress_includes_exporter_when_export_enabled() -> None:
    """With CNPG + exporter on, the pooler-ingress from-list includes the exporter."""
    rendered = _render(
        "templates/networkpolicies.yaml",
        *_EXPORT_ON,
        "cloudNativePg.enabled=true",
        "services.postgres.enabled=false",
    )
    # The pooler-ingress policy renders and lists the exporter component in `from`.
    assert "name: netops-allow-cnpg-pooler-ingress" in rendered
    assert "app.kubernetes.io/component: audit-siem-export" in rendered


@pytest.mark.skipif(_helm() is None, reason="helm not installed; manifest gates run in CI")
def test_cnpg_pooler_ingress_omits_exporter_when_export_disabled() -> None:
    """With CNPG on but the exporter off, the pooler-ingress from-list omits the exporter."""
    rendered = _render(
        "templates/networkpolicies.yaml",
        "cloudNativePg.enabled=true",
        "services.postgres.enabled=false",
    )
    assert "name: netops-allow-cnpg-pooler-ingress" in rendered
    assert "audit-siem-export" not in rendered
