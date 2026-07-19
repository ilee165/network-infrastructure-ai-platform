"""Render-path tests (P4 W3-T1; ADR-0053 §5): CSV neutralization, the deny-all
fetcher (air-gap + SSRF guard), the redaction choke point inside the SINGLE
render path, the pinned WeasyPrint call shape, and — where the native Pango
stack is available — a real PDF structure smoke.

The WeasyPrint call shape is pinned by a contract test against a fake module
(the SDK method, kwargs, and result access the prod path uses) so the PDF path
cannot silently drift on hosts where the real library cannot load; the live
render smoke runs wherever Pango exists (backend image / CI hosts with the
system libs) and skips with a reason elsewhere.
"""

from __future__ import annotations

import csv
import hashlib
import io
import sys
import types
from datetime import UTC, datetime
from typing import Any

import pytest

from app.engines.reports import render
from app.engines.reports.payloads import ReportPayload, ReportSection
from app.engines.reports.redaction import RedactionViolationError
from app.engines.reports.render import (
    RenderEgressBlockedError,
    check_fetch_url,
    neutralize_cell,
    render_artifacts,
)
from app.models.reports import ReportFormat

_START = datetime(2026, 7, 1, tzinfo=UTC)
_END = datetime(2026, 7, 8, tzinfo=UTC)
_GEN = datetime(2026, 7, 8, 5, 0, tzinfo=UTC)


def _payload(**overrides: Any) -> ReportPayload:
    base: dict[str, Any] = {
        "kind": "change",
        "title": "Change Report",
        "period_start": _START,
        "period_end": _END,
        "generated_at": _GEN,
        "regime_tags": ("soc2:CC8.1",),
        "sections": (
            ReportSection(
                title="Data",
                columns=("Field", "Value"),
                rows=(("Device", "core-sw-01"),),
            ),
        ),
        "notes": ("note one",),
    }
    base.update(overrides)
    return ReportPayload(**base)


def _weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001 — missing native libs raise OSError, not ImportError
        return False
    return True


# ---------------------------------------------------------------------------
# CSV formula-injection neutralization (OWASP; ADR-0053 §5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dangerous",
    ["=SUM(A1:A9)", "+1234", "-1234", "@cmd", "\tpayload", "\rpayload"],
)
def test_neutralize_cell_prefixes_formula_leads(dangerous: str) -> None:
    assert neutralize_cell(dangerous) == f"'{dangerous}"


@pytest.mark.parametrize("safe", ["core-sw-01", "10.0.0.1", "approved", "", "a=b"])
def test_neutralize_cell_leaves_safe_cells(safe: str) -> None:
    assert neutralize_cell(safe) == safe


def test_csv_render_neutralizes_attacker_controlled_cells() -> None:
    """A hostname/CR-title cell starting with a formula lead cannot execute."""
    payload = _payload(
        sections=(
            ReportSection(
                title="Changes",
                columns=("CR title", "Requester"),
                rows=(('=HYPERLINK("http://evil")', "@alice"),),
            ),
        )
    )
    raw = render._render_csv(payload).decode("utf-8")
    parsed = list(csv.reader(io.StringIO(raw)))
    flat = [cell for row in parsed for cell in row]
    assert '\'=HYPERLINK("http://evil")' in flat
    assert "'@alice" in flat
    # No parsed cell may still START with a formula lead.
    assert not any(cell.startswith(("=", "+", "@", "\t", "\r")) for cell in flat)


def test_csv_render_carries_report_metadata() -> None:
    raw = render._render_csv(_payload()).decode("utf-8")
    parsed = {row[0]: row[1] for row in csv.reader(io.StringIO(raw)) if len(row) == 2}
    assert parsed["kind"] == "change"
    assert parsed["generated_at"] == _GEN.isoformat()


# ---------------------------------------------------------------------------
# Deny-all URL fetcher (zero render-time egress; template-dir-scoped file:)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://cdn.example.com/font.woff2",
        "http://169.254.169.254/latest/meta-data/",  # SSRF canary
        "ftp://internal/config",
        "file:///etc/passwd",
        "file://fileserver/share/x.css",  # UNC host
        "gopher://x",
    ],
)
def test_fetcher_denies_every_remote_or_out_of_tree_url(url: str) -> None:
    with pytest.raises(RenderEgressBlockedError):
        check_fetch_url(url)
    # The composed fetcher denies BEFORE any weasyprint import — the guard
    # bites on hosts without the native stack too.
    with pytest.raises(RenderEgressBlockedError):
        render._deny_all_url_fetcher(url)


def test_fetcher_allows_data_uris_and_template_dir_files() -> None:
    check_fetch_url("data:image/png;base64,iVBORw0KGgo=")
    template_url = (render._TEMPLATES_DIR / "report_base.html").as_uri()
    check_fetch_url(template_url)


def test_fetcher_denies_template_dir_escape() -> None:
    escape = (render._TEMPLATES_DIR / ".." / "render.py").resolve().as_uri()
    with pytest.raises(RenderEgressBlockedError):
        check_fetch_url(escape)


def test_packaged_templates_reference_no_remote_urls() -> None:
    """A CDN reference in a template is a CI error (ADR-0053 §5).

    WeasyPrint logs-and-continues on a failed subresource fetch, so the
    honest CI enforcement is: no packaged template may carry a remote URL at
    all (the fetcher remains the runtime backstop for payload-derived URLs).
    """
    for template in render._TEMPLATES_DIR.rglob("*.html"):
        text = template.read_text(encoding="utf-8")
        assert "http://" not in text and "https://" not in text, (
            f"template {template.name} references a remote URL — render-time "
            "egress is banned (ADR-0053 §5)"
        )


# ---------------------------------------------------------------------------
# The redaction choke point sits INSIDE the single render path
# ---------------------------------------------------------------------------


def test_render_artifacts_redacts_before_any_renderer_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A planted PEM aborts render_artifacts BEFORE any renderer executes."""
    calls: list[str] = []
    monkeypatch.setattr(render, "_render_csv", lambda p: calls.append("csv") or b"csv")
    monkeypatch.setattr(render, "_render_pdf", lambda p: calls.append("pdf") or b"pdf")
    planted = _payload(
        sections=(
            ReportSection(
                title="Data",
                columns=("Field", "Value"),
                rows=(("blob", "-----BEGIN RSA PRIVATE KEY-----MIIE-----END-----"),),
            ),
        )
    )
    with pytest.raises(RedactionViolationError):
        render_artifacts(planted)
    assert calls == []  # fail CLOSED: no partial artifact bytes were produced


def test_render_artifacts_produces_csv_and_pdf_with_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(render, "_render_pdf", lambda p: b"%PDF-1.7 stub")
    artifacts = render_artifacts(_payload())
    by_format = {a.format: a for a in artifacts}
    assert set(by_format) == {ReportFormat.CSV, ReportFormat.PDF}
    for artifact in artifacts:
        assert artifact.sha256 == hashlib.sha256(artifact.content).hexdigest()
        assert artifact.size_bytes == len(artifact.content)


# ---------------------------------------------------------------------------
# WeasyPrint call-shape contract (pinned against a fake module) + live smoke
# ---------------------------------------------------------------------------


def test_pdf_call_shape_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the exact SDK surface the prod PDF path uses (no-vacuous-coverage).

    Asserts ``weasyprint.HTML(string=..., base_url=<template dir>,
    url_fetcher=_deny_all_url_fetcher).write_pdf()`` — the call shape the
    backend image executes — so a drift here fails even on hosts where the
    real native stack cannot load.
    """
    recorded: dict[str, Any] = {}

    class _FakeDocument:
        def write_pdf(self) -> bytes:
            recorded["write_pdf_called"] = True
            return b"%PDF-1.7 fake"

    class _FakeHTML:
        def __init__(self, **kwargs: Any) -> None:
            recorded["kwargs"] = kwargs

        def write_pdf(self) -> bytes:
            return _FakeDocument().write_pdf()

    fake = types.ModuleType("weasyprint")
    fake.HTML = _FakeHTML  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "weasyprint", fake)

    result = render._render_pdf(_payload())

    assert result == b"%PDF-1.7 fake"
    assert recorded["write_pdf_called"] is True
    kwargs = recorded["kwargs"]
    assert set(kwargs) == {"string", "base_url", "url_fetcher"}
    assert kwargs["url_fetcher"] is render._deny_all_url_fetcher
    assert kwargs["base_url"] == f"{render._TEMPLATES_DIR.as_uri()}/"
    html_source = kwargs["string"]
    # Determinism: PDF metadata dates are pinned from payload.generated_at.
    assert f'content="{_GEN.isoformat()}"' in html_source
    assert "Change Report" in html_source


@pytest.mark.skipif(
    not _weasyprint_available(),
    reason="WeasyPrint native stack (Pango) unavailable on this host — the "
    "backend image installs it (backend.Dockerfile); the call shape is pinned "
    "by test_pdf_call_shape_is_pinned above",
)
def test_pdf_render_smoke_real_weasyprint() -> None:
    """Offline structure smoke on the REAL renderer: valid PDF magic, no egress."""
    artifacts = render_artifacts(_payload())
    pdf = next(a for a in artifacts if a.format is ReportFormat.PDF)
    assert pdf.content.startswith(b"%PDF-")
    assert pdf.size_bytes > 500
