"""The SINGLE payload→artifact render path (ADR-0053 §5/§6).

:func:`render_artifacts` is the ONLY way a payload becomes artifact bytes, and
the fail-closed redaction choke point
(:func:`app.engines.reports.redaction.enforce_redaction`) runs FIRST inside it —
there is no second path for report #5 to forget
(``tests/engines/reports/test_boundary.py`` enforces this structurally).

CSV: stdlib ``csv`` with **formula-injection neutralization** — any cell
beginning with ``=``, ``+``, ``-``, ``@``, TAB, CR, or LF is prefixed with ``'``
(OWASP CSV-injection guidance): auditors open evidence in Excel, and an
attacker-controlled hostname or CR title must not become an executing formula.

PDF: WeasyPrint behind :func:`_deny_all_url_fetcher` — every URL hard-fails
except ``data:`` URIs and ``file:`` paths INSIDE the packaged template
directory. A template referencing a CDN font/stylesheet/image is a render-time
error in CI, not a silent hang in an air-gapped deployment; the same fetcher is
the SSRF guard (payload-derived strings cannot make the renderer fetch an
internal URL). Fonts are bundled in the backend image (``fonts-dejavu-core``),
so no fontconfig network fallback exists. WeasyPrint is imported LAZILY so the
non-PDF paths (and hosts without the Pango system libraries) never require it.

Determinism: the generation timestamp is payload data; the PDF metadata dates
are pinned from the same field via ``dcterms`` meta tags in the template.
"""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.engines.reports.payloads import ReportPayload
from app.engines.reports.redaction import enforce_redaction
from app.models.reports import ReportFormat

__all__ = [
    "RenderEgressBlockedError",
    "RenderedArtifact",
    "check_fetch_url",
    "neutralize_cell",
    "render_artifacts",
]

#: The packaged template directory — the ONLY ``file:`` root the PDF fetcher
#: will serve (template-dir-scoped, ADR-0053 §5).
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

#: Cell prefixes Excel/Sheets interpret as a formula (OWASP CSV injection).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


class RenderEgressBlockedError(Exception):
    """The deny-all fetcher refused a URL (zero render-time egress, ADR-0053 §5)."""

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(
            f"render-time fetch blocked (air-gap contract, ADR-0053 §5): {url!r} — only "
            "data: URIs and file: paths inside the packaged template directory are servable"
        )


@dataclass(frozen=True)
class RenderedArtifact:
    """One rendered artifact: bytes + integrity digest, ready to persist."""

    format: ReportFormat
    content: bytes
    sha256: str
    size_bytes: int


def neutralize_cell(value: str) -> str:
    """Neutralize spreadsheet formula injection for one CSV cell (OWASP)."""
    if value.startswith(_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _render_csv(payload: ReportPayload) -> bytes:
    """Render *payload* to CSV bytes (stdlib writer, every cell neutralized)."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")

    def row(*cells: str) -> None:
        writer.writerow([neutralize_cell(cell) for cell in cells])

    row("report", payload.title)
    row("kind", payload.kind)
    row("period_start", payload.period_start.isoformat())
    row("period_end", payload.period_end.isoformat())
    row("generated_at", payload.generated_at.isoformat())
    row("regime_tags", " ".join(payload.regime_tags))
    for section in payload.sections:
        row()
        row(section.title)
        row(*section.columns)
        for data_row in section.rows:
            row(*data_row)
    for note in payload.notes:
        row()
        row("note", note)
    return buffer.getvalue().encode("utf-8")


def check_fetch_url(url: str) -> None:
    """Validate one render-time URL against the air-gap contract (pure, no I/O).

    Allows ``data:`` URIs and ``file:`` paths that resolve INSIDE the packaged
    template directory; everything else — http(s), ftp, any remote scheme, any
    ``file:`` outside the template dir — raises (fail closed). This is both the
    air-gap enforcement and the SSRF guard (ADR-0053 §5).

    Raises:
        RenderEgressBlockedError: for every URL outside the allowlist.
    """
    parsed = urlparse(url)
    if parsed.scheme == "data":
        return
    if parsed.scheme == "file":
        # Windows file URLs carry the drive in ``path`` (``/D:/...``); strip the
        # leading slash so Path resolves it. A ``netloc`` (UNC host) is denied.
        if parsed.netloc not in ("", "localhost"):
            raise RenderEgressBlockedError(url)
        raw_path = unquote(parsed.path)
        if len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
            raw_path = raw_path[1:]
        try:
            resolved = Path(raw_path).resolve(strict=False)
        except (OSError, ValueError) as exc:
            raise RenderEgressBlockedError(url) from exc
        if resolved == _TEMPLATES_DIR or resolved.is_relative_to(_TEMPLATES_DIR):
            return
        raise RenderEgressBlockedError(url)
    raise RenderEgressBlockedError(url)


def _deny_all_url_fetcher(url: str) -> dict[str, Any]:
    """WeasyPrint ``url_fetcher``: validate, then delegate to the default fetcher.

    The validation happens BEFORE the lazy WeasyPrint import so the deny path is
    unit-testable (and bites) on hosts without the Pango system libraries.
    """
    check_fetch_url(url)
    from weasyprint import default_url_fetcher

    return dict(default_url_fetcher(url))


def _jinja_env() -> Environment:
    """The packaged-template Jinja2 environment (autoescape + strict undefined)."""
    return Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=True,
        undefined=StrictUndefined,
    )


def _render_pdf(payload: ReportPayload) -> bytes:
    """Render *payload* to PDF via WeasyPrint behind the deny-all fetcher.

    WeasyPrint is imported lazily: it needs Pango/HarfBuzz system libraries that
    exist in the backend image (backend.Dockerfile apt layer) but not on every
    dev host. The call shape is pinned by a contract test
    (``tests/engines/reports/test_render.py``) so this path cannot silently
    drift on hosts where the real library is unavailable.
    """
    html_source = _jinja_env().get_template("report_base.html").render(payload=payload)
    from weasyprint import HTML

    document = HTML(
        string=html_source,
        base_url=f"{_TEMPLATES_DIR.as_uri()}/",
        url_fetcher=_deny_all_url_fetcher,
    )
    return bytes(document.write_pdf())


def _artifact(fmt: ReportFormat, content: bytes) -> RenderedArtifact:
    return RenderedArtifact(
        format=fmt,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )


def render_artifacts(payload: ReportPayload) -> list[RenderedArtifact]:
    """THE single payload→artifact path (ADR-0053 §6): redact, then render.

    :func:`enforce_redaction` runs before ANY renderer sees the payload; a hit
    aborts with :class:`~app.engines.reports.redaction.RedactionViolationError`
    and no artifact bytes are produced (fail closed, no partial artifact).
    """
    enforce_redaction(payload)
    return [
        _artifact(ReportFormat.CSV, _render_csv(payload)),
        _artifact(ReportFormat.PDF, _render_pdf(payload)),
    ]
