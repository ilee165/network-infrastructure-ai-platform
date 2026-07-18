"""Per-kind payload builders (ADR-0053 §1/§7).

Maps every :class:`~app.models.reports.ReportKind` to an async builder that
assembles its typed payload from the ALLOWLISTED sources only (ADR-0053 §6
layer 1). The change report (§7.1) is LIVE — the W3-T2 CR lifecycle roll-up in
:mod:`app.engines.reports.change_report`; the remaining three kinds render the
W3-T1 deterministic skeleton until their wave tasks land: W3-T3 (compliance
posture over the §7.2 history), W3-T4 (access review), W3-T5 (audit
integrity).

Source allowlist (layer 1): builders may read ONLY secret-free sources — CR
metadata, approvals, audit columns, users/roles/mappings, the §7.2/§7.4 history
tables, snapshot *metadata*. The deny-set (``device_credentials``,
``config_snapshots.content``, ``raw_artifacts``, any KMS/KEK surface) is not
reachable from ``app.engines.reports`` — enforced by the import-linter contract
in ``pyproject.toml`` plus the no-SELECT-deny-set test
(``tests/engines/reports/test_boundary.py``). What is never queried can never
leak.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.reports.change_report import build_change_sections
from app.engines.reports.payloads import ReportPayload, ReportSection
from app.models.reports import ReportKind

__all__ = ["ENGINE_VERSION", "REGIME_TAG_DEFAULTS", "REPORT_TITLES", "build_payload"]

#: Engine version stamped into payloads/history rows — bump on render-affecting
#: changes so evidence provenance is reconstructible (ADR-0053 §1).
ENGINE_VERSION: Final = "reports-engine/1.0.0"

#: SOC 2 CC-series PROPOSED default regime tags per kind (ADR-0053 §8). Tags are
#: metadata only: the authoritative report↔control mapping is the W3-T6 doc, and
#: a future ISO/NIST answer re-tags without redesigning reports.
REGIME_TAG_DEFAULTS: Final[dict[ReportKind, tuple[str, ...]]] = {
    ReportKind.CHANGE: ("soc2:CC8.1",),
    ReportKind.COMPLIANCE_POSTURE: ("soc2:CC7.1", "soc2:CC4.1"),
    ReportKind.ACCESS_REVIEW: ("soc2:CC6.1", "soc2:CC6.2", "soc2:CC6.3"),
    ReportKind.AUDIT_INTEGRITY: ("soc2:CC7.2",),
}

REPORT_TITLES: Final[dict[ReportKind, str]] = {
    ReportKind.CHANGE: "Change Report",
    ReportKind.COMPLIANCE_POSTURE: "Compliance Posture Report",
    ReportKind.ACCESS_REVIEW: "Access Review Report",
    ReportKind.AUDIT_INTEGRITY: "Audit Integrity Report",
}

#: The wave task that lands each REMAINING kind's full payload on this engine
#: (the change report landed in W3-T2 — see the dispatch in :func:`build_payload`).
_PAYLOAD_TASKS: Final[dict[ReportKind, str]] = {
    ReportKind.COMPLIANCE_POSTURE: "W3-T3",
    ReportKind.ACCESS_REVIEW: "W3-T4",
    ReportKind.AUDIT_INTEGRITY: "W3-T5",
}


async def build_payload(
    session: AsyncSession,
    *,
    kind: ReportKind,
    period_start: datetime,
    period_end: datetime,
    generated_at: datetime,
) -> ReportPayload:
    """Assemble the typed payload for one ``(kind, period)`` (ADR-0053 §1).

    *session* is the report engine's allowlisted read session (the live
    builders query their §7 sources through it — and through it ONLY, so the
    no-SELECT-deny-set test observes every read).

    The generation timestamp is a PARAMETER, not a clock read: determinism is
    the caller-injected ``generated_at`` flowing into both artifact content and
    PDF metadata.
    """
    provenance = ReportSection(
        title="Report provenance",
        columns=("Field", "Value"),
        rows=(
            ("Engine version", ENGINE_VERSION),
            ("Report kind", kind.value),
            ("Period start (UTC)", period_start.isoformat()),
            ("Period end (UTC)", period_end.isoformat()),
        ),
    )
    if kind is ReportKind.CHANGE:
        change_sections, change_notes = await build_change_sections(
            session, period_start=period_start, period_end=period_end
        )
        return ReportPayload(
            kind=kind.value,
            title=REPORT_TITLES[kind],
            period_start=period_start,
            period_end=period_end,
            generated_at=generated_at,
            regime_tags=REGIME_TAG_DEFAULTS[kind],
            sections=(provenance, *change_sections),
            notes=change_notes,
        )
    del session  # The remaining W3-T3..T5 skeleton kinds read nothing yet.
    return ReportPayload(
        kind=kind.value,
        title=REPORT_TITLES[kind],
        period_start=period_start,
        period_end=period_end,
        generated_at=generated_at,
        regime_tags=REGIME_TAG_DEFAULTS[kind],
        sections=(provenance,),
        notes=(
            f"Engine skeleton artifact (P4 W3-T1): the full {kind.value} payload "
            f"lands in {_PAYLOAD_TASKS[kind]} on this render path.",
        ),
    )
