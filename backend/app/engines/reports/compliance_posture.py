"""Compliance posture report builder (P4 W3-T3; ADR-0053 §7.2).

Rolls the M4 compliance engine up from the PERSISTED run history
(``compliance_runs`` / ``compliance_run_findings``, populated by the daily
``reports.compliance_sweep`` beat task): pass/fail by **policy**, **device**,
and **severity** from the latest run in the CLOSED-OPEN UTC period
``[start, end)``, plus a **daily trend** series over the runs themselves.

Honesty contracts this module owns:

* **Gaps render as gaps** — a UTC day with no recorded run carries the
  explicit :data:`GAP_TOKEN` in every posture cell (the "0 runs recorded"
  count is measured; the posture counts are unknowable). Nothing is
  interpolated, smoothed, or carried forward (spec: "a gap in the sweep is
  visible, not interpolated").
* **Out-of-scope ≠ passing** — F5 BIG-IP and VMware vSphere have no
  text-config surface in P4 (ADR-0050 §7.6 / ADR-0051 §3 named deferrals);
  their devices surface in a dedicated out-of-scope section and never appear
  in posture roll-ups.
* **Secret-free by construction (ADR-0053 §6 layer 3)** — the history tables
  persist status/severity only; no evidence-excerpt column exists to quote
  config text. Live excerpt drill-down stays on the on-demand engineer+
  endpoint (``GET /config-snapshots/{device_id}/compliance``).

Sources (§6 layer 1 allowlist): the §7.2 history tables plus ``devices``
inventory metadata (hostname/vendor labels). Nothing here reads
``config_snapshots.content``, ``device_credentials``, or any other deny-set
surface — enforced by the import-linter contract and the no-SELECT-deny-set
runtime proof (``tests/engines/reports/test_boundary.py``).
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.config_mgmt.compliance.engine import FindingStatus
from app.engines.config_mgmt.compliance.schema import Severity
from app.engines.reports.idempotency import coerce_utc
from app.engines.reports.payloads import ReportSection
from app.models.compliance_history import ComplianceRun, ComplianceRunFinding
from app.models.inventory import Device

__all__ = [
    "DEVICE_COLUMNS",
    "GAP_TOKEN",
    "NOTE_EMPTY_HISTORY",
    "OUT_OF_SCOPE_COLUMNS",
    "OUT_OF_SCOPE_VENDORS",
    "POLICY_COLUMNS",
    "RUN_COLUMNS",
    "SECTION_BY_DEVICE",
    "SECTION_BY_POLICY",
    "SECTION_BY_SEVERITY",
    "SECTION_OUT_OF_SCOPE",
    "SECTION_RUNS",
    "SECTION_TREND",
    "SEVERITY_COLUMNS",
    "TREND_COLUMNS",
    "build_compliance_posture_sections",
]

#: Explicit trend gap marker: a day with no recorded run is UNKNOWN posture —
#: rendered as this token, never as a fabricated zero (a plain word so the CSV
#: formula-neutralizer leaves it untouched).
GAP_TOKEN: Final = "gap"

#: Placeholder for absent metadata dimensions (matches the change report).
_NONE: Final = "none"

#: Vendors with NO text-config compliance surface in P4 — the named deferrals
#: both plugin ADRs record. Shown as out-of-scope, never passing.
OUT_OF_SCOPE_VENDORS: Final[tuple[tuple[str, str], ...]] = (
    (
        "f5_bigip",
        "out-of-scope: no text-config surface in P4 (ADR-0050 §7.6 named deferral)",
    ),
    (
        "vmware",
        "out-of-scope: no config backup/drift surface in P4 (ADR-0051 §3 named deferral)",
    ),
)

SECTION_RUNS: Final = "Compliance evaluation runs"
SECTION_BY_POLICY: Final = "Latest posture by policy"
SECTION_BY_DEVICE: Final = "Latest posture by device"
SECTION_BY_SEVERITY: Final = "Latest posture by severity"
SECTION_TREND: Final = "Daily posture trend"
SECTION_OUT_OF_SCOPE: Final = "Out-of-scope vendors (no config-compliance surface)"

RUN_COLUMNS: Final = (
    "Run id",
    "Executed (UTC)",
    "Trigger",
    "Policy id",
    "Policy version",
    "Engine version",
    "Devices in scope",
)
POLICY_COLUMNS: Final = ("Policy id", "Pass", "Violation", "Skipped")
DEVICE_COLUMNS: Final = ("Device", "Vendor", "Pass", "Violation", "Skipped")
SEVERITY_COLUMNS: Final = ("Severity", "Pass", "Violation", "Skipped")
TREND_COLUMNS: Final = (
    "Date (UTC)",
    "Runs recorded",
    "Devices evaluated",
    "Pass",
    "Violation",
    "Skipped",
)
OUT_OF_SCOPE_COLUMNS: Final = ("Vendor", "Devices", "Posture")

NOTE_EMPTY_HISTORY: Final = "No compliance evaluation runs recorded in this period."
_NOTE_LATEST: Final = (
    "Latest-posture sections reflect the most recent compliance run in the period; "
    "counts are per rule-device evaluation (pass/violation/skipped, ADR-0018 §5), and "
    "every run row stamps the policy-pack and engine version in force (ADR-0053 §7.2)."
)
_NOTE_TREND: Final = (
    "Trend semantics: one row per UTC day in the period; a day's posture comes from its "
    "most recent recorded run. A day with no recorded run renders the explicit "
    f"'{GAP_TOKEN}' marker — posture values are never interpolated, smoothed, or carried "
    "forward across missing sweeps."
)
_NOTE_OUT_OF_SCOPE: Final = (
    "F5 BIG-IP and VMware vSphere have no text-configuration compliance surface in P4 "
    "(ADR-0050 §7.6, ADR-0051 §3 — named deferrals): their devices are out of scope for "
    "config compliance and are reported as uncovered, never as passing."
)
_NOTE_SECRET_FREE: Final = (
    "Persisted history carries status/severity only (ADR-0053 §6 layer 3): evidence "
    "excerpts are never stored and cannot appear in this report; live excerpt drill-down "
    "remains on the on-demand compliance endpoint under its own RBAC."
)


# ---------------------------------------------------------------------------
# Queries (allowlisted sources only; re-asserted on real PG in tests/pg/)
# ---------------------------------------------------------------------------


async def _load_runs(session: AsyncSession, start: datetime, end: datetime) -> list[ComplianceRun]:
    """Runs in the CLOSED-OPEN ``[start, end)``, oldest first (id tiebreak)."""
    stmt = (
        select(ComplianceRun)
        .where(ComplianceRun.executed_at >= start, ComplianceRun.executed_at < end)
        .order_by(ComplianceRun.executed_at, ComplianceRun.id)
    )
    return list((await session.execute(stmt)).scalars())


async def _grouped_status_counts(
    session: AsyncSession, run_id: uuid.UUID, dimension: Any
) -> dict[Any, dict[str, int]]:
    """``{dimension value: {status: count}}`` for one run (SQL GROUP BY)."""
    stmt = (
        select(dimension, ComplianceRunFinding.status, func.count())
        .where(ComplianceRunFinding.run_id == run_id)
        .group_by(dimension, ComplianceRunFinding.status)
    )
    grouped: dict[Any, dict[str, int]] = defaultdict(dict)
    for key, status, count in (await session.execute(stmt)).all():
        grouped[key][status] = count
    return dict(grouped)


async def _per_run_status_counts(
    session: AsyncSession, run_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, dict[str, int]]:
    """``{run_id: {status: count}}`` across *run_ids* (the trend aggregation)."""
    if not run_ids:
        return {}
    stmt = (
        select(ComplianceRunFinding.run_id, ComplianceRunFinding.status, func.count())
        .where(ComplianceRunFinding.run_id.in_(run_ids))
        .group_by(ComplianceRunFinding.run_id, ComplianceRunFinding.status)
    )
    grouped: dict[uuid.UUID, dict[str, int]] = defaultdict(dict)
    for run_id, status, count in (await session.execute(stmt)).all():
        grouped[run_id][status] = count
    return dict(grouped)


async def _load_devices(
    session: AsyncSession, device_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, Device]:
    ids = list(set(device_ids))
    if not ids:
        return {}
    rows = (await session.execute(select(Device).where(Device.id.in_(ids)))).scalars()
    return {device.id: device for device in rows}


async def _out_of_scope_device_counts(session: AsyncSession) -> dict[str, int]:
    """Inventory device count per out-of-scope vendor (metadata only)."""
    vendor_ids = [vendor for vendor, _ in OUT_OF_SCOPE_VENDORS]
    stmt = (
        select(Device.vendor_id, func.count())
        .where(Device.vendor_id.in_(vendor_ids))
        .group_by(Device.vendor_id)
    )
    return {vendor: count for vendor, count in (await session.execute(stmt)).all()}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _status_cells(counts: dict[str, int]) -> tuple[str, str, str]:
    """``(pass, violation, skipped)`` count cells in the pinned column order."""
    return (
        str(counts.get(FindingStatus.PASS.value, 0)),
        str(counts.get(FindingStatus.VIOLATION.value, 0)),
        str(counts.get(FindingStatus.SKIPPED.value, 0)),
    )


def _period_days(start: datetime, end: datetime) -> list[date]:
    """Every UTC calendar day whose midnight falls before *end*, from *start*."""
    days: list[date] = []
    cursor = start.date()
    while datetime(cursor.year, cursor.month, cursor.day, tzinfo=UTC) < end:
        days.append(cursor)
        cursor += timedelta(days=1)
    return days


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


async def build_compliance_posture_sections(
    session: AsyncSession, *, period_start: datetime, period_end: datetime
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    """Assemble the ADR-0053 §7.2 posture sections for one period.

    Naive period bounds are pinned as UTC (:func:`coerce_utc`) — the W3 sibling
    bug class: every boundary must interpret the same wall-clock period
    identically regardless of host timezone. Selection is CLOSED-OPEN over
    ``compliance_runs.executed_at``.

    Returns the six sections (stable titles/columns — the golden fixture and
    W4-T3 assert this structure) plus the payload notes.
    """
    start = coerce_utc(period_start)
    end = coerce_utc(period_end)

    runs = await _load_runs(session, start, end)
    latest = runs[-1] if runs else None

    run_rows = tuple(
        (
            str(run.id),
            coerce_utc(run.executed_at).isoformat(),
            run.trigger,
            run.policy_id,
            str(run.policy_version),
            run.engine_version,
            str(len(run.device_scope)),
        )
        for run in runs
    )

    # Latest-posture roll-ups exist ONLY when a run exists — an empty history
    # renders empty sections plus the explicit note, never fabricated zeros.
    policy_rows: tuple[tuple[str, ...], ...] = ()
    device_rows: tuple[tuple[str, ...], ...] = ()
    severity_rows: tuple[tuple[str, ...], ...] = ()
    if latest is not None:
        by_policy = await _grouped_status_counts(session, latest.id, ComplianceRunFinding.policy_id)
        policy_rows = tuple(
            (policy_id, *_status_cells(by_policy[policy_id])) for policy_id in sorted(by_policy)
        )

        by_device = await _grouped_status_counts(session, latest.id, ComplianceRunFinding.device_id)
        devices = await _load_devices(session, by_device.keys())
        labeled = sorted(
            (
                (
                    devices[device_id].hostname if device_id in devices else f"device:{device_id}",
                    (devices[device_id].vendor_id or _NONE) if device_id in devices else _NONE,
                    device_id,
                )
                for device_id in by_device
            ),
            key=lambda item: (item[0], str(item[2])),
        )
        device_rows = tuple(
            (label, vendor, *_status_cells(by_device[device_id]))
            for label, vendor, device_id in labeled
        )

        by_severity = await _grouped_status_counts(
            session, latest.id, ComplianceRunFinding.severity
        )
        severity_rows = tuple(
            (severity.value, *_status_cells(by_severity.get(severity.value, {})))
            for severity in Severity
        )

    per_run = await _per_run_status_counts(session, [run.id for run in runs])
    runs_by_day: dict[date, list[ComplianceRun]] = defaultdict(list)
    for run in runs:
        runs_by_day[coerce_utc(run.executed_at).date()].append(run)
    trend_rows: list[tuple[str, ...]] = []
    for day in _period_days(start, end):
        day_runs = runs_by_day.get(day)
        if not day_runs:
            # Zero runs is a MEASURED fact; the posture cells are unknowable.
            trend_rows.append((day.isoformat(), "0", GAP_TOKEN, GAP_TOKEN, GAP_TOKEN, GAP_TOKEN))
            continue
        day_latest = day_runs[-1]  # runs arrive (executed_at, id)-ordered
        trend_rows.append(
            (
                day.isoformat(),
                str(len(day_runs)),
                str(len(day_latest.device_scope)),
                *_status_cells(per_run.get(day_latest.id, {})),
            )
        )

    out_of_scope_counts = await _out_of_scope_device_counts(session)
    out_of_scope_rows = tuple(
        (vendor, str(out_of_scope_counts.get(vendor, 0)), posture)
        for vendor, posture in OUT_OF_SCOPE_VENDORS
    )

    sections = (
        ReportSection(title=SECTION_RUNS, columns=RUN_COLUMNS, rows=run_rows),
        ReportSection(title=SECTION_BY_POLICY, columns=POLICY_COLUMNS, rows=policy_rows),
        ReportSection(title=SECTION_BY_DEVICE, columns=DEVICE_COLUMNS, rows=device_rows),
        ReportSection(title=SECTION_BY_SEVERITY, columns=SEVERITY_COLUMNS, rows=severity_rows),
        ReportSection(title=SECTION_TREND, columns=TREND_COLUMNS, rows=tuple(trend_rows)),
        ReportSection(
            title=SECTION_OUT_OF_SCOPE, columns=OUT_OF_SCOPE_COLUMNS, rows=out_of_scope_rows
        ),
    )
    notes: tuple[str, ...] = (_NOTE_LATEST, _NOTE_TREND, _NOTE_OUT_OF_SCOPE, _NOTE_SECRET_FREE)
    if latest is None:
        notes = (NOTE_EMPTY_HISTORY, *notes)
    return sections, notes
