"""Audit-integrity report builder (P4 W3-T5; ADR-0053 §7.4, ADR-0038).

Surfaces the ADR-0038 audit spine as 7-year-capable evidence: per-day
hash-chain verification outcomes for the period (read from the PERSISTED
``audit_chain_verification_runs`` history the daily CronJob writes) plus the
**append-only grant attestation** — historical over the window from the daily
rows, AND re-run LIVE against the PostgreSQL catalog at generation time (the
G-SEC "append-only attested" criterion; never cached).

Honesty contracts this module owns:

* **History, not re-verification** — the report reads persisted outcomes only;
  generation never recomputes the chain, so report latency is independent of
  chain length (spec requirement 1 / named risk).
* **Gaps are findings** — a UTC day with no persisted verification run renders
  the explicit :data:`GAP_TOKEN` in the daily section AND raises an explicit
  :data:`FINDING_GAP` row: a verification that never ran is a finding, not a
  blank. Nothing is interpolated or carried forward.
* **Attestation is live** — :func:`check_audit_log_grants` runs against the PG
  catalog on EVERY generation (a cached result would let a transient
  ``UPDATE`` grant slip a period); on a backend with no grant catalog the
  outcome is the honest ``unavailable`` token, never a silent clean.
* **Digests allowed, secrets not** — checkpoint watermark values render as
  SHA-256 hex digest presentations; the ADR-0053 §6 redaction contract uses
  format-anchored secret patterns (no entropy detection) precisely so the
  platform's own integrity evidence renders unredacted.

Sources (§6 layer 1 allowlist): the §7.4 history table plus the PG catalog
(``pg_class``/``pg_roles`` metadata — relation/role names and privilege
keywords only). No secret-bearing surface is reachable from this module
(import-linter contract + ``tests/engines/reports/test_boundary.py``).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.reports.idempotency import coerce_utc
from app.engines.reports.payloads import ReportSection
from app.models.audit import (
    AuditChainVerificationRun,
    ChainVerificationOutcome,
    GrantCheckOutcome,
)
from app.services.audit.grants import check_audit_log_grants

__all__ = [
    "ATTESTATION_COLUMNS",
    "ATTEST_CLEAN",
    "ATTEST_UNAVAILABLE",
    "ATTEST_VIOLATION",
    "DAILY_COLUMNS",
    "FINDING_BREAK",
    "FINDING_COLUMNS",
    "FINDING_GAP",
    "FINDING_GRANT",
    "GAP_TOKEN",
    "GENERATION_TIME_SCOPE",
    "GENESIS_TOKEN",
    "NOTE_NO_FINDINGS",
    "RUN_COLUMNS",
    "SECTION_ATTESTATION",
    "SECTION_DAILY",
    "SECTION_FINDINGS",
    "SECTION_RUNS",
    "build_audit_integrity_sections",
]

SECTION_RUNS: Final = "Chain verification runs"
SECTION_DAILY: Final = "Daily verification outcomes"
SECTION_FINDINGS: Final = "Integrity findings"
SECTION_ATTESTATION: Final = "Append-only grant attestation (generation time)"

RUN_COLUMNS: Final = (
    "Started (UTC)",
    "Finished (UTC)",
    "Chain outcome",
    "Entries verified",
    "Verified from (entry id)",
    "Verified to (entry id)",
    "Checkpoint before (SHA-256)",
    "Checkpoint after (SHA-256)",
    "Append-only grant check",
)
DAILY_COLUMNS: Final = (
    "Date (UTC)",
    "Runs recorded",
    "Chain outcome",
    "Append-only grant check",
)
FINDING_COLUMNS: Final = ("Finding", "Scope", "Detail")
ATTESTATION_COLUMNS: Final = ("Field", "Value")

#: Explicit gap marker: a day with no persisted verification run is UNKNOWN —
#: rendered as this token AND raised as a finding, never left blank (a plain
#: word so the CSV formula-neutralizer leaves it untouched).
GAP_TOKEN: Final = "gap"

#: The walk's exclusive lower bound when no checkpoint anchored it (first run
#: or a full scan): the chain was verified from its genesis.
GENESIS_TOKEN: Final = "genesis"

#: Placeholder for absent values (matches the sibling reports).
_NONE: Final = "none"

#: Finding class tokens (the first column of :data:`SECTION_FINDINGS`).
FINDING_GAP: Final = "verification-gap"
FINDING_BREAK: Final = "chain-break"
FINDING_GRANT: Final = "append-only-grant"

#: Scope token for the generation-time attestation finding (vs a UTC day).
GENERATION_TIME_SCOPE: Final = "generation-time"

_DETAIL_GAP: Final = (
    "no hash-chain verification run was persisted for this day — the ADR-0038 daily "
    "verification did not run or did not record an outcome"
)
_DETAIL_BREAK: Final = "a hash-chain verification run detected a break on this day"
_DETAIL_GRANT_DAY: Final = (
    "the daily attestation found an UPDATE/DELETE grant on audit_log on this day"
)
_DETAIL_GRANT_LIVE: Final = (
    "the generation-time catalog check found an UPDATE/DELETE grant on audit_log"
)

ATTEST_CLEAN: Final = "clean: no UPDATE/DELETE grant exists on audit_log"
ATTEST_VIOLATION: Final = "VIOLATION: UPDATE/DELETE grants exist on audit_log"
ATTEST_UNAVAILABLE: Final = (
    "unavailable: this database backend exposes no grant catalog (non-PostgreSQL)"
)

NOTE_HISTORY: Final = (
    "Verification outcomes are read from the persisted audit_chain_verification_runs "
    "history written by the daily ADR-0038 verification job; generation never re-verifies "
    "the chain inline, so report latency is independent of chain length."
)
NOTE_GAPS: Final = (
    f"Gap semantics: one row per UTC day in the period; a day with no persisted "
    f"verification run renders the explicit '{GAP_TOKEN}' marker AND raises a "
    f"'{FINDING_GAP}' finding — a verification that never ran is a finding, not a blank. "
    "Nothing is interpolated or carried forward."
)
NOTE_ATTESTATION_LIVE: Final = (
    "The append-only grant attestation runs LIVE against the PostgreSQL catalog at every "
    "generation (never cached) and covers the audit_log parent and every partition; the "
    "persisted daily outcomes attest the same posture across the reporting window, so a "
    "transient grant mid-period surfaces as a failed day, never a clean report."
)
NOTE_OWNER_CAVEAT: Final = (
    "A REVOKE cannot bind the table owner or a superuser (the migration 0001 caveat): the "
    "attestation covers grantable UPDATE/DELETE privileges; the ADR-0038 hash chain — "
    "verified daily above — remains the tamper-evidence backstop for privileged actors."
)
NOTE_DIGESTS: Final = (
    "Checkpoint values are SHA-256 hex digest presentations of the hash-chain watermark — "
    "tamper evidence by design. The redaction contract (ADR-0053 §6) uses format-anchored "
    "secret patterns, deliberately not entropy detection, precisely so the platform's own "
    "integrity digests render unredacted."
)
NOTE_NO_FINDINGS: Final = (
    "No integrity findings in this period: every day carries a clean persisted "
    "verification outcome and no append-only grant violation was observed."
)

#: Worst-of ranking for a day's grant outcome (violation dominates).
_GRANT_RANK: Final[dict[str, int]] = {
    GrantCheckOutcome.CLEAN.value: 0,
    GrantCheckOutcome.UNAVAILABLE.value: 1,
    GrantCheckOutcome.VIOLATION.value: 2,
}


# ---------------------------------------------------------------------------
# Queries (allowlisted sources only; re-asserted on real PG in
# tests/pg/test_audit_integrity_pg.py)
# ---------------------------------------------------------------------------


async def _load_runs(
    session: AsyncSession, start: datetime, end: datetime
) -> list[AuditChainVerificationRun]:
    """Verification runs in the CLOSED-OPEN ``[start, end)``, oldest first."""
    stmt = (
        select(AuditChainVerificationRun)
        .where(
            AuditChainVerificationRun.started_at >= start,
            AuditChainVerificationRun.started_at < end,
        )
        .order_by(AuditChainVerificationRun.started_at, AuditChainVerificationRun.id)
    )
    return list((await session.execute(stmt)).scalars())


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _period_days(start: datetime, end: datetime) -> list[date]:
    """Every UTC calendar day FULLY CONTAINED in ``[start, end)``.

    A partial boundary day (``start``/``end`` not aligned to UTC midnight) is
    deliberately EXCLUDED here (PR #166 F2): the daily/gap evaluation below
    reads runs via the same *start*/*end* bounds, so a partial first day would
    have its early-morning runs excluded from THIS day's evidence purely
    because they fall before *start* — falsely rendering a real verification
    day as a gap (e.g. the window ``[07-01T12:00Z, 07-02T12:00Z)`` would
    otherwise report 2026-07-01 as a gap even though a run happened at
    07-01T03:00Z). Excluding an incomplete day renders no row for it at all —
    honest silence, never a false gap. Run-DETAIL rows (:data:`RUN_COLUMNS`)
    are unaffected: they still cover the full requested window as-is.
    """
    days: list[date] = []
    cursor = start.date()
    if datetime(cursor.year, cursor.month, cursor.day, tzinfo=UTC) < start:
        cursor += timedelta(days=1)
    while datetime(cursor.year, cursor.month, cursor.day, tzinfo=UTC) + timedelta(days=1) <= end:
        days.append(cursor)
        cursor += timedelta(days=1)
    return days


def _day_chain_outcome(day_runs: list[AuditChainVerificationRun]) -> str:
    """The day's chain outcome: ``break`` if ANY run broke, else ``clean``."""
    if any(run.outcome == ChainVerificationOutcome.BREAK.value for run in day_runs):
        return ChainVerificationOutcome.BREAK.value
    return ChainVerificationOutcome.CLEAN.value


def _day_grant_outcome(day_runs: list[AuditChainVerificationRun]) -> str:
    """The day's WORST grant outcome (violation > unavailable > clean)."""
    return max(
        (run.grant_check_outcome for run in day_runs),
        key=lambda outcome: _GRANT_RANK.get(outcome, 0),
    )


def _run_row(run: AuditChainVerificationRun) -> tuple[str, ...]:
    return (
        coerce_utc(run.started_at).isoformat(),
        coerce_utc(run.finished_at).isoformat(),
        run.outcome,
        str(run.entries_checked),
        str(run.range_from_entry_id) if run.range_from_entry_id is not None else GENESIS_TOKEN,
        str(run.range_to_entry_id) if run.range_to_entry_id is not None else _NONE,
        run.checkpoint_before_hash if run.checkpoint_before_hash is not None else _NONE,
        run.checkpoint_after_hash if run.checkpoint_after_hash is not None else _NONE,
        run.grant_check_outcome,
    )


def _attestation_text(outcome: str) -> str:
    if outcome == GrantCheckOutcome.VIOLATION.value:
        return ATTEST_VIOLATION
    if outcome == GrantCheckOutcome.UNAVAILABLE.value:
        return ATTEST_UNAVAILABLE
    return ATTEST_CLEAN


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


async def build_audit_integrity_sections(
    session: AsyncSession,
    *,
    period_start: datetime,
    period_end: datetime,
    generated_at: datetime,
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    """Assemble the ADR-0053 §7.4 audit-integrity sections for one period.

    Naive period bounds are pinned as UTC (:func:`coerce_utc`) — the W3 sibling
    bug class: every boundary must interpret the same wall-clock period
    identically regardless of host timezone. Selection is CLOSED-OPEN over
    ``audit_chain_verification_runs.started_at``.

    *generated_at* is the INJECTED generation timestamp (ADR-0053 §1
    determinism) — recorded as the attestation instant; the live catalog query
    itself runs here, per generation, never cached.

    Returns the four sections (stable titles/columns — the golden fixture and
    W4-T3 assert this structure) plus the payload notes.
    """
    start = coerce_utc(period_start)
    end = coerce_utc(period_end)

    runs = await _load_runs(session, start, end)
    run_rows = tuple(_run_row(run) for run in runs)

    runs_by_day: dict[date, list[AuditChainVerificationRun]] = defaultdict(list)
    for run in runs:
        runs_by_day[coerce_utc(run.started_at).date()].append(run)

    daily_rows: list[tuple[str, ...]] = []
    finding_rows: list[tuple[str, ...]] = []
    for day in _period_days(start, end):
        day_runs = runs_by_day.get(day)
        if not day_runs:
            # Zero runs is a MEASURED fact; the outcomes are unknowable — an
            # explicit gap marker plus an explicit finding, never a blank.
            daily_rows.append((day.isoformat(), "0", GAP_TOKEN, GAP_TOKEN))
            finding_rows.append((FINDING_GAP, day.isoformat(), _DETAIL_GAP))
            continue
        chain_outcome = _day_chain_outcome(day_runs)
        grant_outcome = _day_grant_outcome(day_runs)
        daily_rows.append((day.isoformat(), str(len(day_runs)), chain_outcome, grant_outcome))
        if chain_outcome == ChainVerificationOutcome.BREAK.value:
            finding_rows.append((FINDING_BREAK, day.isoformat(), _DETAIL_BREAK))
        if grant_outcome == GrantCheckOutcome.VIOLATION.value:
            finding_rows.append((FINDING_GRANT, day.isoformat(), _DETAIL_GRANT_DAY))

    # LIVE generation-time attestation (G-SEC): the catalog query runs on every
    # build — a cached result could let a granted UPDATE slip a period.
    attestation = await check_audit_log_grants(session)
    if attestation.outcome == GrantCheckOutcome.VIOLATION.value:
        finding_rows.append((FINDING_GRANT, GENERATION_TIME_SCOPE, _DETAIL_GRANT_LIVE))

    grants_cell = (
        "; ".join(
            f"{relation}: {grantee} ({privilege})"
            for relation, grantee, privilege in attestation.grants
        )
        if attestation.grants
        else _NONE
    )
    grants_found = (
        str(len(attestation.grants))
        if attestation.outcome != GrantCheckOutcome.UNAVAILABLE.value
        else GrantCheckOutcome.UNAVAILABLE.value
    )
    attestation_rows = (
        ("Table", "audit_log (parent and every partition)"),
        ("Attested at (UTC)", generated_at.isoformat()),
        (
            "Method",
            "live PostgreSQL catalog query (pg_class relacl via aclexplode) at "
            "generation time; never cached",
        ),
        ("UPDATE/DELETE grants found", grants_found),
        ("Grants", grants_cell),
        ("Attestation", _attestation_text(attestation.outcome)),
    )

    sections = (
        ReportSection(title=SECTION_RUNS, columns=RUN_COLUMNS, rows=run_rows),
        ReportSection(title=SECTION_DAILY, columns=DAILY_COLUMNS, rows=tuple(daily_rows)),
        ReportSection(title=SECTION_FINDINGS, columns=FINDING_COLUMNS, rows=tuple(finding_rows)),
        ReportSection(
            title=SECTION_ATTESTATION, columns=ATTESTATION_COLUMNS, rows=attestation_rows
        ),
    )

    notes: list[str] = [NOTE_HISTORY, NOTE_GAPS, NOTE_ATTESTATION_LIVE, NOTE_OWNER_CAVEAT]
    if not finding_rows:
        notes.append(NOTE_NO_FINDINGS)
    notes.append(NOTE_DIGESTS)
    return sections, tuple(notes)
