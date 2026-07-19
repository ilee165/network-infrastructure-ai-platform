"""Audit-integrity report on REAL PostgreSQL (P4 W3-T5; ADR-0053 §7.4).

The grant attestation is a PG-catalog query by NATURE — SQLite has no grant
catalog at all (spec requirement 5), and REVOKE/GRANT semantics are exactly
the class SQLite hides (the P2 lesson). Asserted here against the migrated
schema (partitioned ``audit_log`` + the migration 0001 REVOKE posture):

* the real CronJob path (:func:`app.services.audit.verify_job.run`) persists
  one ``audit_chain_verification_runs`` row per run with a REAL catalog
  attestation (``clean`` under the migration posture);
* a live ``GRANT UPDATE`` on ``audit_log`` flips the attestation to
  ``violation`` naming the grantee; ``REVOKE`` flips it back — and the report
  builder re-queries per generation (live, never cached: two builds straddling
  the REVOKE disagree);
* a grant planted DIRECTLY on a child partition (which does NOT inherit the
  parent ACL) is still detected — the pg_inherits walk bites;
* a COLUMN-level ``GRANT UPDATE (col)`` — stored in ``pg_attribute.attacl``,
  never ``pg_class.relacl`` — is detected on the parent and on a child
  partition (a relacl-only walk would attest a false ``clean`` while the
  grantee holds a working UPDATE path);
* gap days and break outcomes render as findings from the persisted history;
* the tamper failure path persists ``break`` while still exiting non-zero.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.engines.reports.audit_integrity import (
    ATTEST_CLEAN,
    ATTEST_VIOLATION,
    FINDING_BREAK,
    FINDING_GAP,
    GAP_TOKEN,
    SECTION_ATTESTATION,
    SECTION_DAILY,
    SECTION_FINDINGS,
    build_audit_integrity_sections,
)
from app.engines.reports.payloads import ReportSection
from app.models import (
    AuditChainVerificationRun,
    AuditLog,
    ChainVerificationOutcome,
    GrantCheckOutcome,
)
from app.services.audit import service as audit_service
from app.services.audit import verify_job
from app.services.audit.grants import check_audit_log_grants

pytestmark = pytest.mark.integration

_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 7, 4, tzinfo=UTC)
_GENERATED_AT = datetime(2026, 7, 4, 0, 5, tzinfo=UTC)

#: Throwaway probe role for the GRANT/REVOKE semantics tests. Never a real
#: principal; created and dropped inside each test.
_PROBE_ROLE = "netops_w3t5_grant_probe"


async def _seed_audit(maker: async_sessionmaker, n: int) -> list[AuditLog]:
    async with maker() as session:
        entries = []
        for i in range(n):
            entries.append(
                await audit_service.record(
                    session,
                    actor=f"user:{i}",
                    action=audit_service.DEVICE_UPDATED,
                    target_type="device",
                    target_id=str(i),
                    detail={"step": i},
                )
            )
        await session.commit()
        return entries


async def _drop_probe_role(pg_engine: AsyncEngine) -> None:
    """Drop the probe role if present (DROP OWNED first revokes its grants)."""
    async with pg_engine.begin() as conn:
        exists = (
            await conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :name"), {"name": _PROBE_ROLE}
            )
        ).scalar_one_or_none()
        if exists:
            await conn.execute(text(f"DROP OWNED BY {_PROBE_ROLE}"))
            await conn.execute(text(f"DROP ROLE {_PROBE_ROLE}"))


def _by_title(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(section for section in sections if section.title == title)


# ---------------------------------------------------------------------------
# CronJob persistence on real PG (real catalog attestation)
# ---------------------------------------------------------------------------


async def test_cronjob_persists_row_with_real_clean_attestation(
    pg_engine: AsyncEngine, tmp_path: Path
) -> None:
    """The job path persists one row per run and the REAL catalog check is
    `clean` under the migration 0001 REVOKE posture (no explicit grants)."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    entries = await _seed_audit(maker, 3)

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 0
    async with maker() as session:
        rows = list((await session.execute(select(AuditChainVerificationRun))).scalars())
    assert len(rows) == 1
    row = rows[0]
    assert row.outcome == ChainVerificationOutcome.CLEAN.value
    assert row.entries_checked == 3
    assert row.range_to_entry_id == entries[-1].id
    assert row.checkpoint_after_hash == entries[-1].entry_hash.hex()
    # REAL PG catalog: clean, not the SQLite `unavailable` fallback.
    assert row.grant_check_outcome == GrantCheckOutcome.CLEAN.value


async def test_tampered_run_persists_break_row_on_pg(
    pg_engine: AsyncEngine, tmp_path: Path
) -> None:
    """The failure path exits non-zero AND persists `break` (as the table
    owner, the harness can UPDATE despite the PUBLIC REVOKE — the 0001 caveat
    the hash chain exists to catch)."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    entries = await _seed_audit(maker, 4)
    target = entries[1]
    async with maker() as session:
        await session.execute(
            update(AuditLog)
            .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
            .values(actor="user:evil")
        )
        await session.commit()

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 1
    async with maker() as session:
        rows = list((await session.execute(select(AuditChainVerificationRun))).scalars())
    assert len(rows) == 1
    assert rows[0].outcome == ChainVerificationOutcome.BREAK.value


async def test_grant_check_statement_failure_still_persists_unavailable_row(
    pg_engine: AsyncEngine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A REAL statement failure inside the grant check must not poison the
    verification-history write (PR #166 F2, grant-check transaction poison).

    PostgreSQL aborts the WHOLE enclosing transaction on a failed statement —
    a plain Python-level monkeypatched raise does not reproduce this (SQLite
    would pass trivially with no fix at all); this plants a genuine SQL error
    (an undefined relation) so the session is truly poisoned. Without the
    SAVEPOINT fix, the checkpoint SELECT + history INSERT below also raise on
    the poisoned transaction, and the outer ``run()`` try/except only logs and
    swallows it — the honest ``unavailable`` row is silently lost.
    """
    from typing import NoReturn

    from sqlalchemy import text as sa_text

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    await _seed_audit(maker, 2)

    async def _raising_grant_check(session: AsyncSession) -> NoReturn:
        # A genuine SQL-level failure — PostgreSQL aborts the transaction.
        await session.execute(sa_text("SELECT * FROM this_table_does_not_exist"))
        raise AssertionError("unreachable")  # pragma: no cover

    monkeypatch.setattr(verify_job, "check_audit_log_grants", _raising_grant_check)

    code = await verify_job.run(sessionmaker=maker, textfile_dir=tmp_path)

    assert code == 0  # the chain itself is clean; only the attestation failed
    async with maker() as session:
        rows = list((await session.execute(select(AuditChainVerificationRun))).scalars())
    assert len(rows) == 1
    assert rows[0].outcome == ChainVerificationOutcome.CLEAN.value
    assert rows[0].grant_check_outcome == GrantCheckOutcome.UNAVAILABLE.value


# ---------------------------------------------------------------------------
# Grant attestation: REVOKE semantics + liveness (the P2 lesson class)
# ---------------------------------------------------------------------------


async def test_grant_attestation_detects_grant_and_honors_revoke(
    pg_engine: AsyncEngine, pg_session: AsyncSession
) -> None:
    """GRANT UPDATE flips the attestation to violation naming the grantee;
    REVOKE flips it back — and the builder re-queries PER GENERATION (two
    builds straddling the REVOKE disagree: live, never cached)."""
    await _drop_probe_role(pg_engine)
    async with pg_engine.begin() as conn:
        await conn.execute(text(f"CREATE ROLE {_PROBE_ROLE}"))
        await conn.execute(text(f"GRANT UPDATE ON audit_log TO {_PROBE_ROLE}"))
    try:
        granted = await check_audit_log_grants(pg_session)
        assert granted.outcome == GrantCheckOutcome.VIOLATION.value
        assert ("audit_log", _PROBE_ROLE, "UPDATE") in granted.grants

        sections, _ = await build_audit_integrity_sections(
            pg_session,
            period_start=_PERIOD_START,
            period_end=_PERIOD_END,
            generated_at=_GENERATED_AT,
        )
        attestation = dict(_by_title(sections, SECTION_ATTESTATION).rows)
        assert attestation["Attestation"] == ATTEST_VIOLATION
        assert _PROBE_ROLE in attestation["Grants"]

        async with pg_engine.begin() as conn:
            await conn.execute(text(f"REVOKE UPDATE ON audit_log FROM {_PROBE_ROLE}"))

        # LIVE per generation: the very next build sees the REVOKE.
        sections, _ = await build_audit_integrity_sections(
            pg_session,
            period_start=_PERIOD_START,
            period_end=_PERIOD_END,
            generated_at=_GENERATED_AT,
        )
        attestation = dict(_by_title(sections, SECTION_ATTESTATION).rows)
        assert attestation["Attestation"] == ATTEST_CLEAN
    finally:
        await _drop_probe_role(pg_engine)


async def test_grant_on_a_child_partition_is_detected(
    pg_engine: AsyncEngine, pg_session: AsyncSession
) -> None:
    """A partition does NOT inherit the parent ACL: a grant planted directly
    on a child must still break the attestation (the pg_inherits walk)."""
    child = (
        await pg_session.execute(
            text(
                "SELECT i.inhrelid::regclass::text FROM pg_inherits i "
                "WHERE i.inhparent = 'audit_log'::regclass ORDER BY 1 LIMIT 1"
            )
        )
    ).scalar_one_or_none()
    assert child is not None, "the migrated schema must carry audit_log partitions"

    await _drop_probe_role(pg_engine)
    async with pg_engine.begin() as conn:
        await conn.execute(text(f"CREATE ROLE {_PROBE_ROLE}"))
        await conn.execute(text(f"GRANT DELETE ON {child} TO {_PROBE_ROLE}"))
    try:
        result = await check_audit_log_grants(pg_session)
        assert result.outcome == GrantCheckOutcome.VIOLATION.value
        assert (child, _PROBE_ROLE, "DELETE") in result.grants
    finally:
        await _drop_probe_role(pg_engine)


async def test_column_level_update_grant_is_detected(
    pg_engine: AsyncEngine, pg_session: AsyncSession
) -> None:
    """``GRANT UPDATE (col)`` lives in ``pg_attribute.attacl``, NEVER in
    ``pg_class.relacl`` — yet it confers a working UPDATE path on the granted
    columns. A relacl-only walk attests a false ``clean`` (the W3-T5 review
    finding). Planted on the parent (two columns: the attestation must dedupe
    to ONE entry, not one per column) AND directly on a child partition."""
    child = (
        await pg_session.execute(
            text(
                "SELECT i.inhrelid::regclass::text FROM pg_inherits i "
                "WHERE i.inhparent = 'audit_log'::regclass ORDER BY 1 LIMIT 1"
            )
        )
    ).scalar_one_or_none()
    assert child is not None, "the migrated schema must carry audit_log partitions"

    await _drop_probe_role(pg_engine)
    async with pg_engine.begin() as conn:
        await conn.execute(text(f"CREATE ROLE {_PROBE_ROLE}"))
        await conn.execute(text(f"GRANT UPDATE (actor, action) ON audit_log TO {_PROBE_ROLE}"))
        await conn.execute(text(f"GRANT UPDATE (actor) ON {child} TO {_PROBE_ROLE}"))
    try:
        result = await check_audit_log_grants(pg_session)
        assert result.outcome == GrantCheckOutcome.VIOLATION.value
        assert ("audit_log", _PROBE_ROLE, "UPDATE") in result.grants
        assert (child, _PROBE_ROLE, "UPDATE") in result.grants
        # Two granted columns on the parent still attest as ONE offending
        # (relation, grantee, privilege) entry — per-column duplicates would
        # bloat the rendered compliance artifact.
        assert result.grants.count(("audit_log", _PROBE_ROLE, "UPDATE")) == 1
    finally:
        await _drop_probe_role(pg_engine)


# ---------------------------------------------------------------------------
# History rendering on real PG: gaps + break days are findings
# ---------------------------------------------------------------------------


async def test_gap_and_break_days_render_as_findings_on_pg(pg_session: AsyncSession) -> None:
    """Day 1 clean, day 2 MISSING, day 3 break → gap + break findings from the
    persisted history (the period/day aggregation on real PG timestamps)."""
    day1 = datetime(2026, 7, 1, 2, 0, tzinfo=UTC)
    day3 = datetime(2026, 7, 3, 2, 0, tzinfo=UTC)
    pg_session.add_all(
        [
            AuditChainVerificationRun(
                id=uuid.uuid4(),
                started_at=day1,
                finished_at=day1 + timedelta(minutes=1),
                outcome=ChainVerificationOutcome.CLEAN.value,
                entries_checked=5,
                grant_check_outcome=GrantCheckOutcome.CLEAN.value,
            ),
            AuditChainVerificationRun(
                id=uuid.uuid4(),
                started_at=day3,
                finished_at=day3 + timedelta(minutes=1),
                outcome=ChainVerificationOutcome.BREAK.value,
                entries_checked=1,
                grant_check_outcome=GrantCheckOutcome.CLEAN.value,
            ),
        ]
    )
    await pg_session.commit()

    sections, _ = await build_audit_integrity_sections(
        pg_session,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    daily = {row[0]: row for row in _by_title(sections, SECTION_DAILY).rows}
    assert daily["2026-07-02"][2] == GAP_TOKEN
    assert daily["2026-07-03"][2] == ChainVerificationOutcome.BREAK.value
    findings = {(row[0], row[1]) for row in _by_title(sections, SECTION_FINDINGS).rows}
    assert (FINDING_GAP, "2026-07-02") in findings
    assert (FINDING_BREAK, "2026-07-03") in findings


async def test_verification_history_is_append_only_on_pg(pg_session: AsyncSession) -> None:
    """Migration 0022 (PR #166 F3): the 7-year verification-history evidence
    table refuses UPDATE and DELETE at the database, mirroring the ``approvals``
    trigger (0009) and the ``audit_log`` REVOKE posture (0001).

    The audit-integrity report explicitly TRUSTS these persisted rows — without
    the trigger, a role holding UPDATE on app tables could rewrite a ``break``
    outcome to ``clean`` (or delete the row) with nothing detecting it. The
    refusal must BITE: each tamper statement raises the append-only trigger
    error, and the original row survives verbatim.
    """
    from sqlalchemy.exc import DBAPIError

    started = datetime(2026, 7, 1, 2, 0, tzinfo=UTC)
    row_id = uuid.uuid4()
    pg_session.add(
        AuditChainVerificationRun(
            id=row_id,
            started_at=started,
            finished_at=started + timedelta(minutes=1),
            outcome=ChainVerificationOutcome.BREAK.value,
            entries_checked=5,
            grant_check_outcome=GrantCheckOutcome.CLEAN.value,
        )
    )
    await pg_session.commit()

    # A break→clean rewrite is REFUSED by the trigger (not silently applied).
    with pytest.raises(DBAPIError, match="append-only"):
        await pg_session.execute(
            update(AuditChainVerificationRun)
            .where(AuditChainVerificationRun.id == row_id)
            .values(outcome=ChainVerificationOutcome.CLEAN.value)
        )
    await pg_session.rollback()

    # Deleting the evidence row is refused the same way.
    with pytest.raises(DBAPIError, match="append-only"):
        await pg_session.execute(text("DELETE FROM audit_chain_verification_runs"))
    await pg_session.rollback()

    persisted = (await pg_session.execute(select(AuditChainVerificationRun))).scalars().all()
    assert [(r.id, r.outcome) for r in persisted] == [
        (row_id, ChainVerificationOutcome.BREAK.value)
    ]
