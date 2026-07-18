"""Compliance posture report on REAL PostgreSQL (P4 W3-T3; ADR-0053 §7.2).

Trend/window aggregation is exactly the class SQLite mismodels (P4-PLAN §0a),
so every report query re-asserts here against the migrated schema: the daily
trend aggregation across runs (including the explicit skipped-day gap), the
severity roll-up GROUP BY, the out-of-scope vendor classification, the empty
history posture, and the sweep's per-day idempotency (the deterministic
slot-UUID ``ON CONFLICT DO NOTHING`` — a semantics PG enforces for real).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.engines.reports import ENGINE_VERSION
from app.engines.reports.compliance_posture import (
    GAP_TOKEN,
    NOTE_EMPTY_HISTORY,
    SECTION_BY_DEVICE,
    SECTION_BY_SEVERITY,
    SECTION_OUT_OF_SCOPE,
    SECTION_TREND,
    build_compliance_posture_sections,
)
from app.engines.reports.payloads import ReportSection
from app.models import Device, DeviceStatus
from app.models.compliance_history import ComplianceRun, ComplianceRunFinding
from app.models.config_mgmt import ConfigSnapshot, ConfigSource
from app.workers.tasks import reports as report_tasks

pytestmark = pytest.mark.integration

_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 7, 8, tzinfo=UTC)

_CORE = uuid.UUID("00000000-0000-0000-0000-00000000d001")
_EDGE = uuid.UUID("00000000-0000-0000-0000-00000000d002")
_RUN_A = uuid.UUID("00000000-0000-0000-0000-00000000aa01")
_RUN_B = uuid.UUID("00000000-0000-0000-0000-00000000bb01")
_RUN_C = uuid.UUID("00000000-0000-0000-0000-00000000cc01")

_POLICY = "baseline-security"


def _device(device_id: uuid.UUID, hostname: str, mgmt_ip: str, vendor: str) -> Device:
    return Device(
        id=device_id,
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id=vendor,
        status=DeviceStatus.REACHABLE,
        site="hq",
    )


def _run(
    run_id: uuid.UUID,
    executed_at: datetime,
    trigger: str,
    policy_version: int,
    device_scope: list[str],
) -> ComplianceRun:
    return ComplianceRun(
        id=run_id,
        executed_at=executed_at,
        trigger=trigger,
        policy_id=_POLICY,
        policy_version=policy_version,
        device_scope=device_scope,
        engine_version=ENGINE_VERSION,
    )


def _finding(
    run_id: uuid.UUID, device_id: uuid.UUID, rule_id: str, status: str, severity: str
) -> ComplianceRunFinding:
    return ComplianceRunFinding(
        run_id=run_id,
        device_id=device_id,
        policy_id=_POLICY,
        rule_id=rule_id,
        status=status,
        severity=severity,
    )


def _section(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(s for s in sections if s.title == title)


async def _seed_history(session: AsyncSession) -> None:
    """The deterministic unit scenario: runs on 07-01 and 07-03, gaps between."""
    session.add_all(
        [
            _device(_CORE, "core-sw-01", "10.0.0.1", "cisco_ios"),
            _device(_EDGE, "edge-sw-01", "10.0.0.2", "eos"),
            _run(
                _RUN_A,
                datetime(2026, 7, 1, 4, 30, tzinfo=UTC),
                "sweep",
                3,
                [str(_CORE), str(_EDGE)],
            ),
            _finding(_RUN_A, _CORE, "rule-ssh", "pass", "violation"),
            _finding(_RUN_A, _CORE, "rule-telnet", "violation", "warn"),
            _finding(_RUN_A, _EDGE, "rule-ssh", "pass", "violation"),
            _finding(_RUN_A, _EDGE, "rule-banner", "skipped", "info"),
            _run(_RUN_B, datetime(2026, 7, 3, 4, 0, tzinfo=UTC), "on_demand", 4, [str(_CORE)]),
            _finding(_RUN_B, _CORE, "rule-ssh", "violation", "violation"),
            _run(
                _RUN_C,
                datetime(2026, 7, 3, 5, 0, tzinfo=UTC),
                "sweep",
                4,
                [str(_CORE), str(_EDGE)],
            ),
            _finding(_RUN_C, _CORE, "rule-ssh", "pass", "violation"),
            _finding(_RUN_C, _CORE, "rule-telnet", "violation", "warn"),
            _finding(_RUN_C, _EDGE, "rule-ssh", "violation", "violation"),
            _finding(_RUN_C, _EDGE, "rule-banner", "skipped", "info"),
        ]
    )
    await session.commit()


async def test_trend_aggregation_across_runs_with_explicit_gap_days(
    pg_session: AsyncSession,
) -> None:
    """The daily trend GROUP BY aggregates per run on PG; missing days stay gaps.

    Includes the offset-aware bucketing case: a run stamped 03:00+05:30 on
    07-05 is 21:30 UTC on 07-04 — PG's timestamptz round-trip must land it in
    the 07-04 bucket, never the 07-05 one.
    """
    await _seed_history(pg_session)
    offset = timezone(timedelta(hours=5, minutes=30))
    pg_session.add(
        _run(
            uuid.UUID("00000000-0000-0000-0000-00000000ee01"),
            datetime(2026, 7, 5, 3, 0, tzinfo=offset),
            "on_demand",
            4,
            [],
        )
    )
    await pg_session.commit()

    sections, _ = await build_compliance_posture_sections(
        pg_session, period_start=_PERIOD_START, period_end=_PERIOD_END
    )

    trend = _section(sections, SECTION_TREND).rows
    assert [row[0] for row in trend] == [f"2026-07-0{d}" for d in range(1, 8)]
    assert trend[0] == ("2026-07-01", "1", "2", "2", "1", "1")
    # 07-03: two runs recorded; the day's posture is its LATEST run (RUN_C).
    assert trend[2] == ("2026-07-03", "2", "2", "1", "2", "1")
    # The +05:30 run buckets into its UTC day (07-04), leaving 07-05 a gap.
    assert trend[3][:2] == ("2026-07-04", "1")
    assert trend[4] == ("2026-07-05", "0", GAP_TOKEN, GAP_TOKEN, GAP_TOKEN, GAP_TOKEN)
    # Skipped days render as explicit gaps — never interpolated zeros.
    for row in (trend[1], trend[5], trend[6]):
        assert row[1] == "0"
        assert row[2:] == (GAP_TOKEN,) * 4


async def test_severity_rollup_group_by_on_pg(pg_session: AsyncSession) -> None:
    await _seed_history(pg_session)

    sections, _ = await build_compliance_posture_sections(
        pg_session, period_start=_PERIOD_START, period_end=_PERIOD_END
    )

    assert _section(sections, SECTION_BY_SEVERITY).rows == (
        ("info", "0", "0", "1"),
        ("warn", "0", "1", "0"),
        ("violation", "1", "1", "0"),
    )


async def test_out_of_scope_classification_on_pg(pg_session: AsyncSession) -> None:
    """F5/VMware devices classify as out-of-scope and never enter posture rows."""
    await _seed_history(pg_session)
    pg_session.add_all(
        [
            _device(
                uuid.UUID("00000000-0000-0000-0000-00000000d0f5"),
                "lb-01",
                "10.0.0.3",
                "f5_bigip",
            ),
            _device(
                uuid.UUID("00000000-0000-0000-0000-00000000d0ec"),
                "vcenter-01",
                "10.0.0.4",
                "vmware",
            ),
        ]
    )
    await pg_session.commit()

    sections, _ = await build_compliance_posture_sections(
        pg_session, period_start=_PERIOD_START, period_end=_PERIOD_END
    )

    rows = _section(sections, SECTION_OUT_OF_SCOPE).rows
    by_vendor = {row[0]: row for row in rows}
    assert by_vendor["f5_bigip"][1] == "1"
    assert by_vendor["vmware"][1] == "1"
    assert all("out-of-scope" in row[2] for row in rows)
    device_labels = {row[0] for row in _section(sections, SECTION_BY_DEVICE).rows}
    assert device_labels == {"core-sw-01", "edge-sw-01"}


async def test_empty_history_renders_note_and_all_gaps_on_pg(
    pg_session: AsyncSession,
) -> None:
    sections, notes = await build_compliance_posture_sections(
        pg_session, period_start=_PERIOD_START, period_end=_PERIOD_END
    )

    assert notes[0] == NOTE_EMPTY_HISTORY
    assert _section(sections, SECTION_BY_SEVERITY).rows == ()
    trend = _section(sections, SECTION_TREND).rows
    assert len(trend) == 7
    assert all(row[2:] == (GAP_TOKEN,) * 4 for row in trend)


# ---------------------------------------------------------------------------
# Sweep idempotency per day (the deterministic slot-UUID ON CONFLICT on PG)
# ---------------------------------------------------------------------------


def _wire_session(pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the worker's per-phase session seam at the REAL-PG engine."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _pg_session() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    monkeypatch.setattr(report_tasks, "_session", _pg_session)


async def test_sweep_is_idempotent_per_day_on_pg(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A redelivered daily sweep cannot double-write the day's history on PG.

    The run PK is the deterministic UTC-date slot UUID; the second delivery
    must classify the real ``ON CONFLICT DO NOTHING`` conflict as ``skipped``
    and leave BOTH tables unchanged (one run row, one finding set).
    """
    _wire_session(pg_engine, monkeypatch)
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        device = _device(_CORE, "core-sw-01", "10.0.0.1", "cisco_ios")
        session.add(device)
        # Flush the device BEFORE adding the snapshot: ConfigSnapshot carries a
        # raw ``device_id`` FK column with no relationship(), so the unit of
        # work has no flush-ordering edge between the two mappers — on real PG
        # the snapshot INSERT can be emitted first and trip the FK (caught on
        # the first real-PG run of this suite, W3-T4).
        await session.flush()
        session.add(
            ConfigSnapshot(
                device_id=_CORE,
                captured_at=datetime.now(UTC),
                source=ConfigSource.ON_DEMAND,
                content="hostname core-sw-01\nno service password-recovery\nend\n",
                content_hash="a" * 64,
            )
        )
        await session.commit()

    first = await report_tasks._compliance_sweep_core()
    assert first["status"] == "succeeded"
    assert first["devices"] == 1
    assert first["findings"] > 0

    second = await report_tasks._compliance_sweep_core()
    assert second["status"] == "skipped"
    assert second["run_id"] == first["run_id"]

    async with maker() as session:
        run_count = (await session.execute(select(func.count(ComplianceRun.id)))).scalar_one()
        finding_count = (
            await session.execute(select(func.count(ComplianceRunFinding.id)))
        ).scalar_one()
    assert run_count == 1
    assert finding_count == first["findings"]
