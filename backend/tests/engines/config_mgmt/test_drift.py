"""Drift detection engine (M4; ADR-0017 §4) — baseline vs current diff.

Drift = a unified ``difflib`` diff of a device's *current* snapshot against its
*approved baseline* snapshot, computed over the RAW (unredacted) config text for
server-side fidelity. A clean device (current == baseline) drifts on nothing; an
out-of-band changed line surfaces as exactly that hunk. Establishing a baseline
is an explicit, audited action. In-memory aiosqlite, no Celery, no network.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.engines.config_mgmt.capture import capture_snapshot
from app.engines.config_mgmt.drift import (
    NoBaselineError,
    approve_baseline,
    detect_drift,
)
from app.models import AuditLog, Base, ConfigSnapshot, ConfigSource

RUNNING_CONFIG = (
    "hostname lab-sw-01\n"
    "!\n"
    "interface Gi0/1\n"
    " description uplink\n"
    "!\n"
    "snmp-server community public RO\n"
    "end\n"
)


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _disable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")  # device FK not exercised here
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


async def _capture(session: AsyncSession, *, device_id: uuid.UUID, config: str) -> ConfigSnapshot:
    result = await capture_snapshot(
        session, device_id=device_id, raw_config=config, source=ConfigSource.SCHEDULED
    )
    return result.snapshot


async def _audit_count(session: AsyncSession, action: str) -> int:
    result = await session.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == action)
    )
    return int(result.scalar_one())


# ---------------------------------------------------------------------------
# baseline approval — explicit + audited
# ---------------------------------------------------------------------------


async def test_approve_baseline_marks_snapshot_and_audits(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    snap = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)

    await approve_baseline(session, snapshot=snap, actor="engineer-1")
    await session.commit()

    assert snap.baseline is True
    assert await _audit_count(session, "config.baseline_approved") == 1


async def test_approve_baseline_supersedes_prior_baseline(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    first = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=first, actor="engineer-1")
    await session.commit()

    changed = RUNNING_CONFIG.replace("description uplink", "description core")
    second = await _capture(session, device_id=device_id, config=changed)
    await approve_baseline(session, snapshot=second, actor="engineer-1")
    await session.commit()

    await session.refresh(first)
    assert first.baseline is False
    assert second.baseline is True
    # exactly one baseline remains for the device
    result = await session.execute(
        select(func.count())
        .select_from(ConfigSnapshot)
        .where(
            ConfigSnapshot.device_id == device_id,
            ConfigSnapshot.baseline.is_(True),
        )
    )
    assert int(result.scalar_one()) == 1


async def test_audit_detail_never_carries_config_content(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    snap = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=snap, actor="engineer-1")
    await session.commit()

    entry = (
        await session.execute(select(AuditLog).where(AuditLog.action == "config.baseline_approved"))
    ).scalar_one()
    serialized = str(entry.detail)
    assert "snmp-server community public" not in serialized
    assert entry.detail is not None
    assert entry.detail["content_hash"] == snap.content_hash


# ---------------------------------------------------------------------------
# drift detection
# ---------------------------------------------------------------------------


async def test_no_baseline_raises(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await session.commit()

    with pytest.raises(NoBaselineError):
        await detect_drift(session, device_id=device_id, actor="engineer-1")


async def test_clean_device_has_no_drift(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    snap = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=snap, actor="engineer-1")
    await session.commit()

    result = await detect_drift(session, device_id=device_id, actor="engineer-1")

    assert result.has_drift is False
    assert result.diff == ""
    assert result.hunks == []
    assert result.baseline_hash == snap.content_hash
    assert result.current_hash == snap.content_hash


async def test_out_of_band_change_flags_exactly_that_hunk(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    baseline = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=baseline, actor="engineer-1")
    await session.commit()

    # Out-of-band change: a single line edited on the device.
    changed = RUNNING_CONFIG.replace("description uplink", "description HACKED")
    current = await _capture(session, device_id=device_id, config=changed)
    await session.commit()

    result = await detect_drift(session, device_id=device_id, actor="engineer-1")

    assert result.has_drift is True
    assert result.baseline_hash == baseline.content_hash
    assert result.current_hash == current.content_hash
    # exactly one changed hunk, containing precisely the changed line pair
    assert len(result.hunks) == 1
    hunk = result.hunks[0]
    assert "-    description uplink".replace("    ", " ") in hunk or "- description uplink" in hunk
    assert "+ description HACKED" in hunk
    # untouched lines must not appear as changes
    assert "-hostname lab-sw-01" not in result.diff
    assert "+hostname lab-sw-01" not in result.diff


async def test_diff_runs_over_raw_unredacted_text(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    baseline = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=baseline, actor="engineer-1")
    await session.commit()

    # A secret-bearing line changes out of band — fidelity requires it surface raw.
    changed = RUNNING_CONFIG.replace(
        "snmp-server community public RO", "snmp-server community s3cr3t RW"
    )
    await _capture(session, device_id=device_id, config=changed)
    await session.commit()

    result = await detect_drift(session, device_id=device_id, actor="engineer-1")

    assert result.has_drift is True
    assert "-snmp-server community public RO" in result.diff
    assert "+snmp-server community s3cr3t RW" in result.diff


async def test_detect_drift_records_audit_entry(session: AsyncSession) -> None:
    """detect_drift must write a CONFIG_SNAPSHOT_DRIFT_CHECKED audit row (ADR-0017 §2)."""
    from app.services.audit.service import CONFIG_SNAPSHOT_DRIFT_CHECKED

    device_id = uuid.uuid4()
    snap = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=snap, actor="engineer-1")
    await session.commit()

    result = await detect_drift(session, device_id=device_id, actor="engineer-2")
    await session.commit()

    assert await _audit_count(session, CONFIG_SNAPSHOT_DRIFT_CHECKED) == 1
    entry = (
        await session.execute(
            select(AuditLog).where(AuditLog.action == CONFIG_SNAPSHOT_DRIFT_CHECKED)
        )
    ).scalar_one()
    assert entry.actor == "engineer-2"
    assert entry.target_type == "config_snapshot"
    assert entry.target_id == str(snap.id)
    detail = entry.detail
    assert detail is not None
    assert detail["device_id"] == str(device_id)
    assert detail["baseline_hash"] == result.baseline_hash
    assert detail["current_hash"] == result.current_hash
    assert detail["has_drift"] is False
    assert detail["hunk_count"] == 0
    # config content must never enter the audit detail
    assert "snmp-server" not in str(detail)


async def test_detect_drift_audit_detail_never_carries_config_content(
    session: AsyncSession,
) -> None:
    """Audit detail for drift check must not include raw config text (ADR-0017 §2)."""
    from app.services.audit.service import CONFIG_SNAPSHOT_DRIFT_CHECKED

    device_id = uuid.uuid4()
    baseline_snap = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=baseline_snap, actor="engineer-1")
    await session.commit()

    changed = RUNNING_CONFIG.replace(
        "snmp-server community public RO", "snmp-server community s3cr3t RW"
    )
    await _capture(session, device_id=device_id, config=changed)
    await session.commit()

    await detect_drift(session, device_id=device_id, actor="engineer-2")
    await session.commit()

    entry = (
        await session.execute(
            select(AuditLog).where(AuditLog.action == CONFIG_SNAPSHOT_DRIFT_CHECKED)
        )
    ).scalar_one()
    serialized = str(entry.detail)
    assert "s3cr3t" not in serialized
    assert "public RO" not in serialized
    assert entry.detail is not None and entry.detail["has_drift"] is True


async def test_current_is_latest_non_baseline_snapshot(session: AsyncSession) -> None:
    device_id = uuid.uuid4()
    baseline = await _capture(session, device_id=device_id, config=RUNNING_CONFIG)
    await approve_baseline(session, snapshot=baseline, actor="engineer-1")
    await session.commit()

    first_change = RUNNING_CONFIG.replace("description uplink", "description one")
    await _capture(session, device_id=device_id, config=first_change)
    second_change = RUNNING_CONFIG.replace("description uplink", "description two")
    latest = await _capture(session, device_id=device_id, config=second_change)
    await session.commit()

    result = await detect_drift(session, device_id=device_id, actor="engineer-1")

    assert result.current_hash == latest.content_hash
    assert "+ description two" in result.diff
    assert "+ description one" not in result.diff
