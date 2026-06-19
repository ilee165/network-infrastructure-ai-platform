"""pcap_metadata ORM roundtrip, FK integrity, and tombstone semantics (M5; ADR-0023).

Mirrors ``tests/models/test_config_mgmt.py``: in-memory aiosqlite, no
Postgres/Docker/network. pcap *files* live on a disk volume; this row is the
Postgres metadata + audit record. Retention NEVER hard-deletes the row — it
sets ``tombstoned_at`` + ``tombstoned_reason`` (ADR-0023 §4), so the audit fact
"a capture existed and was purged" survives the file's deletion.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Device, PcapMetadata, Role, User


async def _requester(session: AsyncSession) -> User:
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}")
    session.add(role)
    await session.flush()
    user = User(username=f"user-{uuid.uuid4().hex[:8]}", password_hash="x", role_id=role.id)
    session.add(user)
    await session.flush()
    return user


async def test_pcap_metadata_roundtrip(session: AsyncSession, device: Device) -> None:
    """A capture's metadata persists path/size/params/expiry and reloads."""
    requester = await _requester(session)
    started = datetime(2026, 6, 18, 4, 0, tzinfo=UTC)
    ended = started + timedelta(seconds=300)
    expires = started + timedelta(days=30)
    meta = PcapMetadata(
        capture_id=uuid.uuid4(),
        device_id=device.id,
        interface="Ethernet1",
        capture_filter="tcp port 443",
        requester_id=requester.id,
        started_at=started,
        ended_at=ended,
        byte_count=4096,
        packet_count=42,
        sha256="d" * 64,
        storage_path="/data/pcaps/abc.pcap",
        retention_expires_at=expires,
    )
    session.add(meta)
    await session.commit()

    reloaded = (
        await session.execute(
            select(PcapMetadata)
            .where(PcapMetadata.id == meta.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.device_id == device.id
    assert reloaded.interface == "Ethernet1"
    assert reloaded.capture_filter == "tcp port 443"
    assert reloaded.requester_id == requester.id
    assert reloaded.byte_count == 4096
    assert reloaded.packet_count == 42
    assert reloaded.sha256 == "d" * 64
    assert reloaded.storage_path == "/data/pcaps/abc.pcap"
    assert reloaded.retention_expires_at == expires
    # A fresh capture is not yet tombstoned (the file is still on the volume).
    assert reloaded.tombstoned_at is None
    assert reloaded.tombstoned_reason is None


async def test_pcap_metadata_device_id_nullable_for_worker_side_tcpdump(
    session: AsyncSession,
) -> None:
    """device_id is nullable — worker-side tcpdump captures have no device (ADR-0023 §3)."""
    requester = await _requester(session)
    started = datetime(2026, 6, 18, 4, 0, tzinfo=UTC)
    meta = PcapMetadata(
        capture_id=uuid.uuid4(),
        interface="eth0",
        capture_filter="udp port 53",
        requester_id=requester.id,
        started_at=started,
        retention_expires_at=started + timedelta(days=30),
        storage_path="/data/pcaps/seg.pcap",
        sha256="e" * 64,
    )
    session.add(meta)
    await session.commit()
    assert meta.device_id is None


async def test_pcap_metadata_requires_requester_fk(session: AsyncSession) -> None:
    """requester_id references users.id — an unknown requester violates the FK."""
    started = datetime(2026, 6, 18, 4, 0, tzinfo=UTC)
    session.add(
        PcapMetadata(
            capture_id=uuid.uuid4(),
            interface="eth0",
            requester_id=uuid.uuid4(),
            started_at=started,
            retention_expires_at=started + timedelta(days=30),
            storage_path="/data/pcaps/x.pcap",
            sha256="f" * 64,
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_pcap_metadata_requires_device_fk_when_set(session: AsyncSession) -> None:
    """When device_id is set it references devices.id — an unknown device is rejected."""
    requester = await _requester(session)
    started = datetime(2026, 6, 18, 4, 0, tzinfo=UTC)
    session.add(
        PcapMetadata(
            capture_id=uuid.uuid4(),
            device_id=uuid.uuid4(),
            interface="Ethernet1",
            requester_id=requester.id,
            started_at=started,
            retention_expires_at=started + timedelta(days=30),
            storage_path="/data/pcaps/y.pcap",
            sha256="a" * 64,
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_pcap_metadata_tombstone_preserves_row(session: AsyncSession) -> None:
    """Retention sets tombstoned_at + reason; the metadata row is NEVER deleted.

    ADR-0023 §4 / alt #2: tombstoning removes the sensitive payload (the file)
    while preserving the audited fact that a capture existed and was purged.
    """
    requester = await _requester(session)
    started = datetime(2026, 6, 1, 0, 0, tzinfo=UTC)
    meta = PcapMetadata(
        capture_id=uuid.uuid4(),
        interface="eth0",
        requester_id=requester.id,
        started_at=started,
        retention_expires_at=started + timedelta(days=30),
        storage_path="/data/pcaps/old.pcap",
        sha256="b" * 64,
    )
    session.add(meta)
    await session.commit()

    purged_at = datetime(2026, 6, 18, 0, 0, tzinfo=UTC)
    meta.tombstoned_at = purged_at
    meta.tombstoned_reason = "retention_expired"
    await session.commit()

    reloaded = (
        await session.execute(
            select(PcapMetadata)
            .where(PcapMetadata.id == meta.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.tombstoned_at == purged_at
    assert reloaded.tombstoned_reason == "retention_expired"
    # The row (the audit record) survives; only the file is gone.
    assert reloaded.storage_path == "/data/pcaps/old.pcap"


async def test_pcap_metadata_capture_id_unique(session: AsyncSession) -> None:
    """capture_id is unique — one metadata row per capture (file at /{capture_id}.pcap)."""
    requester = await _requester(session)
    started = datetime(2026, 6, 18, 4, 0, tzinfo=UTC)
    capture_id = uuid.uuid4()
    common = {
        "capture_id": capture_id,
        "interface": "eth0",
        "requester_id": requester.id,
        "started_at": started,
        "retention_expires_at": started + timedelta(days=30),
        "storage_path": "/data/pcaps/dup.pcap",
        "sha256": "c" * 64,
    }
    session.add(PcapMetadata(**common))
    await session.flush()
    session.add(PcapMetadata(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()
