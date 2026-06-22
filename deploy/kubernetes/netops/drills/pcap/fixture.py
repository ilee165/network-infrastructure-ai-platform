"""Seeded throwaway fixture for the pcap spot-restore drill (ADR-0030 §5.4).

P1 ships a GREEN dry-run with NO hardware and NO live object store: this module
builds an in-memory async-SQLite ``pcap_metadata`` table (the REAL
:class:`app.models.pcap_metadata.PcapMetadata` model) seeded with exactly the two
cases the spec requires —

  * one LIVE (non-tombstoned, in-retention) capture whose pcap file is written to a
    throwaway temp dir so its capture-time sha256 (computed by the REAL
    ``app.engines.packet.capture.sha256_file``) round-trips through the restore;
  * one TOMBSTONED capture (file already purged, row tombstoned via the REAL
    ``app.engines.packet.capture.tombstone_capture``) that the snapshot must SKIP
    and the restore must NEVER resurrect.

The P2 annual run swaps this fixture for a real restore from the ``pcaps/`` prefix
to a throwaway target; the assertions in :mod:`pcap.assertions` are unchanged.

Reuse, not re-implementation (ADR-0023 §4): the tombstone state is produced by the
SAME ``tombstone_capture`` the platform purges with, and the live/expired worklist
by the SAME ``expired_capture_ids`` — the drill never re-derives retention.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import cast

from sqlalchemy import Table
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.engines.packet.capture import (
    DEFAULT_RETENTION_DAYS,
    expired_capture_ids,
    pcap_path_for,
    sha256_file,
    tombstone_capture,
)
from app.models.mixins import utcnow
from app.models.pcap_metadata import PcapMetadata

#: The bytes the LIVE fixture capture's pcap file holds (a tiny stand-in payload —
#: this is harness scratch, never a real packet capture). The sha256 of these
#: bytes is what the restore must reproduce.
_LIVE_PCAP_BYTES = b"\xd4\xc3\xb2\xa1drill-fixture-live-capture-payload"


@dataclass(frozen=True, slots=True)
class SeededPcapState:
    """Everything the pcap drill needs after the (simulated) snapshot + restore.

    Holds the throwaway DB sessionmaker, the on-disk pcap dir, and the two seeded
    capture ids (live + tombstoned) with the live capture's recorded sha256.
    """

    sessionmaker: async_sessionmaker[AsyncSession]
    pcap_dir: Path
    live_capture_id: uuid.UUID
    live_sha256: str
    live_pcap_path: str
    tombstoned_capture_id: uuid.UUID
    min_role: str = "engineer"


async def build_seeded_state(pcap_dir: Path, *, min_role: str = "engineer") -> SeededPcapState:
    """Build the throwaway DB + on-disk pcap files the drill runs against.

    Creates ONLY the ``pcap_metadata`` table (SQLite FK enforcement is off by
    default, so no User/Device rows are needed to satisfy the row's FKs — this is
    harness scratch). Seeds one LIVE capture (file present, in-retention) and one
    TOMBSTONED capture (file deleted, row tombstoned via the REAL model helper).

    Args:
        pcap_dir: A throwaway directory the live capture's pcap file is written to
            (the restore re-reads it to recompute the sha256).
        min_role: The minimum role the restore is gated to (ADR-0023 §5).

    Returns:
        The :class:`SeededPcapState`.
    """
    pcap_dir.mkdir(parents=True, exist_ok=True)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Create ONLY the pcap_metadata table — the drill touches no other model.
        await conn.run_sync(
            PcapMetadata.metadata.create_all,
            tables=[cast("Table", PcapMetadata.__table__)],
        )
    maker = async_sessionmaker(engine, expire_on_commit=False)

    now = utcnow()
    live_id = uuid.uuid4()
    tombstoned_id = uuid.uuid4()

    # Write the LIVE capture's pcap file and hash it with the REAL integrity hasher
    # (the same sha256_file the platform records at capture-complete).
    live_path = pcap_path_for(live_id, pcap_dir=pcap_dir)
    Path(live_path).write_bytes(_LIVE_PCAP_BYTES)
    live_sha = sha256_file(live_path)

    async with maker() as session:
        # LIVE capture: in-retention, not tombstoned, file present.
        session.add(
            PcapMetadata(
                capture_id=live_id,
                interface="Ethernet1",
                requester_id=uuid.uuid4(),
                started_at=now - timedelta(hours=1),
                ended_at=now - timedelta(minutes=55),
                byte_count=len(_LIVE_PCAP_BYTES),
                packet_count=1,
                sha256=live_sha,
                storage_path=live_path,
                retention_expires_at=now + timedelta(days=DEFAULT_RETENTION_DAYS),
            )
        )
        # TOMBSTONED capture: seeded as past-retention so the REAL retention helpers
        # can act on it, then tombstoned via the REAL tombstone_capture (its file is
        # already gone — a purged payload that must never come back).
        session.add(
            PcapMetadata(
                capture_id=tombstoned_id,
                interface="Ethernet2",
                requester_id=uuid.uuid4(),
                started_at=now - timedelta(days=DEFAULT_RETENTION_DAYS + 2),
                ended_at=now - timedelta(days=DEFAULT_RETENTION_DAYS + 2),
                byte_count=2048,
                packet_count=2,
                sha256="e" * 64,
                storage_path=pcap_path_for(tombstoned_id, pcap_dir=pcap_dir),
                retention_expires_at=now - timedelta(days=2),
            )
        )
        await session.flush()

        # Tombstone it via the REAL model helper — this is the SAME call the
        # platform retention beat makes (ADR-0023 §4); no re-implementation.
        await tombstone_capture(session, capture_id=tombstoned_id, reason="retention_expired")
        await session.commit()

    return SeededPcapState(
        sessionmaker=maker,
        pcap_dir=pcap_dir,
        live_capture_id=live_id,
        live_sha256=live_sha,
        live_pcap_path=live_path,
        tombstoned_capture_id=tombstoned_id,
        min_role=min_role,
    )


async def live_snapshot_ids(state: SeededPcapState) -> set[uuid.UUID]:
    """The capture ids a retention-honoring snapshot would COPY (live only).

    REUSES the model: a row is snapshot-eligible iff it is NOT tombstoned. The
    purge worklist (``expired_capture_ids``) is the inverse signal — anything it
    would purge is excluded. This is the live-vs-tombstoned decision the snapshot
    CronJob makes, computed by the same code (no duplicated retention logic).
    """
    async with state.sessionmaker() as session:
        from sqlalchemy import select

        rows = list(
            (
                await session.execute(
                    select(PcapMetadata.capture_id).where(PcapMetadata.tombstoned_at.is_(None))
                )
            ).scalars()
        )
        # A row can be NON-tombstoned yet PAST retention (the live purge worklist):
        # it is about to be purged and must NOT be a snapshot candidate. Exclude it
        # via the SAME expired_capture_ids worklist the snapshot/prune uses — so the
        # retention proof is not weakened by an expired-but-not-yet-tombstoned leak.
        expired = set(await expired_capture_ids(session))
        return {capture_id for capture_id in rows if capture_id not in expired}


async def tombstoned_capture_ids(state: SeededPcapState) -> set[uuid.UUID]:
    """The capture ids that are tombstoned OR past retention (must NOT resurrect).

    Combines the rows the model has already tombstoned with the live purge worklist
    ``expired_capture_ids`` (past-retention, not-yet-tombstoned) — the union is the
    "must-not-resurrect" set the restore guard checks against.
    """
    async with state.sessionmaker() as session:
        from sqlalchemy import select

        already = (
            await session.execute(
                select(PcapMetadata.capture_id).where(PcapMetadata.tombstoned_at.is_not(None))
            )
        ).scalars()
        worklist = await expired_capture_ids(session)
        return set(already) | set(worklist)
