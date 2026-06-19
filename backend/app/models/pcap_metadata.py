"""pcap capture metadata + retention/tombstone record (M5; ADR-0023, D14).

pcap *files* live on a dedicated disk volume at ``/data/pcaps/{capture_id}.pcap``
(Compose named volume / K8s PVC). This row is the Postgres metadata + audit
record for one capture: who requested it, on which device/interface, with what
filter, its byte/packet counts, the sha256 (integrity, re-checked on download),
the on-disk path, and the retention clock.

Retention (ADR-0023 §4): a beat job finds rows past ``retention_expires_at`` with
``tombstoned_at IS NULL``, deletes the file from the volume, and sets
``tombstoned_at`` + ``tombstoned_reason`` — the metadata row is **tombstoned,
never hard-deleted**, so the audited fact "a capture existed and was purged"
survives the removal of the sensitive payload (the file). A tombstoned capture's
download 404s; its row remains for audit.

Design decision (fixed): ``requester_id`` (FK ``users``) is always required;
``device_id`` (FK ``devices``) is **nullable** because worker-side ``tcpdump``
captures on a reachable segment have no device. Both target non-partitioned
tables, so both are real DB-level FKs. ``pcap_metadata`` is not partitioned (one
row per capture, bounded by retention).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import TimestampMixin, UtcDateTime, UuidPkMixin, utcnow

__all__ = ["PcapMetadata"]


class PcapMetadata(UuidPkMixin, TimestampMixin, Base):
    """Metadata + retention/audit record for one pcap capture (ADR-0023 §3).

    ``capture_id`` is the capture's stable reference (and names the file on the
    volume) — unique, one metadata row per capture. ``sha256`` is recorded at
    capture-complete and re-checked on download (integrity + audit). The
    ``tombstoned_*`` columns are set by the retention job; the row itself is
    never deleted (ADR-0023 §4).
    """

    __tablename__ = "pcap_metadata"
    __table_args__ = (UniqueConstraint("capture_id", name="uq_pcap_metadata_capture_id"),)

    capture_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    # Nullable: worker-side tcpdump captures a segment, not a device (ADR-0023 §3).
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id"), index=True)
    interface: Mapped[str] = mapped_column(String(255), nullable=False)
    capture_filter: Mapped[str | None] = mapped_column(Text)
    requester_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(UtcDateTime())
    byte_count: Mapped[int | None] = mapped_column(BigInteger)
    packet_count: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    retention_expires_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    tombstoned_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), index=True)
    tombstoned_reason: Mapped[str | None] = mapped_column(String(64))
