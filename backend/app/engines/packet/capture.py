"""Packet-capture orchestration + pcap ingest/retention (M5; ADR-0023 §2/§3/§4).

Pure logic over the persistence layer and over filename/argv construction — no
Celery, no subprocess execution, no SSH (those live in
:mod:`app.workers.tasks.packet`). This module:

1. **builds capture argv/commands** for the two M5 capture mechanisms — worker
   side ``tcpdump`` (:func:`build_tcpdump_argv`) and ``eos`` device-side
   monitor-session capture (:func:`build_eos_capture_commands`) — as **argv
   lists / discrete CLI lines**, never shell strings. The interface name and the
   (already-whitelisted) BPF filter are discrete elements, so an untrusted
   interface/filter cannot smuggle a shell command or an extra flag (ADR-0023
   §1/§2). Both enforce the mandatory **duration cap (default 300 s)** and
   **size cap (default 50 MB)**.
2. **content-addresses + persists** a finished capture into ``pcap_metadata``
   (:func:`ingest_capture`): sha256 of the file (integrity, re-checked on
   download), byte/packet counts, storage path, and the retention clock.
3. **tombstones expired captures** (:func:`expired_capture_ids` +
   :func:`tombstone_capture`): retention finds rows past ``retention_expires_at``
   whose file is still present and, after the worker deletes the file, sets
   ``tombstoned_at`` + ``tombstoned_reason`` — the row is **never deleted** so the
   audit fact survives (ADR-0023 §4).

A pcap holds packet payloads (the most sensitive artifact class) — this module
never reads payload bytes; it hashes the file and records metadata only.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.packet.filters import FilterValidationError, validate_capture_filter
from app.models.mixins import utcnow
from app.models.pcap_metadata import PcapMetadata

__all__ = [
    "DEFAULT_PCAP_DIR",
    "MAX_DURATION_SECONDS",
    "MAX_SIZE_BYTES",
    "CaptureSpec",
    "build_eos_capture_commands",
    "build_eos_finalize_commands",
    "build_tcpdump_argv",
    "expired_capture_ids",
    "ingest_capture",
    "pcap_path_for",
    "tombstone_capture",
    "validate_interface",
]

logger = structlog.get_logger(__name__)

#: pcap files live on a dedicated disk volume (ADR-0023 §3); the worker resolves
#: the absolute root from settings — this is the documented default mount point.
DEFAULT_PCAP_DIR = "/data/pcaps"

#: Mandatory capture caps (ADR-0023 §2): a capture is a bounded, auto-reverting
#: diagnostic, so duration and size are always capped by the engine.
MAX_DURATION_SECONDS = 300
MAX_SIZE_BYTES = 50 * 1024 * 1024

#: Default retention window before a pcap file is purged (ADR-0023 §4).
DEFAULT_RETENTION_DAYS = 30

#: An interface name is an untrusted argv element. Allow only the characters real
#: NIC / device-port names use (``eth0``, ``Ethernet1/1``, ``ens192.100``) — no
#: shell metacharacters, no spaces, no leading dash (cannot become a flag).
_INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_./:-]{0,62}$")


class InterfaceValidationError(FilterValidationError):
    """An untrusted capture interface name failed the whitelist."""

    title = "Capture Interface Rejected"
    slug = "capture-interface-rejected"


def validate_interface(interface: str) -> str:
    """Validate an untrusted interface name; return it unchanged or raise.

    The name becomes one argv element of the ``tcpdump``/``eos`` capture command,
    so it must be a plain NIC/port identifier — no shell metacharacters, spaces,
    or a leading ``-`` (which could be parsed as a flag).

    :raises InterfaceValidationError: the name is empty or outside the whitelist.
    """
    if not _INTERFACE_RE.match(interface or ""):
        raise InterfaceValidationError(
            "capture interface name is not a valid NIC/port identifier "
            "(shell metacharacters, spaces, and leading dashes are rejected)"
        )
    return interface


@dataclass(frozen=True)
class CaptureSpec:
    """A validated, capped capture request (ADR-0023 §2).

    ``interface`` and ``capture_filter`` are validated on construction, and the
    duration/size are clamped to the engine caps — so a spec that reaches the
    argv builders is already safe and bounded.
    """

    interface: str
    capture_filter: str | None
    duration_seconds: int
    size_bytes: int

    @classmethod
    def create(
        cls,
        *,
        interface: str,
        capture_filter: str | None = None,
        duration_seconds: int = MAX_DURATION_SECONDS,
        size_bytes: int = MAX_SIZE_BYTES,
    ) -> CaptureSpec:
        """Validate inputs and clamp duration/size to the mandatory caps.

        :raises InterfaceValidationError: the interface name is rejected.
        :raises app.engines.packet.filters.FilterValidationError: the BPF filter
            is rejected (untrusted input — validated before any argv is built).
        :raises ValueError: a non-positive duration or size.
        """
        if duration_seconds <= 0 or size_bytes <= 0:
            raise ValueError("capture duration and size must be positive")
        return cls(
            interface=validate_interface(interface),
            capture_filter=validate_capture_filter(capture_filter),
            duration_seconds=min(duration_seconds, MAX_DURATION_SECONDS),
            size_bytes=min(size_bytes, MAX_SIZE_BYTES),
        )


def pcap_path_for(capture_id: UUID, *, pcap_dir: str | Path = DEFAULT_PCAP_DIR) -> str:
    """Deterministic on-volume path for a capture's pcap (``/{capture_id}.pcap``)."""
    return str(Path(pcap_dir) / f"{capture_id}.pcap")


def build_tcpdump_argv(spec: CaptureSpec, output_path: str | Path) -> list[str]:
    """Build the worker-side ``tcpdump`` capture **argv list** (never a shell line).

    ``-i <interface>`` selects the segment, ``-w <output_path>`` writes a standard
    pcap (Wireshark-compatible), ``-c``-free size/time bounding uses ``-G`` +
    ``-W 1`` (rotate once after the duration → stop) and a post-rotate guard, and
    a trailing validated BPF filter (if any) is appended as discrete argv
    elements. Every value is its own list element, so an untrusted interface or
    filter can never inject a flag or a shell command (ADR-0023 §1/§2).
    """
    argv = [
        "tcpdump",
        "-i",
        spec.interface,
        "-w",
        str(output_path),
        "-n",  # no name resolution at capture time either
        "-G",
        str(spec.duration_seconds),
        "-W",
        "1",  # rotate exactly once → tcpdump exits after one duration window
        "-C",
        str(max(1, spec.size_bytes // (1024 * 1024))),  # size cap in MB
    ]
    if spec.capture_filter is not None:
        # The BPF filter is the trailing positional expression; split on
        # whitespace so each token is its own argv element (validated above).
        argv += spec.capture_filter.split()
    return argv


#: Name of the EOS monitor-capture point this engine drives.
_EOS_CAPTURE_POINT = "netops"


def build_eos_capture_commands(spec: CaptureSpec, remote_path: str) -> list[str]:
    """Build the Arista ``eos`` device-side monitor-session **setup+start** lines.

    Returns the discrete EOS CLI command strings (run one-per-line over the SSH
    transport, never concatenated into a shell) that configure the capture point
    on the validated interface, apply the capped duration/size, and **start** the
    capture — the last line is always ``monitor capture netops start``.

    ``start`` is non-blocking on EOS, so the capture must be allowed to run for
    ``spec.duration_seconds`` before it is stopped; this builder therefore does
    **not** emit ``stop``/``copy`` (an adjacent ``stop`` would terminate the
    session before any traffic is captured and defeat ``limit duration``). The
    worker waits the duration and then sends :func:`build_eos_finalize_commands`.
    Each interface/filter value is already whitelisted, so no command line is
    attacker-constructible (ADR-0023 §2). *remote_path* is accepted for symmetry
    and used by the finalize step.
    """
    point = _EOS_CAPTURE_POINT
    commands = [
        f"monitor capture {point} interface {spec.interface} both",
    ]
    if spec.capture_filter is not None:
        commands.append(f"monitor capture {point} match ipall {spec.capture_filter}")
    commands += [
        f"monitor capture {point} limit duration {spec.duration_seconds}",
        f"monitor capture {point} limit packet-length 0 size {spec.size_bytes}",
        f"monitor capture {point} start",
    ]
    return commands


def build_eos_finalize_commands(remote_path: str) -> list[str]:
    """Build the EOS ``stop`` + ``copy`` lines, sent only **after** the dwell.

    The worker issues these once the capture has run for ``duration_seconds`` (or
    the device's own ``limit duration`` has auto-stopped it): stop the capture
    point, then write the staged pcap to *remote_path* for retrieval. Kept
    separate from :func:`build_eos_capture_commands` so ``stop`` can never be sent
    adjacent to ``start`` (ADR-0023 §2).
    """
    point = _EOS_CAPTURE_POINT
    return [
        f"monitor capture {point} stop",
        f"copy capture {point} {remote_path}",
    ]


def sha256_file(path: str | Path) -> str:
    """SHA-256 of a file's bytes (integrity hash; re-checked on download)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


async def ingest_capture(
    session: AsyncSession,
    *,
    capture_id: UUID,
    requester_id: UUID,
    interface: str,
    storage_path: str,
    sha256: str,
    byte_count: int,
    packet_count: int | None,
    started_at: datetime,
    ended_at: datetime | None,
    device_id: UUID | None = None,
    capture_filter: str | None = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> PcapMetadata:
    """Persist one finished capture's metadata row (ADR-0023 §3).

    Records the integrity ``sha256``, byte/packet counts, the on-volume
    ``storage_path``, and the retention clock (``retention_expires_at =
    started_at + retention_days``). The caller owns the transaction boundary
    (this only flushes), so the metadata row commits atomically with the audit
    entry the worker writes alongside it. ``device_id`` is ``None`` for a
    worker-side ``tcpdump`` capture (segment, not a device).
    """
    metadata = PcapMetadata(
        capture_id=capture_id,
        device_id=device_id,
        interface=interface,
        capture_filter=capture_filter,
        requester_id=requester_id,
        started_at=started_at,
        ended_at=ended_at,
        byte_count=byte_count,
        packet_count=packet_count,
        sha256=sha256,
        storage_path=storage_path,
        retention_expires_at=started_at + timedelta(days=retention_days),
    )
    session.add(metadata)
    await session.flush()
    logger.info(
        "packet.capture_ingested",
        capture_id=str(capture_id),
        device_id=str(device_id) if device_id is not None else None,
        byte_count=byte_count,
        packet_count=packet_count,
        sha256=sha256,
    )
    return metadata


async def expired_capture_ids(session: AsyncSession, *, now: datetime | None = None) -> list[UUID]:
    """Capture ids past retention and not yet tombstoned (the purge worklist)."""
    cutoff = now or utcnow()
    rows = (
        await session.execute(
            select(PcapMetadata.capture_id).where(
                PcapMetadata.retention_expires_at < cutoff,
                PcapMetadata.tombstoned_at.is_(None),
            )
        )
    ).scalars()
    return list(rows)


async def tombstone_capture(
    session: AsyncSession,
    *,
    capture_id: UUID,
    reason: str = "retention_expired",
    now: datetime | None = None,
) -> PcapMetadata | None:
    """Tombstone a capture's metadata row (set tombstoned_at + reason).

    The row is **never deleted** (ADR-0023 §4): only the file is removed (by the
    worker, before this call); the metadata survives so the audit fact "a capture
    existed and was purged" persists. Returns the row, or ``None`` if no such
    (un-tombstoned) capture exists.
    """
    row = (
        await session.execute(
            select(PcapMetadata).where(
                PcapMetadata.capture_id == capture_id,
                PcapMetadata.tombstoned_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    row.tombstoned_at = now or utcnow()
    row.tombstoned_reason = reason
    await session.flush()
    logger.info(
        "packet.capture_tombstoned",
        capture_id=str(capture_id),
        reason=reason,
    )
    return row
