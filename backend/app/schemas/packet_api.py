"""Packet capture / analysis API contracts (M5-T15): request/response models for
the ``/api/v1/agents/captures`` surface.

Pure data (D2): validation only, no I/O. A capture **launch** is asynchronous —
the route validates the spec, enqueues the worker-side ``tcpdump`` task on the
``packet`` queue, and returns the ``capture_id`` + a ``queued`` status; the
client polls the status endpoint for completion (ADR-0023 §2/§3, mirroring the
discovery run surface).

Data minimization (ADR-0023 §1): :class:`CaptureAnalysisRead` reuses the
engine's :class:`~app.engines.packet.analysis.PacketFindings` — top talkers,
protocol hierarchy, and coarse TCP-anomaly counts — **never raw packet bytes**.
Payload bytes never leave the sandbox worker.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CaptureLaunchRequest",
    "CaptureLaunchResponse",
    "CaptureStatus",
    "CaptureStatusResponse",
]


class CaptureStatus(StrEnum):
    """Lifecycle of a capture as surfaced by the API.

    ``queued`` — the worker task was enqueued and has not yet persisted metadata
    (no ``pcap_metadata`` row exists). ``completed`` — the worker captured and
    persisted the pcap metadata. ``tombstoned`` — the retention job purged the
    pcap file (the audited metadata row survives; the file is gone).
    """

    QUEUED = "queued"
    COMPLETED = "completed"
    TOMBSTONED = "tombstoned"


class CaptureLaunchRequest(BaseModel):
    """Body of ``POST /agents/captures``.

    ``interface`` is the segment/interface to capture on. ``capture_filter`` is
    an optional BPF filter; it is whitelist-validated at the route **before** any
    task is enqueued, so a dash-prefixed/injection token is rejected (422) rather
    than reaching the worker. ``device_id`` selects the device-side ``eos``
    monitor-session capture variant; when omitted, the worker-side ``tcpdump``
    segment capture runs.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    interface: str = Field(min_length=1, max_length=255)
    capture_filter: str | None = Field(default=None, max_length=1024)
    device_id: uuid.UUID | None = None
    duration_seconds: int | None = Field(default=None, ge=1, le=3600)
    size_bytes: int | None = Field(default=None, ge=1)


class CaptureLaunchResponse(BaseModel):
    """Result of ``POST /agents/captures``: the capture id + ``queued`` status.

    202-style contract (mirrors the discovery run surface): the capture happens
    asynchronously on the ``packet`` queue — poll
    ``GET /agents/captures/{capture_id}`` for lifecycle progress.
    """

    capture_id: uuid.UUID
    status: CaptureStatus = CaptureStatus.QUEUED
    interface: str
    device_id: uuid.UUID | None = None


class CaptureStatusResponse(BaseModel):
    """Metadata + lifecycle status for one capture (no raw pcap content)."""

    model_config = ConfigDict(from_attributes=True)

    capture_id: uuid.UUID
    status: CaptureStatus
    interface: str
    device_id: uuid.UUID | None = None
    byte_count: int | None = None
    packet_count: int | None = None
    sha256: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    retention_expires_at: datetime
    tombstoned_at: datetime | None = None
