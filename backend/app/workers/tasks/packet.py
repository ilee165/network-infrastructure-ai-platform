"""Celery packet tasks (M5-T8): capture + sandboxed analysis + retention on the
``packet`` queue (ADR-0008 D8, ADR-0023).

Four tasks, routed to the ``packet`` queue by name prefix:

- ``packet.capture_segment`` — worker-side ``tcpdump`` capture of a reachable
  segment (no device, ``device_id=None``). Runs the capped capture argv (built by
  the engine, never a shell), writes the pcap to the read-write volume, hashes
  it, and persists ``pcap_metadata``. This is the credential-free capture
  variant; the segment capture worker only needs host network access.

- ``packet.capture_device`` — ``eos`` device-side monitor-session capture: opens
  an SSH session (vault credential, like ``config.capture_device``), drives the
  EOS ``monitor capture`` CLI, retrieves the pcap to the volume, hashes it, and
  persists ``pcap_metadata``.

- ``packet.analyze_capture`` — **sandboxed** tshark analysis: reads the pcap
  **read-only**, runs tshark via an argv list (``shell=False``, ``-n``, validated
  display filter, hard timeout — :mod:`app.engines.packet.sandbox`), and stores
  normalized findings. This task holds **no credentials** and needs **no egress**;
  the OS sandbox (dropped caps, non-root, RO mount, limits) is the deployment's
  job — see ADR-0023 §1 and the dedicated ``packet``-analysis worker class.

- ``packet.purge_expired`` — Celery-beat retention job (ADR-0023 §4): finds
  captures past ``retention_expires_at``, deletes each pcap **file** from the
  volume, and tombstones (never deletes) its metadata row, audited.

Async DB from sync Celery follows the config/discovery pattern: each phase wraps
its DB work in ``asyncio.run`` with a fresh engine, and module-level seams
(``_make_engine``, ``_settings``, ``_open_ssh``, ``_run_tcpdump``,
``_analyze_pcap``, ``_delete_file``) let unit tests run everything eagerly with
the capture subprocess and tshark mocked.

Secret discipline (D11): the EOS capture credential plaintext lives only inside
the SSH session and never enters a log line, audit ``detail``, result payload, or
exception message. Packet *payloads* (the most sensitive artifact class) never
leave the sandbox: the analysis task stores only normalized aggregate findings,
never raw bytes (ADR-0023 §1).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app import db
from app.core.config import Settings, get_settings
from app.core.crypto import KeyProvider, get_key_provider
from app.engines.packet import (
    CaptureSpec,
    PacketFindings,
    analyze_pcap,
    build_eos_capture_commands,
    build_eos_finalize_commands,
    build_tcpdump_argv,
    expired_capture_ids,
    ingest_capture,
    pcap_path_for,
    tombstone_capture,
)
from app.engines.packet.capture import sha256_file
from app.models.mixins import utcnow
from app.models.pcap_metadata import PcapMetadata
from app.services import audit
from app.workers.celery_app import celery_app

__all__ = [
    "analyze_capture",
    "capture_device",
    "capture_segment",
    "purge_expired",
]

logger = structlog.get_logger(__name__)

#: Audit actor for the packet queue (capture/analysis) and the retention system.
_ACTOR = "worker:packet"
_RETENTION_ACTOR = "system:retention"

#: Packet-queue audit action vocabulary (worker-local, like the config queue).
_CAPTURE_COMPLETED = "packet.capture_completed"
_CAPTURE_FAILED = "packet.capture_failed"
_ANALYSIS_COMPLETED = "packet.analysis_completed"
_ANALYSIS_FAILED = "packet.analysis_failed"
_PCAP_PURGED = "pcap.purged"


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    return db.create_engine(get_settings())


def _settings() -> Settings:
    return get_settings()


def _key_provider() -> KeyProvider:
    return get_key_provider(get_settings())


def _run_tcpdump(argv: list[str]) -> None:
    """Execute the worker-side ``tcpdump`` capture argv (no shell).

    Seam: tests replace this so no real subprocess/NIC is touched. Production
    runs the capped argv built by the engine via ``subprocess.run`` with
    ``shell=False``.
    """
    import subprocess  # local import: capture-only dependency

    subprocess.run(argv, check=True, shell=False)  # noqa: S603 — argv list, validated, no shell


def _open_ssh(params: Any) -> Any:
    """Context-managed SSH transport (netmiko) for the EOS capture path."""
    from app.plugins.transport import SshTransport

    return SshTransport(params)


def _sleep(seconds: float) -> None:
    """Block for *seconds* (the EOS capture dwell).

    Seam: unit tests replace this so the capture-duration wait is instant. The
    EOS ``monitor capture ... start`` is non-blocking, so the worker must dwell
    the capped duration before issuing ``stop``/``copy`` (ADR-0023 §2).
    """
    import time  # local import: capture-only dependency

    time.sleep(seconds)


def _analyze_pcap(path: str, *, display_filter: str | None, settings: Settings) -> PacketFindings:
    """Run the sandboxed tshark analysis (seam: mocked in tests)."""
    return analyze_pcap(
        path,
        display_filter=display_filter,
        tshark_bin=settings.tshark_bin,
        timeout_seconds=settings.packet_analysis_timeout_seconds,
    )


def _delete_file(path: str) -> bool:
    """Delete a pcap file from the volume; return whether it was present."""
    try:
        os.remove(path)
    except FileNotFoundError:
        return False
    return True


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    engine = _make_engine()
    try:
        async with db.create_sessionmaker(engine)() as session:
            yield session
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CaptureRecord:
    capture_id: UUID
    storage_path: str
    sha256: str
    byte_count: int


async def _persist_capture(
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
    device_id: UUID | None,
    capture_filter: str | None,
    retention_days: int,
) -> None:
    """Persist the metadata row and audit the completed capture (atomic)."""
    async with _session() as session:
        metadata = await ingest_capture(
            session,
            capture_id=capture_id,
            requester_id=requester_id,
            interface=interface,
            storage_path=storage_path,
            sha256=sha256,
            byte_count=byte_count,
            packet_count=packet_count,
            started_at=started_at,
            ended_at=ended_at,
            device_id=device_id,
            capture_filter=capture_filter,
            retention_days=retention_days,
        )
        await audit.record(
            session,
            actor=_ACTOR,
            action=_CAPTURE_COMPLETED,
            target_type="pcap_metadata",
            target_id=str(metadata.id),
            detail={
                "capture_id": str(capture_id),
                "device_id": str(device_id) if device_id is not None else None,
                "interface": interface,
                "byte_count": byte_count,
                "sha256": sha256,
            },
        )
        await session.commit()


async def _audit_failure(
    *, capture_id: UUID, error: str, action: str, device_id: UUID | None
) -> None:
    """Append an audited capture/analysis failure (no secret/payload material)."""
    async with _session() as session:
        await audit.record(
            session,
            actor=_ACTOR,
            action=action,
            target_type="pcap_capture",
            target_id=str(capture_id),
            detail={
                "error": error,
                "device_id": str(device_id) if device_id is not None else None,
            },
        )
        await session.commit()


async def _audit_purge(*, capture_id: UUID, sha256: str | None, file_removed: bool) -> None:
    """Audit one retention purge (actor=system/retention, file hash)."""
    async with _session() as session:
        await audit.record(
            session,
            actor=_RETENTION_ACTOR,
            action=_PCAP_PURGED,
            target_type="pcap_metadata",
            target_id=str(capture_id),
            detail={"sha256": sha256, "file_removed": file_removed, "reason": "retention_expired"},
        )
        await session.commit()


async def _record_analysis(*, capture_id: UUID, findings: PacketFindings) -> None:
    """Audit a completed analysis (normalized counts only — never payload bytes)."""
    async with _session() as session:
        await audit.record(
            session,
            actor=_ACTOR,
            action=_ANALYSIS_COMPLETED,
            target_type="pcap_metadata",
            target_id=str(capture_id),
            detail={
                "capture_id": str(capture_id),
                "packet_count": findings.packet_count,
                "top_talker_count": len(findings.top_talkers),
                "tcp_resets": findings.tcp_resets,
                "tcp_retransmissions": findings.tcp_retransmissions,
            },
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Task: packet.capture_segment (worker-side tcpdump)
# ---------------------------------------------------------------------------


@celery_app.task(name="packet.capture_segment")
def capture_segment(
    requester_id: str,
    interface: str,
    capture_filter: str | None = None,
    duration_seconds: int | None = None,
    size_bytes: int | None = None,
    capture_id: str | None = None,
) -> dict[str, Any]:
    """Capture a reachable segment with worker-side ``tcpdump`` (no device).

    Validates + caps the spec (engine), runs the capture argv with no shell,
    hashes the resulting pcap, and persists ``pcap_metadata`` with
    ``device_id=None``. Returns a JSON-safe summary. A validation/capture failure
    is audited and returned as ``ok=False`` (no exception escapes to the caller).

    ``capture_id`` is optional: the API launch path (M5-T15) allocates the id up
    front so the launch response, the status endpoint, and the persisted metadata
    all share one capture reference; when omitted (beat/other callers) a fresh id
    is generated.
    """
    settings = _settings()
    capture_id = uuid.UUID(capture_id) if capture_id else uuid.uuid4()
    storage_path = pcap_path_for(capture_id, pcap_dir=settings.pcap_dir)
    started_at = utcnow()
    try:
        spec = CaptureSpec.create(
            interface=interface,
            capture_filter=capture_filter,
            duration_seconds=duration_seconds or settings.packet_capture_duration_seconds,
            size_bytes=size_bytes or settings.packet_capture_size_bytes,
        )
        argv = build_tcpdump_argv(spec, storage_path)
        _run_tcpdump(argv)
        byte_count = os.path.getsize(storage_path)
        sha256 = sha256_file(storage_path)
    except Exception as exc:  # noqa: BLE001 — capture/validation failure is audited, not raised
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("packet.segment_capture_failed", capture_id=str(capture_id), error=error)
        asyncio.run(
            _audit_failure(
                capture_id=capture_id, error=error, action=_CAPTURE_FAILED, device_id=None
            )
        )
        return {"ok": False, "capture_id": str(capture_id), "error": error}

    asyncio.run(
        _persist_capture(
            capture_id=capture_id,
            requester_id=uuid.UUID(requester_id),
            interface=spec.interface,
            storage_path=storage_path,
            sha256=sha256,
            byte_count=byte_count,
            packet_count=None,
            started_at=started_at,
            ended_at=utcnow(),
            device_id=None,
            capture_filter=spec.capture_filter,
            retention_days=settings.pcap_retention_days,
        )
    )
    logger.info("packet.segment_captured", capture_id=str(capture_id), byte_count=byte_count)
    return {
        "ok": True,
        "capture_id": str(capture_id),
        "storage_path": storage_path,
        "sha256": sha256,
        "byte_count": byte_count,
    }


# ---------------------------------------------------------------------------
# Task: packet.capture_device (eos monitor-session)
# ---------------------------------------------------------------------------


@celery_app.task(name="packet.capture_device")
def capture_device(
    requester_id: str,
    device_id: str,
    interface: str,
    capture_filter: str | None = None,
    duration_seconds: int | None = None,
    size_bytes: int | None = None,
    capture_id: str | None = None,
) -> dict[str, Any]:
    """Capture on an ``eos`` device via a monitor session, retrieve the pcap.

    Loads the device's SSH credential, drives the EOS ``monitor capture`` CLI
    (commands built by the engine — discrete CLI lines, never a shell string),
    retrieves the pcap to the volume, hashes it, and persists ``pcap_metadata``.
    The EOS retrieval mechanics run through the ``_open_ssh`` seam; only the
    metadata path is exercised in unit tests (transport faked).

    ``capture_id`` is optional: the API launch path (M5-T15) allocates it up
    front so the launch response and the persisted metadata share one reference;
    when omitted a fresh id is generated.
    """
    settings = _settings()
    capture_id = uuid.UUID(capture_id) if capture_id else uuid.uuid4()
    device_uuid = uuid.UUID(device_id)
    storage_path = pcap_path_for(capture_id, pcap_dir=settings.pcap_dir)
    started_at = utcnow()
    try:
        spec = CaptureSpec.create(
            interface=interface,
            capture_filter=capture_filter,
            duration_seconds=duration_seconds or settings.packet_capture_duration_seconds,
            size_bytes=size_bytes or settings.packet_capture_size_bytes,
        )
        remote_path = f"flash:netops-{capture_id}.pcap"
        _drive_eos_capture(device_uuid, spec, remote_path, storage_path)
        byte_count = os.path.getsize(storage_path)
        sha256 = sha256_file(storage_path)
    except Exception as exc:  # noqa: BLE001 — failure is audited, not raised
        error = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "packet.device_capture_failed", capture_id=str(capture_id), error=error
        )
        asyncio.run(
            _audit_failure(
                capture_id=capture_id,
                error=error,
                action=_CAPTURE_FAILED,
                device_id=device_uuid,
            )
        )
        return {"ok": False, "capture_id": str(capture_id), "error": error}

    asyncio.run(
        _persist_capture(
            capture_id=capture_id,
            requester_id=uuid.UUID(requester_id),
            interface=spec.interface,
            storage_path=storage_path,
            sha256=sha256,
            byte_count=byte_count,
            packet_count=None,
            started_at=started_at,
            ended_at=utcnow(),
            device_id=device_uuid,
            capture_filter=spec.capture_filter,
            retention_days=settings.pcap_retention_days,
        )
    )
    logger.info("packet.device_captured", capture_id=str(capture_id), byte_count=byte_count)
    return {
        "ok": True,
        "capture_id": str(capture_id),
        "storage_path": storage_path,
        "sha256": sha256,
        "byte_count": byte_count,
    }


def _drive_eos_capture(
    device_id: UUID, spec: CaptureSpec, remote_path: str, storage_path: str
) -> None:
    """Run the EOS capture CLI lines over SSH, dwell, then retrieve the pcap.

    ``monitor capture ... start`` is non-blocking on EOS, so this drives the
    capture in two phases: send the setup+``start`` lines, **wait
    ``spec.duration_seconds``** for traffic to be recorded (mirroring the device's
    own ``limit duration``), then send ``stop``+``copy`` and retrieve. Issuing
    ``stop`` immediately after ``start`` would terminate the session before any
    traffic is captured and produce an empty pcap (ADR-0023 §2).

    Seam-driven so unit tests can fake the transport, retrieval, and the dwell.
    The credential plaintext lives only inside the SSH session; it never enters
    this function's arguments, return value, or any log/audit line.
    """
    context = asyncio.run(_load_ssh_context(device_id))
    start_commands = build_eos_capture_commands(spec, remote_path)
    finalize_commands = build_eos_finalize_commands(remote_path)
    with _open_ssh(context.params) as transport:
        for command in start_commands:
            transport.send_command(command)
        # Let the capture run for the capped duration before stopping it.
        _sleep(spec.duration_seconds)
        for command in finalize_commands:
            transport.send_command(command)
        context.retrieve(transport, storage_path)


@dataclass(frozen=True)
class _EosCaptureContext:
    params: Any

    def retrieve(self, transport: Any, storage_path: str) -> None:
        """Pull the staged pcap off the device to *storage_path* (override seam)."""
        retriever = getattr(transport, "retrieve_file", None)
        if retriever is not None:
            retriever(storage_path)


async def _load_ssh_context(device_id: UUID) -> _EosCaptureContext:
    """Resolve the EOS device's SSH params from inventory + vault (seam in tests)."""
    from app.models import Device, DeviceStatus  # noqa: F401 — kept for parity/clarity
    from app.models.inventory import CredentialKind, DeviceCredential
    from app.plugins.transport import SshParams
    from app.services import credentials

    async with _session() as session:
        device = await session.get(Device, device_id)
        if device is None or device.credential_id is None:
            raise ValueError(f"device {device_id} has no usable SSH credential")
        row = await session.get(DeviceCredential, device.credential_id)
        if row is None or row.kind is not CredentialKind.SSH:
            raise ValueError(f"device {device_id} has no usable SSH credential")
        secret = await credentials.decrypt(
            session, _key_provider(), row, actor=_ACTOR, reason="packet_capture"
        )
        params = SshParams(
            host=device.mgmt_ip,
            device_type="arista_eos",
            username=row.username or "",
            password=secret.plaintext.decode("utf-8"),
            port=int((row.params or {}).get("port", 22)),
        )
        await session.commit()  # decrypt audit row
        return _EosCaptureContext(params=params)


# ---------------------------------------------------------------------------
# Task: packet.analyze_capture (sandboxed tshark)
# ---------------------------------------------------------------------------


@celery_app.task(name="packet.analyze_capture")
def analyze_capture(capture_id: str, display_filter: str | None = None) -> dict[str, Any]:
    """Analyze a stored pcap under the tshark sandbox; return normalized findings.

    Reads the pcap **read-only** and runs tshark via the sandbox (argv list,
    ``shell=False``, ``-n``, validated display filter, hard timeout). Returns the
    normalized findings (top talkers, protocol hierarchy, TCP anomalies) — never
    raw packet bytes (ADR-0023 §1). A rejected filter or a sandbox failure is
    audited and returned as ``ok=False``.
    """
    settings = _settings()
    cap_uuid = uuid.UUID(capture_id)
    storage_path = pcap_path_for(cap_uuid, pcap_dir=settings.pcap_dir)
    try:
        findings = _analyze_pcap(
            storage_path, display_filter=display_filter, settings=settings
        )
    except Exception as exc:  # noqa: BLE001 — sandbox/validation failure is audited, not raised
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("packet.analysis_failed", capture_id=capture_id, error=error)
        asyncio.run(
            _audit_failure(
                capture_id=cap_uuid, error=error, action=_ANALYSIS_FAILED, device_id=None
            )
        )
        return {"ok": False, "capture_id": capture_id, "error": error}

    asyncio.run(_record_analysis(capture_id=cap_uuid, findings=findings))
    logger.info(
        "packet.analysis_completed",
        capture_id=capture_id,
        packet_count=findings.packet_count,
    )
    return {"ok": True, "capture_id": capture_id, "findings": findings.model_dump()}


# ---------------------------------------------------------------------------
# Task: packet.purge_expired (retention beat)
# ---------------------------------------------------------------------------


async def _purge_one(capture_id: UUID) -> bool:
    """Delete the file and tombstone the row for one expired capture (audited)."""
    async with _session() as session:
        row = (
            await session.execute(
                select(PcapMetadata).where(PcapMetadata.capture_id == capture_id)
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        storage_path, sha256 = row.storage_path, row.sha256

    file_removed = _delete_file(storage_path)

    async with _session() as session:
        tombstoned = await tombstone_capture(
            session, capture_id=capture_id, reason="retention_expired"
        )
        await session.commit()
    await _audit_purge(capture_id=capture_id, sha256=sha256, file_removed=file_removed)
    return tombstoned is not None


@celery_app.task(name="packet.purge_expired")
def purge_expired() -> dict[str, Any]:
    """Retention beat: purge expired pcap files + tombstone their rows (ADR-0023 §4).

    Finds captures past ``retention_expires_at`` that are not yet tombstoned,
    deletes each pcap **file** from the volume, tombstones (never deletes) its
    metadata row, and audits each purge (actor=system/retention, file hash). The
    metadata row survives so the audit fact "a capture existed and was purged"
    persists.
    """

    async def _ids() -> list[UUID]:
        async with _session() as session:
            return await expired_capture_ids(session)

    capture_ids = asyncio.run(_ids())
    purged = 0
    for capture_id in capture_ids:
        if asyncio.run(_purge_one(capture_id)):
            purged += 1
    logger.info("packet.retention_run", expired=len(capture_ids), purged=purged)
    return {"expired": len(capture_ids), "purged": purged}
