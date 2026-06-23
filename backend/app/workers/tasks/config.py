"""Celery config-management tasks (M4-T5): snapshot capture on the ``config``
queue (ADR-0008 D8, ADR-0017).

Two tasks, routed to the ``config`` queue by name prefix:

- ``config.capture_device`` — captures one device's running configuration:
  loads the device + its vault credential, opens an SSH session, runs the
  vendor plugin's ``CONFIG_BACKUP`` capability, and hands the verbatim text to
  :func:`app.engines.config_mgmt.capture_snapshot` (content-addressed dedup —
  an unchanged config stores no new blob). Transient transport failures
  (``SshTransportError`` with no successful connection) are raised so Celery's
  ``autoretry_for`` retries with backoff; permanent failures (no credential,
  unsupported vendor, empty config) return ``ok=False`` and are **audited** so
  a dead device degrades the nightly run to ``partial`` instead of aborting it.

- ``config.nightly_backup`` — the Celery-beat scheduled job (``CONFIG_BACKUP_*``
  settings drive the cron). Fans every **reachable** device out as one
  ``config.capture_device`` per device (a Celery group), gathers per-device
  summaries, audits the run start/finish, and reports counts.

Async DB from sync Celery follows the discovery-task pattern exactly: each task
phase wraps its DB work in ``asyncio.run`` with a fresh engine per invocation,
and module-level seams (``_make_engine``, ``_registry``, ``_key_provider``,
``_open_ssh``) let unit tests run everything eagerly with fakes.

Secret discipline (D11): credential plaintext exists only inside
:class:`_DeviceCredential` (redacted ``repr``) for the lifetime of the SSH
session and never enters a log line, audit ``detail``, result payload, or
exception message. Snapshot content is stored verbatim/unredacted at rest
(ADR-0017 parity with ``raw_artifacts``); redaction is an LLM-boundary concern,
not a capture concern.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from celery import group
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app import db
from app.core.config import get_settings
from app.core.crypto import KeyProvider, get_key_provider
from app.core.errors import PluginError
from app.engines.config_mgmt import capture_snapshot
from app.models import Device, DeviceStatus
from app.models.config_mgmt import ConfigSource
from app.models.inventory import CredentialKind, DeviceCredential
from app.plugins.base import Capability, ConfigBackupCapability, PluginCapability
from app.plugins.registry import PluginRegistry, get_default_registry
from app.plugins.transport import SshParams, SshTransport, SshTransportError
from app.services import audit, credentials
from app.workers.celery_app import celery_app

__all__ = ["capture_device", "nightly_backup"]

logger = structlog.get_logger(__name__)

#: Audit actor recorded for every capture credential decryption / snapshot.
_ACTOR = "worker:config"

#: Audit action vocabulary for the config queue (kept local: these are
#: worker-only events, not part of the shared M1 service vocabulary).
_SNAPSHOT_CAPTURED = "config.snapshot_captured"
_SNAPSHOT_FAILED = "config.snapshot_failed"
_BACKUP_RUN_STARTED = "config.backup_run_started"
_BACKUP_RUN_FINISHED = "config.backup_run_finished"

#: vendor_id -> netmiko ``device_type`` used to open the capture session.
_NETMIKO_DEVICE_TYPES: dict[str, str] = {
    "cisco_ios": "cisco_ios",
    "cisco_iosxe": "cisco_xe",
    "eos": "arista_eos",
}


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    """New async engine for one task phase (loop-scoped, disposed after use)."""
    return db.create_engine(get_settings())


def _registry() -> PluginRegistry:
    """The plugin registry resolving a device's vendor plugin."""
    return get_default_registry()


def _key_provider() -> KeyProvider:
    """The KEK provider used to decrypt vault credentials."""
    return get_key_provider(get_settings())


def _open_ssh(params: SshParams) -> SshTransport:
    """Context-managed SSH transport for *params* (netmiko-backed)."""
    return SshTransport(params)


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    """One AsyncSession on a fresh engine, disposed when the phase ends."""
    engine = _make_engine()
    try:
        async with db.create_sessionmaker(engine)() as session:
            yield session
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Credential materialization (SSH only — config backup is a CLI capability)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class _DeviceCredential:
    """A decrypted SSH credential held in memory for one capture only."""

    id: UUID
    username: str | None
    secret: str
    params: dict[str, Any]

    def __repr__(self) -> str:  # secret never rendered
        return f"<_DeviceCredential id={self.id!s}>"


@dataclass(frozen=True)
class _CaptureContext:
    """Everything one capture needs, resolved from inventory under one session."""

    mgmt_ip: str
    vendor_id: str
    credential: _DeviceCredential


async def _load_context(device_id: UUID) -> _CaptureContext | None:
    """Load device + decrypt its SSH credential; ``None`` if not capturable.

    The decryption audit row is committed here so the trail survives even if the
    SSH session or persistence subsequently fails. Returns ``None`` (no
    exception) when the device has no vendor, no credential, or a non-SSH
    credential — these are permanent, non-retryable conditions the caller turns
    into an audited ``ok=False`` summary.
    """
    async with _session() as session:
        device = await session.get(Device, device_id)
        if device is None:
            raise ValueError(f"device {device_id} does not exist")
        if device.vendor_id is None or device.credential_id is None:
            logger.warning(
                "config.device_not_capturable",
                device_id=str(device_id),
                reason="missing vendor_id or credential",
            )
            return None
        row = await session.get(DeviceCredential, device.credential_id)
        if row is None or row.kind is not CredentialKind.SSH:
            logger.warning(
                "config.device_not_capturable",
                device_id=str(device_id),
                reason="no usable ssh credential",
            )
            return None
        secret = await credentials.decrypt(
            session,
            _key_provider(),
            row,
            actor=_ACTOR,
            reason="config_backup",
            sessionmaker=credentials.autonomous_sessionmaker(session),
        )
        context = _CaptureContext(
            mgmt_ip=device.mgmt_ip,
            vendor_id=device.vendor_id,
            credential=_DeviceCredential(
                id=row.id,
                username=row.username,
                secret=secret.plaintext.decode("utf-8"),
                params=dict(row.params or {}),
            ),
        )
        await session.commit()  # decrypt audit row
        return context


# ---------------------------------------------------------------------------
# Config fetch over SSH (sync, no DB)
# ---------------------------------------------------------------------------


def _fetch_running_config(
    registry: PluginRegistry, context: _CaptureContext, device_id: UUID
) -> str:
    """Open SSH and return the device running config via ``CONFIG_BACKUP``.

    Raises :class:`SshTransportError` when the session never connects (transient
    — the task retries) and :class:`PluginError` when the vendor does not
    support config backup or returns empty output (permanent).
    """
    plugin = registry.get_plugin(context.vendor_id)
    if not plugin.supports(Capability.CONFIG_BACKUP):
        raise PluginError(f"vendor {context.vendor_id!r} does not support config backup")
    cred = context.credential
    default_device_type = _NETMIKO_DEVICE_TYPES.get(context.vendor_id, context.vendor_id)
    params = SshParams(
        host=context.mgmt_ip,
        device_type=str(cred.params.get("device_type") or default_device_type),
        username=cred.username or "",
        password=cred.secret,
        port=int(cred.params.get("port", 22)),
    )
    with _open_ssh(params) as transport:
        impl_cls = plugin.get_capability(Capability.CONFIG_BACKUP)
        instance: PluginCapability = impl_cls(transport, device_id)  # type: ignore[call-arg]
        if not isinstance(instance, ConfigBackupCapability):
            raise PluginError(f"{type(instance).__name__} is not a ConfigBackupCapability")
        return instance.fetch_running_config()


async def _persist(
    device_id: UUID, raw_config: str, *, source: ConfigSource, capture_run_id: UUID | None
) -> tuple[str, bool]:
    """Content-address + store the snapshot and audit the capture.

    Returns ``(content_hash, created)``. The snapshot and its audit entry commit
    atomically.
    """
    async with _session() as session:
        result = await capture_snapshot(
            session,
            device_id=device_id,
            raw_config=raw_config,
            source=source,
            capture_run_id=capture_run_id,
        )
        await audit.record(
            session,
            actor=_ACTOR,
            action=_SNAPSHOT_CAPTURED,
            target_type="config_snapshot",
            target_id=str(result.snapshot.id),
            detail={
                "device_id": str(device_id),
                "content_hash": result.content_hash,
                "created": result.created,
                "source": source.value,
            },
        )
        await session.commit()
        return result.content_hash, result.created


async def _audit_failure(device_id: UUID, error: str, *, source: ConfigSource) -> None:
    """Append an audited capture failure (no secret material in *error*)."""
    async with _session() as session:
        await audit.record(
            session,
            actor=_ACTOR,
            action=_SNAPSHOT_FAILED,
            target_type="device",
            target_id=str(device_id),
            detail={"error": error, "source": source.value},
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Task: config.capture_device
# ---------------------------------------------------------------------------


@celery_app.task(
    name="config.capture_device",
    autoretry_for=(SshTransportError,),
    max_retries=2,
    retry_backoff=True,
)
def capture_device(
    device_id: str, source: str = ConfigSource.ON_DEMAND.value, capture_run_id: str | None = None
) -> dict[str, Any]:
    """Capture one device's running configuration into ``config_snapshots``.

    Returns a JSON-safe summary: ``ok``, ``device_id``, ``content_hash`` and
    ``created`` on success, or ``ok=False`` + ``error`` on a permanent failure
    (the failure is audited). Raises the transport error when the device was
    never reached so Celery retries it (transient failure).
    """
    device_uuid = uuid.UUID(device_id)
    snapshot_source = ConfigSource(source)
    run_uuid = uuid.UUID(capture_run_id) if capture_run_id is not None else None

    context = asyncio.run(_load_context(device_uuid))
    if context is None:
        error = "device is not capturable (missing vendor or usable SSH credential)"
        asyncio.run(_audit_failure(device_uuid, error, source=snapshot_source))
        return {"ok": False, "device_id": device_id, "error": error}

    registry = _registry()
    try:
        raw_config = _fetch_running_config(registry, context, device_uuid)
    except SshTransportError as exc:
        logger.warning(
            "config.device_unreachable",
            device_id=device_id,
            error_type=type(exc).__name__,
        )
        raise
    except PluginError as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("config.capture_failed", device_id=device_id, error=error)
        asyncio.run(_audit_failure(device_uuid, error, source=snapshot_source))
        return {"ok": False, "device_id": device_id, "error": error}

    content_hash, created = asyncio.run(
        _persist(device_uuid, raw_config, source=snapshot_source, capture_run_id=run_uuid)
    )
    logger.info(
        "config.device_captured",
        device_id=device_id,
        content_hash=content_hash,
        created=created,
        source=source,
    )
    return {
        "ok": True,
        "device_id": device_id,
        "content_hash": content_hash,
        "created": created,
    }


# ---------------------------------------------------------------------------
# Task: config.nightly_backup (beat-scheduled fan-out)
# ---------------------------------------------------------------------------


async def _reachable_device_ids() -> list[UUID]:
    """All device ids in ``reachable`` state — the nightly backup target set."""
    async with _session() as session:
        rows = (
            await session.execute(select(Device.id).where(Device.status == DeviceStatus.REACHABLE))
        ).scalars()
        return list(rows)


async def _audit_run(action: str, run_id: UUID, detail: dict[str, Any]) -> None:
    """Audit a nightly-backup run lifecycle event."""
    async with _session() as session:
        await audit.record(
            session,
            actor=_ACTOR,
            action=action,
            target_type="config_backup_run",
            target_id=str(run_id),
            detail=detail,
        )
        await session.commit()


def _dispatch_captures(run_id: str, device_ids: list[str]) -> list[dict[str, Any]]:
    """Fan device captures out as a Celery group and gather per-device summaries.

    A child task that exhausted its retries surfaces here as an exception; it is
    folded into an ``ok=False`` summary so one dead device degrades the run to
    ``partial`` instead of aborting the whole backup.
    """
    job = group(
        capture_device.s(device_id, ConfigSource.SCHEDULED.value, run_id)
        for device_id in device_ids
    )
    group_result = job.apply_async()
    results: list[dict[str, Any]] = []
    for device_id, child in zip(device_ids, group_result.results, strict=True):
        try:
            results.append(child.get(disable_sync_subtasks=False))
        except Exception as exc:  # noqa: BLE001 — retries exhausted; record + continue
            results.append(
                {"ok": False, "device_id": device_id, "error": f"{type(exc).__name__}: {exc}"}
            )
    return results


@celery_app.task(name="config.nightly_backup")
def nightly_backup() -> dict[str, Any]:
    """Scheduled nightly backup of every reachable device (Celery beat).

    Fans one ``config.capture_device`` task out per reachable device, gathers
    the summaries, and audits the run start and finish. The terminal status is
    ``succeeded`` (all captured), ``partial`` (some failed), ``empty`` (no
    reachable devices), or ``failed`` (every device failed).
    """
    run_uuid = uuid.uuid4()
    run_id = str(run_uuid)
    device_uuids = asyncio.run(_reachable_device_ids())
    device_ids = [str(d) for d in device_uuids]

    asyncio.run(_audit_run(_BACKUP_RUN_STARTED, run_uuid, {"device_count": len(device_ids)}))
    logger.info("config.backup_started", run_id=run_id, device_count=len(device_ids))

    if not device_ids:
        asyncio.run(
            _audit_run(
                _BACKUP_RUN_FINISHED, run_uuid, {"status": "empty", "succeeded": 0, "failed": 0}
            )
        )
        logger.info("config.backup_finished", run_id=run_id, status="empty")
        return {"run_id": run_id, "status": "empty", "succeeded": 0, "failed": 0}

    results = _dispatch_captures(run_id, device_ids)
    succeeded = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]

    if not succeeded:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "succeeded"

    asyncio.run(
        _audit_run(
            _BACKUP_RUN_FINISHED,
            run_uuid,
            {"status": status, "succeeded": len(succeeded), "failed": len(failed)},
        )
    )
    logger.info(
        "config.backup_finished",
        run_id=run_id,
        status=status,
        succeeded=len(succeeded),
        failed=len(failed),
    )
    return {
        "run_id": run_id,
        "status": status,
        "succeeded": len(succeeded),
        "failed": len(failed),
        "devices": results,
    }
