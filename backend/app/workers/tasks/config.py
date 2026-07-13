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

  Idempotency (W2-T4 finding, ADR-0043 §6 / ADR-0008 §5): ``task_acks_late``
  is global, so a worker killed between receipt and ack causes ``nightly_backup``
  to be **redelivered**. With the old ``uuid.uuid4()``-on-entry approach, each
  delivery generated a fresh run UUID, unconditionally emitting a duplicate
  ``config.backup_run_started`` + ``config.backup_run_finished`` audit pair and
  dispatching a second full fan-out wave — the exact "double audit row" hazard
  the ADR names. Fix: ``nightly_backup`` now accepts an optional ``run_id``
  parameter. Beat (or any caller) supplies a stable, slot-derived UUID; when
  ``run_id`` is absent the task derives one deterministically from the UTC date
  slot (SHA-256 of ``"config.nightly_backup:<YYYY-MM-DD>"``). Before emitting
  any audit or fan-out, it INSERTs a ``config_backup_runs`` row with
  ``ON CONFLICT DO NOTHING``; if the row already exists (redelivery), the task
  returns immediately with ``status="skipped"`` — one effect, every time.

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
import hashlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

import structlog
from celery import chord, group
from celery.exceptions import Ignore, Reject, Retry
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app import db
from app.core.config import get_settings
from app.core.crypto import KeyProvider, get_key_provider
from app.core.errors import PluginError
from app.engines.config_mgmt import capture_snapshot
from app.models import Device, DeviceStatus
from app.models.config_mgmt import ConfigBackupRun, ConfigSource
from app.models.inventory import CredentialKind, DeviceCredential
from app.plugins.base import Capability, ConfigBackupCapability, PluginCapability
from app.plugins.registry import PluginRegistry, get_default_registry
from app.plugins.transport import (
    SshParams,
    SshTransport,
    SshTransportError,
    make_ssh_transport,
    netmiko_device_type,
    ssh_params_from,
)
from app.services import audit, credentials
from app.workers.celery_app import celery_app

__all__ = ["capture_device", "finalize_backup_wave", "nightly_backup"]

logger = structlog.get_logger(__name__)

#: Audit actor recorded for every capture credential decryption / snapshot.
_ACTOR = "worker:config"

#: Audit action vocabulary for the config queue (kept local: these are
#: worker-only events, not part of the shared M1 service vocabulary).
_SNAPSHOT_CAPTURED = "config.snapshot_captured"
_SNAPSHOT_FAILED = "config.snapshot_failed"
_BACKUP_RUN_STARTED = "config.backup_run_started"
_BACKUP_RUN_FINISHED = "config.backup_run_finished"


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
    """Context-managed SSH transport for *params* (netmiko-backed).

    Uses :func:`make_ssh_transport` so JunOS write sessions get
    :class:`~app.plugins.transport.junos_ssh.JunosSshTransport` (Wave 3 C2).
    """
    return make_ssh_transport(params)


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
            # ADR-0040 §2: enforce the credential's scope against THIS device at
            # session open — a scoped credential cannot open a session on a device
            # outside its site/role/group.
            target=device,
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
    # Host-key policy + pin (Wave 3 H7 / B4): shared helper for all SSH open sites.
    params = ssh_params_from(
        host=context.mgmt_ip,
        device_type=netmiko_device_type(context.vendor_id, cred.params),
        username=cred.username or "",
        password=cred.secret,
        cred_params=cred.params,
        settings=get_settings(),
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

    Idempotency (W2-T4, ADR-0043 §6 / ADR-0008 §5): with ``acks_late`` a
    worker-killed ``config.capture_device`` is **redelivered**, so this path runs
    twice for the same config. :func:`capture_snapshot` already content-addresses
    the blob — the second run is a dedup hit (``created=False``) that writes no new
    snapshot row, advancing only ``captured_at`` to mark the fresh observation. The
    ``config.snapshot_captured`` **audit row is emitted only when a new blob was
    actually stored** (``result.created``): a redelivery must not append a duplicate
    audit row for a capture that already happened (the exact "double audit row" the
    ADR names as the redelivery hazard). An unchanged re-observation is not an
    audited capture event, so the task is idempotent end-to-end — same content twice
    yields one snapshot row and one audit row.
    """
    async with _session() as session:
        result = await capture_snapshot(
            session,
            device_id=device_id,
            raw_config=raw_config,
            source=source,
            capture_run_id=capture_run_id,
        )
        if result.created:
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
    bind=True,
    name="config.capture_device",
    autoretry_for=(SshTransportError,),
    max_retries=2,
    retry_backoff=True,
)
def capture_device(
    self: Any,
    device_id: str,
    source: str = ConfigSource.ON_DEMAND.value,
    capture_run_id: str | None = None,
) -> dict[str, Any]:
    """Capture one device's running configuration into ``config_snapshots``.

    Returns a JSON-safe summary: ``ok``, ``device_id``, ``content_hash`` and
    ``created`` on success, or ``ok=False`` + ``error`` on a permanent failure
    (the failure is audited). Raises the transport error when the device was
    never reached so Celery retries it (transient failure). After retries are
    exhausted, returns ``ok=False`` so a backup **chord** still completes
    (Wave 5 / perf #2).

    Any *other* exception is folded into ``ok=False`` as well: a raised
    header task fails the whole chord and ``finalize_backup_wave`` never
    runs, stranding the backup run in ``running`` forever.
    """
    try:
        return _capture_device_inner(self, device_id, source, capture_run_id)
    except (SshTransportError, Retry, Ignore, Reject):
        # Transport: autoretry_for retries these (retries-exhausted folds
        # inside). Retry/Ignore/Reject: Celery control flow, never folded
        # (PR 161 Task C).
        raise
    except Exception as exc:  # noqa: BLE001 — the chord body must always run
        logger.exception("config.capture_device_unexpected", device_id=device_id)
        error = f"{type(exc).__name__}: {exc}"
        # Mirror the audited permanent-failure paths (config.snapshot_failed)
        # so a folded failure still leaves an audit trace — best-effort on a
        # fresh loop, since the broken state may be the DB itself.
        try:
            asyncio.run(_audit_failure(uuid.UUID(device_id), error, source=ConfigSource(source)))
        except Exception:  # noqa: BLE001 — never mask the fold's ok=False result
            logger.exception("config.capture_failure_audit_error", device_id=device_id)
        return {"ok": False, "device_id": device_id, "error": error}


def _capture_device_inner(
    self: Any,
    device_id: str,
    source: str,
    capture_run_id: str | None,
) -> dict[str, Any]:
    """Body of :func:`capture_device` (wrapped by its chord-safety fold)."""
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
        max_retries = int(getattr(self, "max_retries", 0) or 0)
        retries = int(getattr(getattr(self, "request", None), "retries", 0) or 0)
        if retries >= max_retries:
            error = f"{type(exc).__name__}: {exc}"
            asyncio.run(_audit_failure(device_uuid, error, source=snapshot_source))
            return {"ok": False, "device_id": device_id, "error": error}
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


def _slot_uuid(slot: str) -> UUID:
    """Derive a deterministic UUID from a scheduled-slot string.

    Uses the SHA-256 digest of ``"config.nightly_backup:<slot>"`` (where *slot*
    is the UTC date ``YYYY-MM-DD``) to produce a stable, collision-resistant UUID
    that is identical on every delivery of the same beat tick — so a redelivered
    task carries the same ``run_uuid`` and the ``ON CONFLICT DO NOTHING`` guard
    recognises it as a duplicate.
    """
    digest = hashlib.sha256(f"config.nightly_backup:{slot}".encode()).digest()
    # Build a UUID from the first 16 bytes of the digest (variant/version bits
    # overwritten — this is a name-derived opaque token, not RFC-4122 v5).
    return UUID(bytes=digest[:16])


#: Terminal lifecycle statuses of a ``config_backup_runs`` row — a run that
#: reached one of these finished (cleanly or not). A redelivery that finds the
#: row in one of these states is a genuine duplicate and is skipped.
_TERMINAL_BACKUP_STATUSES: Final[frozenset[str]] = frozenset(
    {"succeeded", "partial", "empty", "failed"}
)


async def _claim_backup_run(run_uuid: UUID, scheduled_slot: str) -> str:
    """INSERT a ``config_backup_runs`` row with ON CONFLICT DO NOTHING.

    Returns a 3-state claim outcome:

    - ``"claimed"`` — the row was **newly inserted** (first/only delivery); the
      caller proceeds with the fan-out AND emits the ``backup_run_started``
      audit (the started pair is tied to this fresh claim).
    - ``"skipped"`` — the row already existed in a **terminal** status (the run
      genuinely finished); the caller returns a skip sentinel without touching
      the audit log or dispatching captures (the duplicate-prevention proof).
    - ``"resumed"`` — the row already existed but is still ``"running"``: a prior
      delivery committed the claim then died (``task_reject_on_worker_lost``)
      before finishing, leaving the run stuck. The caller proceeds with the
      fan-out but SKIPS the ``backup_run_started`` audit (the started audit
      belongs to the original claim) so the scheduled backup is recovered rather
      than lost — without double-emitting the started/finished pair.

    The DB-level uniqueness of ``run_uuid`` (the PK) is the enforcement
    mechanism: PostgreSQL's ``ON CONFLICT DO NOTHING`` skips the INSERT when
    the PK row exists and sets ``cursor.rowcount == 0``; SQLite's
    ``INSERT OR IGNORE`` does the same. On a ``rowcount == 0`` conflict the
    existing row's ``status`` is re-read in the SAME transaction to classify the
    redelivery as a terminal duplicate (skip) or a stale claim (resume).

    Implementation uses the dialect-specific ``insert`` (PostgreSQL or SQLite)
    because SQLAlchemy's generic ``Insert`` does not expose ``.on_conflict_*``
    methods — those are dialect extensions. Both flavours are identical in
    semantics: skip on PK conflict, no error raised, rowcount reflects whether
    the INSERT actually landed.
    """
    async with _session() as session:
        dialect = session.bind.dialect.name if session.bind is not None else "sqlite"
        values: dict[str, Any] = {
            "run_uuid": run_uuid,
            "scheduled_slot": scheduled_slot,
            "status": "running",
            "started_at": datetime.now(UTC),
        }
        if dialect == "postgresql":
            stmt: Any = (
                pg_insert(ConfigBackupRun)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["run_uuid"])
            )
        else:
            # aiosqlite unit-test backend: INSERT OR IGNORE on PK conflict.
            stmt = sqlite_insert(ConfigBackupRun).values(**values).on_conflict_do_nothing()
        cursor = await session.execute(stmt)
        if cursor.rowcount == 1:  # type: ignore[attr-defined]
            await session.commit()
            return "claimed"
        # rowcount == 0 → PK conflict (redelivery). Classify by the existing
        # row's status: a terminal run is a real duplicate (skip); a still
        # ``running`` row is a stale claim from a dead worker (resume).
        existing_status = (
            await session.execute(
                select(ConfigBackupRun.status).where(ConfigBackupRun.run_uuid == run_uuid)
            )
        ).scalar_one_or_none()
        await session.commit()
        if existing_status in _TERMINAL_BACKUP_STATUSES:
            return "skipped"
        return "resumed"


async def _finish_backup_run(run_uuid: UUID, status: str) -> None:
    """Mark the ``config_backup_runs`` row as finished (mutable lifecycle column)."""
    async with _session() as session:
        await session.execute(
            update(ConfigBackupRun)
            .where(ConfigBackupRun.run_uuid == run_uuid)
            .values(status=status, finished_at=datetime.now(UTC))
        )
        await session.commit()


async def _fail_backup_run_if_not_terminal(run_uuid: UUID, error: str) -> None:
    """Mark the backup run ``failed`` unless it already reached a terminal status.

    PR 161 Task C: conditional UPDATE so a body failure that happens *after*
    the run finished (e.g. while building the return payload) cannot clobber
    the terminal status. The ``backup_run_finished`` audit (carrying the error
    note — ``config_backup_runs`` has no error column) is emitted only when
    this attempt actually flipped the row.
    """
    async with _session() as session:
        cursor = await session.execute(
            update(ConfigBackupRun)
            .where(
                ConfigBackupRun.run_uuid == run_uuid,
                ConfigBackupRun.status.not_in(_TERMINAL_BACKUP_STATUSES),
            )
            .values(status="failed", finished_at=datetime.now(UTC))
        )
        if cursor.rowcount == 1:  # type: ignore[attr-defined]
            await audit.record(
                session,
                actor=_ACTOR,
                action=_BACKUP_RUN_FINISHED,
                target_type="config_backup_run",
                target_id=str(run_uuid),
                detail={"status": "failed", "error": error},
            )
        await session.commit()


def _fail_backup_run_best_effort(run_id: str, error: str) -> None:
    """Best-effort ``failed`` finalize on a fresh loop + engine (guard support).

    Runs on its own ``asyncio.run`` and engine so the attempt does not depend
    on whatever broke the body task; a secondary failure is logged and
    swallowed — the caller re-raises the original exception regardless.
    """
    try:
        asyncio.run(_fail_backup_run_if_not_terminal(uuid.UUID(run_id), error))
    except Exception:  # noqa: BLE001 — never mask the original body failure
        logger.exception("config.finalize_failed_error", run_id=run_id)


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


def _normalize_capture_results(
    raw_results: list[Any], device_ids: list[str]
) -> list[dict[str, Any]]:
    """Fold chord header results into per-device summaries."""
    results: list[dict[str, Any]] = []
    padded: list[Any] = list(raw_results) if raw_results is not None else []
    while len(padded) < len(device_ids):
        padded.append(None)
    for device_id, item in zip(device_ids, padded, strict=False):
        if isinstance(item, dict) and "ok" in item:
            results.append(item)
            continue
        if isinstance(item, BaseException):
            results.append(
                {
                    "ok": False,
                    "device_id": device_id,
                    "error": f"{type(item).__name__}: {item}",
                }
            )
            continue
        results.append(
            {
                "ok": False,
                "device_id": device_id,
                "error": f"wave_member_failed: {type(item).__name__}: {item!r}",
            }
        )
    return results


@celery_app.task(name="config.finalize_backup_wave")
def finalize_backup_wave(
    results: list[Any],
    run_id: str,
    device_ids: list[str],
) -> dict[str, Any]:
    """Chord body: audit finish + terminal status for a nightly backup wave.

    Safety net (PR 161 Task C): with global ``acks_late`` and no ``link_error``
    a chord body that raises is acked and never redelivered, so the backup run
    row would strand in ``running`` forever. Any unexpected exception
    best-effort finalizes the run as ``failed`` (never clobbering an
    already-terminal status) and then re-raises so Celery still records the
    task failure.
    """
    try:
        return _finalize_backup_wave_inner(results, run_id, device_ids)
    except (Retry, Ignore, Reject):
        raise  # celery control flow, not a body failure
    except Exception as exc:
        logger.exception("config.finalize_backup_wave_unexpected", run_id=run_id)
        _fail_backup_run_best_effort(run_id, f"finalize_backup_wave: {type(exc).__name__}: {exc}")
        raise


def _finalize_backup_wave_inner(
    results: list[Any],
    run_id: str,
    device_ids: list[str],
) -> dict[str, Any]:
    """Body of :func:`finalize_backup_wave` (wrapped by its safety net)."""
    run_uuid = uuid.UUID(run_id)
    normalized = _normalize_capture_results(results, device_ids)
    succeeded = [r for r in normalized if r.get("ok")]
    failed = [r for r in normalized if not r.get("ok")]
    if not succeeded:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "succeeded"

    async def _finish() -> None:
        await _audit_run(
            _BACKUP_RUN_FINISHED,
            run_uuid,
            {"status": status, "succeeded": len(succeeded), "failed": len(failed)},
        )
        await _finish_backup_run(run_uuid, status)

    asyncio.run(_finish())
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
        "devices": normalized,
    }


def _dispatch_captures(run_id: str, device_ids: list[str]) -> dict[str, Any]:
    """Fan captures as a Celery chord (Wave 5 / perf #2) — no blocking ``.get``.

    Header = per-device ``capture_device``; body = :func:`finalize_backup_wave`.
    Under eager mode the chord resolves inline and this returns the body result.
    """
    header = group(
        capture_device.s(device_id, ConfigSource.SCHEDULED.value, run_id)
        for device_id in device_ids
    )
    body = finalize_backup_wave.s(run_id, list(device_ids))
    async_result = chord(header)(body)
    if celery_app.conf.task_always_eager:
        return dict(async_result.get(disable_sync_subtasks=True))
    return {
        "run_id": run_id,
        "status": "running",
        "dispatched": True,
        "device_count": len(device_ids),
    }


async def _nightly_backup_core(run_id: str | None = None) -> dict[str, Any]:
    """Async body of :func:`nightly_backup` (the sync Celery task wraps this).

    Extracting the body as an ``async def`` lets the async DB phases be awaited
    directly on a caller-owned event loop. The sync Celery task owns its own loop
    via a single ``asyncio.run`` at the top; the PG idempotency tests await this
    core on the running pytest loop (matching the other ``tests/pg`` cases that
    await async helpers directly) instead of calling the sync task from inside a
    running loop — which would raise ``RuntimeError: asyncio.run() cannot be
    called from a running event loop``.

    Fans one ``config.capture_device`` task out per reachable device via a
    **chord** (Wave 5): the orchestrator does not block on children. Final
    audit/finish runs in :func:`finalize_backup_wave`.

    Idempotency (W2-T4 finding, ADR-0043 §6): ``run_id`` is an optional
    parameter so the beat caller (or a test) can supply a stable UUID. When
    absent, a deterministic UUID is derived from the UTC date slot so that
    every redelivery of the same beat tick carries the same token. The task
    INSERTs a ``config_backup_runs`` row with ``ON CONFLICT DO NOTHING`` before
    any audit emit or fan-out. The 3-state claim (:func:`_claim_backup_run`)
    decides what happens on a PK conflict:

    - ``"claimed"`` (fresh insert) → run the fan-out AND emit the started audit.
    - ``"skipped"`` (existing row is terminal) → return ``{"status":"skipped"}``
      without a second audit pair or a second fan-out wave (the dedup proof).
    - ``"resumed"`` (existing row stuck ``"running"`` from a dead worker) → run
      the fan-out but SKIP the started audit (it belongs to the original claim),
      so a backup whose worker died mid-run is recovered, not lost forever.
    """
    # Resolve the scheduled slot (UTC date) and the stable run UUID.
    scheduled_slot = datetime.now(UTC).strftime("%Y-%m-%d")
    run_uuid = uuid.UUID(run_id) if run_id is not None else _slot_uuid(scheduled_slot)
    run_id_str = str(run_uuid)

    # --- Idempotency guard (W2-T4 fix) ---
    # INSERT the run record; classify a PK conflict as a terminal duplicate
    # (skip) or a stale ``running`` claim from a dead worker (resume).
    claim = await _claim_backup_run(run_uuid, scheduled_slot)
    if claim == "skipped":
        logger.info(
            "config.backup_skipped_redelivery",
            run_id=run_id_str,
            scheduled_slot=scheduled_slot,
        )
        return {"run_id": run_id_str, "status": "skipped"}
    resumed = claim == "resumed"
    if resumed:
        logger.info(
            "config.backup_resumed_stale_claim",
            run_id=run_id_str,
            scheduled_slot=scheduled_slot,
        )

    device_uuids = await _reachable_device_ids()
    device_ids = [str(d) for d in device_uuids]

    # The ``backup_run_started`` audit is tied to the original claim, so a resumed
    # run does NOT re-emit it (no double started/finished pair).
    if not resumed:
        await _audit_run(_BACKUP_RUN_STARTED, run_uuid, {"device_count": len(device_ids)})
    logger.info("config.backup_started", run_id=run_id_str, device_count=len(device_ids))

    if not device_ids:
        await _audit_run(
            _BACKUP_RUN_FINISHED, run_uuid, {"status": "empty", "succeeded": 0, "failed": 0}
        )
        await _finish_backup_run(run_uuid, "empty")
        logger.info("config.backup_finished", run_id=run_id_str, status="empty")
        return {"run_id": run_id_str, "status": "empty", "succeeded": 0, "failed": 0}

    # Chord dispatch is sync Celery (may run children under eager). Offload so
    # nested asyncio.run inside capture_device never nests on this loop.
    return await asyncio.to_thread(_dispatch_captures, run_id_str, device_ids)


@celery_app.task(name="config.nightly_backup")
def nightly_backup(run_id: str | None = None) -> dict[str, Any]:
    """Scheduled nightly backup of every reachable device (Celery beat).

    Thin sync wrapper that owns the event loop: the real body lives in
    :func:`_nightly_backup_core` so it can be awaited directly by callers that
    already run inside an event loop (the PG idempotency tests). See that
    function for the fan-out + 3-state idempotency contract.
    """
    return asyncio.run(_nightly_backup_core(run_id))
