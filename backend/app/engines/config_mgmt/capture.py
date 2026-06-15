"""Configuration snapshot capture engine (M4; ADR-0017).

Given a device's running configuration text, this module:

1. **normalizes** it to a byte-stable form (line endings collapsed to ``\\n``,
   trailing per-line whitespace stripped, a single trailing newline) so the
   content hash is stable across transports that differ only in CR/LF or
   trailing-whitespace handling — drift must reflect *real* config changes, not
   transport noise;
2. **content-addresses** it: ``content_hash`` is the SHA-256 of the normalized
   text, and an unchanged re-capture (same ``(device_id, content_hash)``) stores
   **no new blob** — only a fresh observation is recorded as the
   ``captured_at`` of the existing row, exactly as ADR-0017 §1 mandates;
3. **persists** a :class:`~app.models.ConfigSnapshot` row when (and only when)
   the content is new for that device.

The configuration content is stored **verbatim** (the normalized text is
byte-for-byte the device output minus transport noise) and **unredacted at
rest** — parity with ``raw_artifacts`` (RBAC + audit). The A9 redaction layer
applies only at the LLM boundary (the Configuration Agent, M4 task 9), never
here.

No Celery wiring lives here (that is :mod:`app.workers.tasks.config`) and no
transport I/O — the engine consumes already-fetched config text so it is pure,
synchronous-friendly logic over the persistence layer, unit-testable against an
in-memory database with a fake plugin.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ConfigSnapshot, ConfigSource
from app.models.mixins import utcnow
from app.services.audit import service as _audit_svc

__all__ = [
    "BackupPassResult",
    "CaptureResult",
    "capture_snapshot",
    "hash_config",
    "normalize_config",
    "run_backup_pass",
]

logger = structlog.get_logger(__name__)


def normalize_config(raw_config: str) -> str:
    """Return *raw_config* in a byte-stable normalized form for hashing.

    Collapses ``\\r\\n``/``\\r`` to ``\\n``, strips trailing whitespace from
    each line, and guarantees exactly one trailing newline for non-empty
    content. This is the text both stored as ``content`` and hashed, so the
    stored blob is itself stable and a re-capture of an unchanged config always
    dedups (ADR-0017 §1). The transform is idempotent: normalizing an
    already-normalized config returns it unchanged.
    """
    unified = raw_config.replace("\r\n", "\n").replace("\r", "\n")
    stripped = "\n".join(line.rstrip() for line in unified.split("\n"))
    body = stripped.strip("\n")
    return f"{body}\n" if body else ""


def hash_config(normalized_config: str) -> str:
    """SHA-256 hex digest of already-:func:`normalize_config`-d text."""
    return hashlib.sha256(normalized_config.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CaptureResult:
    """Outcome of one capture: the snapshot row and whether it was new.

    ``created`` is ``False`` when the content matched an existing snapshot for
    the device (content-addressed dedup — no new blob was written); the
    pre-existing row's ``captured_at`` is advanced to mark the fresh
    observation. ``content_hash`` is exposed so callers can log/audit the
    snapshot identity without touching the (secret-bearing) content.
    """

    snapshot: ConfigSnapshot
    created: bool

    @property
    def content_hash(self) -> str:
        """The SHA-256 identity of the captured configuration."""
        return self.snapshot.content_hash


async def capture_snapshot(
    session: AsyncSession,
    *,
    device_id: UUID,
    raw_config: str,
    source: ConfigSource,
    capture_run_id: UUID | None = None,
) -> CaptureResult:
    """Content-address and persist one device configuration snapshot.

    Normalizes *raw_config*, computes its hash, and looks up an existing
    snapshot for ``(device_id, content_hash)``. On a hit the config is unchanged
    since that capture: no new blob is stored, the existing row's
    ``captured_at`` is advanced to record the new observation, and
    ``created=False`` is returned. On a miss a new verbatim-content row is
    inserted (``created=True``).

    The caller owns the transaction boundary (this function only flushes), so
    the snapshot commits or rolls back atomically with whatever audit entry the
    caller writes alongside it.

    :param raw_config: the device's running configuration, exactly as the
        ``CONFIG_BACKUP`` capability returned it (normalization handles only
        transport-level whitespace/line-ending noise — never content).
    :param source: ``scheduled`` for the nightly beat job, ``on_demand`` for an
        operator-triggered capture.
    :param capture_run_id: optional id correlating this capture with its
        orchestrating job (the nightly backup run), mirroring
        ``raw_artifacts.run_id``.
    """
    normalized = normalize_config(raw_config)
    content_hash = hash_config(normalized)

    existing = (
        await session.execute(
            select(ConfigSnapshot).where(
                ConfigSnapshot.device_id == device_id,
                ConfigSnapshot.content_hash == content_hash,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.captured_at = utcnow()
        await session.flush()
        logger.info(
            "config.snapshot_unchanged",
            device_id=str(device_id),
            content_hash=content_hash,
            source=source.value,
        )
        return CaptureResult(snapshot=existing, created=False)

    snapshot = ConfigSnapshot(
        device_id=device_id,
        captured_at=utcnow(),
        content_hash=content_hash,
        content=normalized,
        source=source,
        capture_run_id=capture_run_id,
        baseline=False,
    )
    session.add(snapshot)
    await session.flush()
    logger.info(
        "config.snapshot_captured",
        device_id=str(device_id),
        content_hash=content_hash,
        source=source.value,
        bytes=len(normalized),
    )
    return CaptureResult(snapshot=snapshot, created=True)


# ---------------------------------------------------------------------------
# Backup-pass orchestration — unit-testable boundary (no Celery coupling)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackupPassResult:
    """Outcome of one :func:`run_backup_pass` call.

    ``captured`` maps each successfully snapshotted device id to its content
    hash; ``failed`` maps each device id whose capture raised an exception to
    that exception. Both dicts are disjoint — every input device id appears in
    exactly one of them.
    """

    captured: dict[UUID, str] = field(default_factory=dict)
    failed: dict[UUID, BaseException] = field(default_factory=dict)


async def run_backup_pass(
    session: AsyncSession,
    *,
    device_configs: dict[UUID, str],
    device_errors: dict[UUID, BaseException],
    source: ConfigSource = ConfigSource.SCHEDULED,
    actor: str = "worker:config",
) -> BackupPassResult:
    """Orchestrate one backup pass: persist successes and audit failures.

    This is the unit-testable production boundary that the nightly Celery beat
    job and tests both target. Transport-layer concerns (SSH, plugin dispatch)
    are resolved *before* calling this function; the caller supplies the
    already-fetched config texts and the already-materialized exceptions.

    For each device in *device_configs* the snapshot is content-addressed and
    persisted (via :func:`capture_snapshot`). For each device in
    *device_errors* an audit row is written with action
    ``config.snapshot_failed``; no exception is re-raised so one dead device
    degrades the pass to ``partial`` rather than aborting it.

    The session is flushed after every operation but the caller owns the
    transaction boundary — commit or roll back as needed after this returns.

    :param device_configs: mapping of device_id → fetched running config text
        for every device the transport layer reached successfully.
    :param device_errors: mapping of device_id → exception for every device
        the transport layer could not reach or whose capture failed permanently.
    :param source: ``ConfigSource.SCHEDULED`` for the nightly beat job,
        ``ConfigSource.ON_DEMAND`` for operator-triggered passes.
    :param actor: the audit actor string (defaults to the config worker identity).
    """
    captured: dict[UUID, str] = {}
    failed: dict[UUID, BaseException] = {}

    for device_id, raw_config in device_configs.items():
        result = await capture_snapshot(
            session,
            device_id=device_id,
            raw_config=raw_config,
            source=source,
        )
        captured[device_id] = result.content_hash

    for device_id, exc in device_errors.items():
        await _audit_svc.record(
            session,
            actor=actor,
            action=_audit_svc.CONFIG_SNAPSHOT_FAILED,
            target_type="device",
            target_id=str(device_id),
            detail={"error": str(exc), "source": source.value},
        )
        failed[device_id] = exc

    return BackupPassResult(captured=captured, failed=failed)
