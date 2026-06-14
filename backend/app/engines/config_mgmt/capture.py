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
from dataclasses import dataclass
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ConfigSnapshot, ConfigSource
from app.models.mixins import utcnow

__all__ = ["CaptureResult", "capture_snapshot", "hash_config", "normalize_config"]

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
