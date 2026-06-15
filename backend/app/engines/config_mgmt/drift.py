"""Configuration drift detection (M4; ADR-0017 §4).

Drift is defined as the **unified diff** (:mod:`difflib`) of a device's
*current* configuration snapshot against its *approved baseline* snapshot. A
non-empty diff is a drift event; the changed hunks are recorded so the
Configuration Agent (M4 task 9) can explain *what* changed and reference the
exact lines.

Two operations live here:

* :func:`approve_baseline` — promote one snapshot to the device's baseline. This
  is the **explicit, audited** action ADR-0017 §4 requires: any prior baseline
  for the device is demoted (exactly one baseline per device) and an
  ``config.baseline_approved`` :class:`~app.models.audit.AuditLog` entry is
  appended. The audit ``detail`` references the snapshot by id/hash only — never
  the secret-bearing config content.
* :func:`detect_drift` — diff the latest captured snapshot against the baseline.

The diff runs over the **raw, unredacted** snapshot ``content`` for server-side
fidelity: a security-relevant out-of-band change (a new SNMP community, a
changed enable secret) *must* surface as drift, so redaction would defeat the
check. The A9 redaction layer applies only later, at the LLM boundary, when the
Configuration Agent explains a diff — never here.

No Celery wiring and no transport I/O: this is pure logic over the persistence
layer, unit-testable against an in-memory database.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ConfigSnapshot
from app.services.audit import service as audit
from app.services.audit.service import CONFIG_SNAPSHOT_DRIFT_CHECKED

__all__ = [
    "DriftResult",
    "NoBaselineError",
    "approve_baseline",
    "detect_drift",
]

logger = structlog.get_logger(__name__)

# difflib emits a hunk header line starting with ``@@`` per changed region; we
# split the unified diff on these to count and surface the changed hunks.
_HUNK_MARKER = "@@"


class NoBaselineError(Exception):
    """Raised when a drift check is requested for a device with no baseline.

    Drift is defined relative to an *approved* baseline; until an engineer
    explicitly approves one (:func:`approve_baseline`), there is nothing to diff
    against and the caller must surface this distinctly from "no drift".
    """

    def __init__(self, device_id: UUID) -> None:
        self.device_id = device_id
        super().__init__(f"device {device_id} has no approved baseline snapshot")


@dataclass(frozen=True)
class DriftResult:
    """Outcome of one drift check.

    ``has_drift`` is ``True`` iff the unified ``diff`` is non-empty (the current
    config differs from the approved baseline). ``hunks`` holds each changed
    region of the diff (one entry per ``@@`` hunk) so a caller can record or
    explain exactly the lines that changed. ``baseline_hash`` / ``current_hash``
    identify the two snapshots compared, letting callers log/audit the drift by
    content identity without touching the secret-bearing content.
    """

    device_id: UUID
    has_drift: bool
    diff: str
    hunks: list[str]
    baseline_hash: str
    current_hash: str


async def _latest_snapshot(session: AsyncSession, device_id: UUID) -> ConfigSnapshot | None:
    """The most recently captured snapshot for a device, or ``None``.

    Ordered by ``captured_at`` then ``created_at`` (both descending) so the
    newest observation wins even when two captures share a ``captured_at``.
    """
    return (
        await session.execute(
            select(ConfigSnapshot)
            .where(ConfigSnapshot.device_id == device_id)
            .order_by(
                ConfigSnapshot.captured_at.desc(),
                ConfigSnapshot.created_at.desc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()


async def _baseline_snapshot(session: AsyncSession, device_id: UUID) -> ConfigSnapshot | None:
    """The device's approved baseline snapshot, or ``None`` if none is set."""
    return (
        await session.execute(
            select(ConfigSnapshot).where(
                ConfigSnapshot.device_id == device_id,
                ConfigSnapshot.baseline.is_(True),
            )
        )
    ).scalar_one_or_none()


async def approve_baseline(
    session: AsyncSession,
    *,
    snapshot: ConfigSnapshot,
    actor: str,
) -> None:
    """Promote *snapshot* to its device's drift baseline (explicit + audited).

    Any prior baseline for the same device is demoted first, so a device always
    has at most one baseline. An ``config.baseline_approved`` audit entry is
    appended referencing the snapshot by id and ``content_hash`` only — the
    config content (secret-bearing) never enters the audit trail.

    The caller owns the transaction boundary (this only flushes), so the
    baseline flip and its audit row commit or roll back atomically.
    """
    await session.execute(
        update(ConfigSnapshot)
        .where(
            ConfigSnapshot.device_id == snapshot.device_id,
            ConfigSnapshot.baseline.is_(True),
            ConfigSnapshot.id != snapshot.id,
        )
        .values(baseline=False)
    )
    snapshot.baseline = True
    await session.flush()

    await audit.record(
        session,
        actor=actor,
        action=audit.CONFIG_BASELINE_APPROVED,
        target_type="config_snapshot",
        target_id=str(snapshot.id),
        detail={
            "device_id": str(snapshot.device_id),
            "content_hash": snapshot.content_hash,
        },
    )
    logger.info(
        "config.baseline_approved",
        device_id=str(snapshot.device_id),
        snapshot_id=str(snapshot.id),
        content_hash=snapshot.content_hash,
        actor=actor,
    )


def _split_hunks(unified_diff: str) -> list[str]:
    """Split a unified diff into its changed hunks (one per ``@@`` header)."""
    if not unified_diff:
        return []
    hunks: list[str] = []
    current: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith(_HUNK_MARKER):
            if current:
                hunks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        hunks.append("\n".join(current))
    return hunks


async def detect_drift(
    session: AsyncSession,
    *,
    device_id: UUID,
    actor: str,
) -> DriftResult:
    """Diff a device's latest snapshot against its approved baseline.

    Computes a unified ``difflib`` diff of the baseline ``content`` against the
    most recently captured ``content`` (both **raw, unredacted** — fidelity over
    secrecy at the storage boundary). A non-empty diff is drift; the changed
    hunks are returned for recording/explanation.

    Because this operation reads the raw, secret-bearing ``content`` fields of
    both snapshots, ADR-0017 §2 classifies it as a read/decrypt-equivalent
    access.  An ``config.snapshot_drift_checked`` :class:`~app.models.audit.AuditLog`
    row is therefore appended and committed after the diff is computed.  The
    audit ``detail`` references snapshots by id/hash only — config content never
    enters the detail payload.  The engine owns and commits its audit row; the
    caller does not need to commit after this function returns.

    :param actor: Identity of the requesting user; forwarded to the audit row
        (mirrors :func:`approve_baseline`'s signature).
    :raises NoBaselineError: if the device has no approved baseline to diff
        against — distinct from "no drift".
    """
    baseline = await _baseline_snapshot(session, device_id)
    if baseline is None:
        raise NoBaselineError(device_id)

    current = await _latest_snapshot(session, device_id)
    # A baseline exists, so at least one snapshot exists; narrow for the type
    # checker and guard defensively.
    if current is None:  # pragma: no cover - baseline implies a snapshot exists
        current = baseline

    diff_lines = difflib.unified_diff(
        baseline.content.splitlines(),
        current.content.splitlines(),
        fromfile=f"baseline:{baseline.content_hash[:12]}",
        tofile=f"current:{current.content_hash[:12]}",
        lineterm="",
    )
    diff = "\n".join(diff_lines)
    hunks = _split_hunks(diff)
    has_drift = bool(hunks)

    await audit.record(
        session,
        actor=actor,
        action=CONFIG_SNAPSHOT_DRIFT_CHECKED,
        target_type="config_snapshot",
        target_id=str(baseline.id),
        detail={
            "device_id": str(device_id),
            "baseline_hash": baseline.content_hash,
            "current_hash": current.content_hash,
            "has_drift": has_drift,
            "hunk_count": len(hunks),
        },
    )
    await session.commit()

    logger.info(
        "config.drift_checked",
        device_id=str(device_id),
        has_drift=has_drift,
        baseline_hash=baseline.content_hash,
        current_hash=current.content_hash,
        hunks=len(hunks),
    )
    return DriftResult(
        device_id=device_id,
        has_drift=has_drift,
        diff=diff,
        hunks=hunks,
        baseline_hash=baseline.content_hash,
        current_hash=current.content_hash,
    )
