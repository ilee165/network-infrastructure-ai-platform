"""Append-only audit writer (brief §7, ADR-0004, ADR-0011).

:func:`record` inserts one :class:`~app.models.audit.AuditLog` row on the
caller's session (flush only — the caller owns the transaction boundary) and
emits one structlog ``info`` event carrying the same fields, so every audited
action appears both in the database trail and in the log stream.

``detail`` is persisted verbatim and logged verbatim: callers must never put
secret material (passwords, keys, decrypted credential payloads) into it —
reference the credential by id instead.
"""

from __future__ import annotations

from typing import Any, Final

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.audit import AuditLog

_logger = get_logger(__name__)

# M1 audit action vocabulary. Routes, services, and engines must reuse these
# constants instead of re-typing the strings.
CREDENTIAL_CREATED: Final = "credential.created"
CREDENTIAL_ROTATED: Final = "credential.rotated"
CREDENTIAL_DECRYPTED: Final = "credential.decrypted"
DEVICE_CREATED: Final = "device.created"
DEVICE_UPDATED: Final = "device.updated"
DEVICE_DELETED: Final = "device.deleted"
DISCOVERY_RUN_STARTED: Final = "discovery.run_started"
DISCOVERY_RUN_FINISHED: Final = "discovery.run_finished"
AUTH_LOGIN: Final = "auth.login"
AUTH_REFRESH: Final = "auth.refresh"
# M3 agent-session audit vocabulary (brief §5/§7): every session start and
# completion is audited, and each reasoning trace produced by the run is linked
# back to the session via a dedicated trace entry (``reasoning_trace_id`` set).
AGENT_SESSION_STARTED: Final = "agent.session_started"
AGENT_SESSION_COMPLETED: Final = "agent.session_completed"
AGENT_TRACE_RECORDED: Final = "agent.trace_recorded"


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | None,
    detail: dict[str, Any] | None,
) -> AuditLog:
    """Append one audit entry and emit the matching structlog event.

    Flushes (assigning ``id`` / ``created_at``) but never commits: the caller
    owns the transaction, so the audit row commits or rolls back atomically
    with the action it describes.
    """
    entry = AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
    )
    session.add(entry)
    await session.flush()
    _logger.info(
        "audit.recorded",
        audit_id=str(entry.id),
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
    )
    return entry
