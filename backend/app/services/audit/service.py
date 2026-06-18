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

import uuid
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
# Auth & Account UI audit vocabulary (B1): authentication lifecycle, server-side
# session revocation, admin user management, and settings changes. As with every
# other constant here, ``detail`` must never carry a password hash or secret.
AUTH_LOGOUT: Final = "auth.logout"
AUTH_LOGIN_FAILED: Final = "auth.login_failed"
AUTH_PASSWORD_CHANGED: Final = "auth.password_changed"
AUTH_SESSION_REVOKED: Final = "auth.session_revoked"
USER_CREATED: Final = "user.created"
USER_UPDATED: Final = "user.updated"
USER_ROLE_CHANGED: Final = "user.role_changed"
USER_PASSWORD_RESET: Final = "user.password_reset"
SETTINGS_UPDATED: Final = "settings.updated"
# M4 config-management audit vocabulary (ADR-0017 §4): approving a snapshot as a
# device's drift baseline is an explicit, audited action. ``detail`` references
# the snapshot by id/hash only — never the (secret-bearing) config content.
# Reading raw (unredacted) snapshot content for a drift check is a
# read/decrypt-equivalent access and must also appear in the persistent audit
# trail (ADR-0017 §2).
CONFIG_BASELINE_APPROVED: Final = "config.baseline_approved"
CONFIG_SNAPSHOT_DRIFT_CHECKED: Final = "config.snapshot_drift_checked"
# An engineer explicitly fetching the raw (unredacted) snapshot content via the
# API is audited as a distinct action from a drift check (ADR-0017 §2).
CONFIG_SNAPSHOT_CONTENT_READ: Final = "config.snapshot_content_read"
# A capture attempt that could not produce a snapshot (transport failure, missing
# credential, unsupported vendor) — the device is identified by id; no config
# content or credential material appears in the audit detail.
CONFIG_SNAPSHOT_FAILED: Final = "config.snapshot_failed"
# M5 ChangeRequest lifecycle audit vocabulary (ADR-0020 §4): every guarded
# state transition writes one audit entry whose action is
# ``change_request.<from>_to_<to>`` (and ``change_request.created`` for the
# initial draft), carrying before/after lifecycle state in ``detail`` and the
# reasoning-trace link when the CR originated from an agent run. ``detail``
# references the CR / target devices by id only — a CR ``payload`` may carry
# secret-bearing config/DNS content and must never appear here verbatim.
CHANGE_REQUEST_CREATED: Final = "change_request.created"
CHANGE_REQUEST_DRAFT_TO_PENDING: Final = "change_request.draft_to_pending_approval"
CHANGE_REQUEST_PENDING_TO_APPROVED: Final = "change_request.pending_approval_to_approved"
CHANGE_REQUEST_PENDING_TO_DRAFT: Final = "change_request.pending_approval_to_draft"
CHANGE_REQUEST_APPROVED_TO_EXECUTING: Final = "change_request.approved_to_executing"
CHANGE_REQUEST_EXECUTING_TO_COMPLETED: Final = "change_request.executing_to_completed"
CHANGE_REQUEST_EXECUTING_TO_FAILED: Final = "change_request.executing_to_failed"
CHANGE_REQUEST_FAILED_TO_ROLLED_BACK: Final = "change_request.failed_to_rolled_back"


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | None,
    detail: dict[str, Any] | None,
    reasoning_trace_id: uuid.UUID | None = None,
) -> AuditLog:
    """Append one audit entry and emit the matching structlog event.

    Flushes (assigning ``id`` / ``created_at``) but never commits: the caller
    owns the transaction, so the audit row commits or rolls back atomically
    with the action it describes.

    ``reasoning_trace_id`` links the audited action back to the reasoning trace
    that produced it (brief §6, ADR-0020 §4) — a plain indexed UUID with no FK
    (``reasoning_traces`` is range-partitioned). It is ``None`` for actions with
    no originating agent run.
    """
    entry = AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        reasoning_trace_id=reasoning_trace_id,
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
        reasoning_trace_id=str(reasoning_trace_id) if reasoning_trace_id is not None else None,
    )
    return entry
