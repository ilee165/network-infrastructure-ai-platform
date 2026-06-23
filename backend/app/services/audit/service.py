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
# ADR-0028 OIDC / SSO identity-federation audit vocabulary. Each event carries
# the federated actor ``(idp_iss, idp_subject)`` (or ``user:<id>`` for local),
# an outcome, and the request id — and NEVER any token/secret material. The
# ``login_failed`` detail carries a coarse machine reason only, never raw claims
# or tokens (ADR-0028 §3/§5). ``role_mapped`` may carry group *names* and the
# resolved role (authorization decision), but no token material.
AUTH_OIDC_LOGIN_SUCCEEDED: Final = "auth.oidc.login_succeeded"
AUTH_OIDC_LOGIN_FAILED: Final = "auth.oidc.login_failed"
AUTH_OIDC_USER_PROVISIONED: Final = "auth.oidc.user_provisioned"
AUTH_OIDC_ROLE_MAPPED: Final = "auth.oidc.role_mapped"
# Logging in via the fenced local path while OIDC is enabled is the audited,
# alerted break-glass recovery action (ADR-0028 §5).
AUTH_LOCAL_BREAKGLASS_LOGIN: Final = "auth.local.breakglass_login"
# W6-T6 rate-limit + login throttle/lockout audit vocabulary (PRODUCTION.md §5,
# ADR-0028 §2). Each event carries the attempted ``actor`` (``user:<id>`` or the
# attempted username), the source, the request id, and an outcome — and NEVER
# any token material or raw claims, mirroring the ``auth.login_failed`` posture.
# ``auth.rate_limited`` covers an API request or OIDC callback turned away for
# exceeding its budget; ``auth.login_locked`` is the temporary, alerting-friendly
# break-glass lockout once the failed-attempt threshold is crossed.
AUTH_RATE_LIMITED: Final = "auth.rate_limited"
AUTH_LOGIN_LOCKED: Final = "auth.login_locked"
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
# Disabling four-eyes on a CR is a deliberate, separately-audited policy event
# (ADR-0020 §3: "when disabled, the disablement itself is an audited config
# event"), attributing who waived the control — distinct from
# ``change_request.created`` so the waiver is first-class in the audit chain.
CHANGE_REQUEST_FOUR_EYES_WAIVED: Final = "change_request.four_eyes_waived"
CHANGE_REQUEST_DRAFT_TO_PENDING: Final = "change_request.draft_to_pending_approval"
CHANGE_REQUEST_PENDING_TO_APPROVED: Final = "change_request.pending_approval_to_approved"
CHANGE_REQUEST_PENDING_TO_DRAFT: Final = "change_request.pending_approval_to_draft"
CHANGE_REQUEST_APPROVED_TO_EXECUTING: Final = "change_request.approved_to_executing"
CHANGE_REQUEST_EXECUTING_TO_COMPLETED: Final = "change_request.executing_to_completed"
CHANGE_REQUEST_EXECUTING_TO_FAILED: Final = "change_request.executing_to_failed"
CHANGE_REQUEST_FAILED_TO_ROLLED_BACK: Final = "change_request.failed_to_rolled_back"
# M5 Automation Agent audit vocabulary (M5 task #9; ADR-0020 §1/§4, ADR-0021 §3).
# The Automation Agent is the sole executor of approved ChangeRequests: each
# device/DDI write step, each structured rollback, and every refusal of a
# non-``approved`` CR is audited here — distinct from the CR *lifecycle*
# transitions above so the executor's own actions (apply / rollback / refusal)
# are first-class in the audit chain. ``detail`` references the CR / target by id
# and carries only redaction-safe summaries (applied-diff line counts, rollback
# notes) — never the secret-bearing CR ``payload`` (config fragment / DDI body).
AUTOMATION_CHANGE_APPLIED: Final = "automation.change_applied"
AUTOMATION_ROLLBACK: Final = "automation.rollback"
AUTOMATION_ROLLBACK_FAILED: Final = "automation.rollback_failed"
# An executor that is handed a CR not in ``approved`` refuses it (no device/DDI
# write, CR state left untouched) and audits the refusal — the executor never
# acts on a draft/pending/rejected/in-flight/terminal CR (M5-PLAN risk #1).
AUTOMATION_EXECUTION_REFUSED: Final = "automation.execution_refused"
# M5 packet-capture API audit vocabulary (M5 task #15; ADR-0023 §2/§3): an
# engineer launching a capture through the API enqueues the worker-side capture
# task — the request itself is audited at the route (who requested a capture on
# which interface/device), distinct from the worker's ``packet.capture_completed``
# entry. ``detail`` references the device by id and carries no packet payload or
# credential material (the BPF filter is whitelist-validated, never secret).
PACKET_CAPTURE_REQUESTED: Final = "packet.capture_requested"
# P1 W6 KEK wrap/unwrap audit vocabulary (ADR-0032 §5). Every master-key (KEK)
# operation on the credential-vault core path is audited in the same append-only
# audit_log. ``detail`` carries identifiers and KEK versions ONLY — never DEK
# bytes, KEK bytes, the wrapped blob, or a credential_ref value (ADR-0032 §6).
KEK_WRAP: Final = "kek.wrap"
KEK_UNWRAP: Final = "kek.unwrap"
# The fail-closed gate tripped (ADR-0032 §4): the provider was unreachable, so no
# row was written/read unwrapped. ``detail`` carries the coarse reason class only.
KEK_PROVIDER_UNAVAILABLE: Final = "kek.provider.unavailable"
# The active key provider/backend chosen at startup (ADR-0032 §5): after =
# {provider, kek_version} — no key material.
KEK_PROVIDER_SELECT: Final = "kek.provider.select"


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | None,
    detail: dict[str, Any] | None,
    reasoning_trace_id: uuid.UUID | None = None,
    request_id: uuid.UUID | None = None,
) -> AuditLog:
    """Append one audit entry and emit the matching structlog event.

    Flushes (assigning ``id`` / ``created_at``) but never commits: the caller
    owns the transaction, so the audit row commits or rolls back atomically
    with the action it describes.

    ``reasoning_trace_id`` links the audited action back to the reasoning trace
    that produced it (brief §6, ADR-0020 §4) — a plain indexed UUID with no FK
    (``reasoning_traces`` is range-partitioned). It is ``None`` for actions with
    no originating agent run.

    ``request_id`` is the inbound request/correlation id of the call that
    produced the audited action (ADR-0020 §4 names ``request id`` as a required
    dimension of every transition audit entry). It is a plain indexed UUID with
    no FK — captured at the route layer and threaded down here. It is ``None``
    for actions raised outside an HTTP request (background/agent-driven calls
    that carry no inbound correlation id).
    """
    entry = AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        reasoning_trace_id=reasoning_trace_id,
        request_id=request_id,
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
        request_id=str(request_id) if request_id is not None else None,
    )
    return entry
