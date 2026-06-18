"""ChangeRequest lifecycle service (M5 task #3; ADR-0020, brief §7, D11).

The persistent :class:`~app.models.change_requests.ChangeRequest` is the single
spine for every state-changing action (config restore/deploy, DDI record
add/modify/delete). This service is the **only** place that mutates a CR's
lifecycle: every edge of the ADR-0020 §1 state machine is a guarded transition
here, and no UPDATE to ``change_requests.state`` happens outside it.

Lifecycle (ADR-0020 §1)::

    draft --submit--> pending_approval --approve--> approved --claim--> executing
                          |                                              |
                          +--reject--> draft               +--> completed (success)
                                                            +--> failed --rollback--> rolled_back

Terminal states: ``completed`` and ``rolled_back``. ``failed`` is non-terminal —
it transitions to ``rolled_back`` once the structured rollback (ADR-0021)
completes. Illegal transitions raise :class:`~app.core.errors.ConflictError`.

Security posture (ADR-0020 §3 — this service is the *primary* enforcement, the
migration-0007 DB constraint trigger is the backstop, not the only check):

* **Four-eyes (PRIMARY):** :meth:`approve` rejects an approve by the CR's
  requester whenever ``four_eyes_required`` is true (the secure default). The
  predicate ``actor_id != requester_id`` is checked here, before any state write
  and before any ``approvals`` row is inserted, so a four-eyes violation never
  reaches the database at all. The DB constraint trigger re-checks on the
  ``approvals`` insert as defense-in-depth; this guard does not rely on it.
* **RBAC:** authoring/editing, submitting, approving, and rejecting all require
  ``engineer``+ (ADR-0010 §3 / ADR-0020 §5). ``admin`` inherits ``engineer``;
  ``operator`` and ``viewer`` are read-only on the CR lifecycle.
* **Post-submit immutability:** ``requester_id`` and ``four_eyes_required`` are
  frozen once a CR leaves ``draft`` — :meth:`update_draft` refuses to run on a
  non-draft CR and never accepts those fields, so the four-eyes invariant cannot
  be retroactively weakened through the application (ADR-0020 §3, the real
  invariant the DB trigger does *not* guarantee).

Auditing (ADR-0020 §4): every transition writes one ``audit_log`` row via the
shared :func:`app.services.audit.record` helper — action
``change_request.<from>_to_<to>`` (``change_request.created`` for the initial
draft), the actor, the target CR id, before/after lifecycle state in ``detail``,
and the CR's ``reasoning_trace_id`` link when it originated from an agent run.

**Out of scope (by design):** this service performs **no** device or DDI writes.
The ``approved -> executing`` edge is only a lifecycle handoff; the Automation
Agent (M5 Wave 4) is the sole executor of approved changes and calls
:meth:`mark_executing` / :meth:`mark_completed` / :meth:`mark_failed` /
:meth:`mark_rolled_back` to drive the post-approval lifecycle.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import ConflictError, ForbiddenError, NotFoundError
from app.core.logging import get_logger
from app.core.security import Role
from app.models.change_requests import (
    Approval,
    ApprovalDecision,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.services.audit import service as audit

_logger = get_logger(__name__)

#: Minimum role for any CR lifecycle action — author/edit/submit/approve/reject
#: are all ``engineer`` capabilities (ADR-0010 §3, ADR-0020 §5). ``admin``
#: inherits via :meth:`Role.can_act_as`. Execution handoffs (``mark_*``) are not
#: human actions — they are driven by the Automation Agent service-to-service.
_MIN_LIFECYCLE_ROLE: Role = Role.ENGINEER

#: ``state``-machine edges keyed by the legal *from* state, with the audit action
#: that documents the transition. The single source of truth for "what may follow
#: what"; every transition validates against it before writing.
_TARGET_TYPE = "change_request"


class ChangeRequestService:
    """Owns the guarded lifecycle of every :class:`ChangeRequest` (ADR-0020).

    Takes an :class:`async_sessionmaker` (not a request-scoped session): each
    transition commits in its own short transaction together with its audit row
    and any ``approvals`` row, so the audit trail and the state change are
    atomic (ADR-0011 §2 / ADR-0020 §4).
    """

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    # -- reads ---------------------------------------------------------------

    async def get(self, cr_id: uuid.UUID) -> ChangeRequest:
        """Reload the CR row or raise :class:`NotFoundError`."""
        async with self._sessionmaker() as session:
            row = await session.get(ChangeRequest, cr_id)
            if row is None:
                raise NotFoundError(f"change request '{cr_id}' does not exist")
            return row

    # -- authoring (draft) ---------------------------------------------------

    async def create_draft(
        self,
        *,
        requester_id: uuid.UUID,
        actor_role: Role,
        kind: ChangeRequestKind,
        payload: dict[str, Any] | None = None,
        target_refs: dict[str, Any] | None = None,
        rollback_plan: dict[str, Any] | None = None,
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        four_eyes_required: bool = True,
        generating_session_id: uuid.UUID | None = None,
        reasoning_trace_id: uuid.UUID | None = None,
    ) -> ChangeRequest:
        """Author a new CR in ``draft`` (engineer+; ADR-0020 §5).

        ``four_eyes_required`` defaults to ``True`` (secure by default) and may
        only be set here — it is frozen at submit (ADR-0020 §3). Audited as
        ``change_request.created``.
        """
        self._require_role(actor_role, action="author a change request")
        async with self._sessionmaker() as session:
            cr = ChangeRequest(
                state=ChangeRequestState.DRAFT,
                kind=kind,
                requester_id=requester_id,
                generating_session_id=generating_session_id,
                payload=payload,
                target_refs=target_refs,
                rollback_plan=rollback_plan,
                before_state=before_state,
                after_state=after_state,
                four_eyes_required=four_eyes_required,
                reasoning_trace_id=reasoning_trace_id,
            )
            session.add(cr)
            await session.flush()
            await audit.record(
                session,
                actor=f"user:{requester_id}",
                action=audit.CHANGE_REQUEST_CREATED,
                target_type=_TARGET_TYPE,
                target_id=str(cr.id),
                detail={"kind": kind.value, "four_eyes_required": four_eyes_required},
                reasoning_trace_id=reasoning_trace_id,
            )
            await session.commit()
            cr_id = cr.id
        _logger.info("change_request.created", cr_id=str(cr_id), requester_id=str(requester_id))
        return await self.get(cr_id)

    async def update_draft(
        self,
        cr_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        actor_role: Role,
        payload: dict[str, Any] | None = None,
        target_refs: dict[str, Any] | None = None,
        rollback_plan: dict[str, Any] | None = None,
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
    ) -> ChangeRequest:
        """Edit a CR's execution inputs while it is still in ``draft`` (engineer+).

        Refuses on any non-``draft`` CR (post-submit immutability, ADR-0020 §3).
        ``requester_id`` and ``four_eyes_required`` are intentionally *not*
        parameters — they can never be changed after :meth:`create_draft`.
        Only fields passed (not ``None``) are overwritten.
        """
        self._require_role(actor_role, action="edit a change request")
        async with self._sessionmaker() as session:
            cr = await self._load(session, cr_id)
            if cr.state is not ChangeRequestState.DRAFT:
                raise ConflictError(
                    f"change request '{cr_id}' is {cr.state.value}; only a draft may be edited "
                    "(re-editing an approved/submitted CR requires reject -> draft)"
                )
            if payload is not None:
                cr.payload = payload
            if target_refs is not None:
                cr.target_refs = target_refs
            if rollback_plan is not None:
                cr.rollback_plan = rollback_plan
            if before_state is not None:
                cr.before_state = before_state
            if after_state is not None:
                cr.after_state = after_state
            await session.commit()
        return await self.get(cr_id)

    # -- submit / approve / reject ------------------------------------------

    async def submit(
        self, cr_id: uuid.UUID, *, actor_id: uuid.UUID, actor_role: Role
    ) -> ChangeRequest:
        """``draft -> pending_approval`` (engineer+; ADR-0020 §1)."""
        self._require_role(actor_role, action="submit a change request")
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.DRAFT,
            new=ChangeRequestState.PENDING_APPROVAL,
            action=audit.CHANGE_REQUEST_DRAFT_TO_PENDING,
            actor_id=actor_id,
        )

    async def approve(
        self,
        cr_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        actor_role: Role,
        comment: str | None = None,
    ) -> ChangeRequest:
        """``pending_approval -> approved`` — PRIMARY four-eyes guard (ADR-0020 §3).

        Rejects with :class:`ForbiddenError` when ``four_eyes_required`` is true
        and ``actor_id == requester_id`` — checked **before** any state write or
        ``approvals`` insert, so a self-approval never reaches the database. Writes
        one append-only ``approvals`` row (``decision = approve``) and the
        transition audit entry, both atomic with the state change.
        """
        self._require_role(actor_role, action="approve a change request")
        async with self._sessionmaker() as session:
            cr = await self._load(session, cr_id)
            self._require_state(cr, ChangeRequestState.PENDING_APPROVAL, "approve")
            # PRIMARY four-eyes enforcement (ADR-0020 §3): the predicate is checked
            # here, in the service guard, not left to the DB trigger backstop.
            if cr.four_eyes_required and actor_id == cr.requester_id:
                raise ForbiddenError(
                    "four-eyes violation: the approver must differ from the requester "
                    f"for change request '{cr_id}'"
                )
            session.add(
                Approval(
                    change_request_id=cr.id,
                    actor_id=actor_id,
                    decision=ApprovalDecision.APPROVE,
                    comment=comment,
                )
            )
            await self._apply_transition(
                session,
                cr,
                new=ChangeRequestState.APPROVED,
                action=audit.CHANGE_REQUEST_PENDING_TO_APPROVED,
                actor_id=actor_id,
            )
            await session.commit()
        return await self.get(cr_id)

    async def reject(
        self,
        cr_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        actor_role: Role,
        comment: str | None = None,
    ) -> ChangeRequest:
        """``pending_approval -> draft`` (engineer+; ADR-0020 §1).

        Four-eyes constrains *approve*, not *reject* — the requester may withdraw
        their own CR. Writes the ``reject`` decision row + the transition audit.
        """
        self._require_role(actor_role, action="reject a change request")
        async with self._sessionmaker() as session:
            cr = await self._load(session, cr_id)
            self._require_state(cr, ChangeRequestState.PENDING_APPROVAL, "reject")
            session.add(
                Approval(
                    change_request_id=cr.id,
                    actor_id=actor_id,
                    decision=ApprovalDecision.REJECT,
                    comment=comment,
                )
            )
            await self._apply_transition(
                session,
                cr,
                new=ChangeRequestState.DRAFT,
                action=audit.CHANGE_REQUEST_PENDING_TO_DRAFT,
                actor_id=actor_id,
            )
            await session.commit()
        return await self.get(cr_id)

    # -- execution handoffs (Automation Agent; no device/DDI writes here) ----

    async def mark_executing(self, cr_id: uuid.UUID) -> ChangeRequest:
        """``approved -> executing`` — the Automation Agent claims the CR (ADR-0021).

        A lifecycle handoff only: this service performs no device/DDI write.
        """
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.APPROVED,
            new=ChangeRequestState.EXECUTING,
            action=audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
            actor_id=None,
        )

    async def mark_completed(
        self, cr_id: uuid.UUID, *, after_state: dict[str, Any] | None = None
    ) -> ChangeRequest:
        """``executing -> completed`` (terminal). Optional ``after_state`` records the
        post-apply verified diff (ADR-0020 §4)."""
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.EXECUTING,
            new=ChangeRequestState.COMPLETED,
            action=audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED,
            actor_id=None,
            after_state=after_state,
        )

    async def mark_failed(
        self, cr_id: uuid.UUID, *, after_state: dict[str, Any] | None = None
    ) -> ChangeRequest:
        """``executing -> failed`` (non-terminal — rollback may follow, ADR-0021)."""
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.EXECUTING,
            new=ChangeRequestState.FAILED,
            action=audit.CHANGE_REQUEST_EXECUTING_TO_FAILED,
            actor_id=None,
            after_state=after_state,
        )

    async def mark_rolled_back(self, cr_id: uuid.UUID) -> ChangeRequest:
        """``failed -> rolled_back`` (terminal) once the structured rollback completes."""
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.FAILED,
            new=ChangeRequestState.ROLLED_BACK,
            action=audit.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK,
            actor_id=None,
        )

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _require_role(actor_role: Role, *, action: str) -> None:
        """Deny any actor below ``engineer`` (ADR-0010 §3, ADR-0020 §5)."""
        if not actor_role.can_act_as(_MIN_LIFECYCLE_ROLE):
            raise ForbiddenError(
                f"role '{actor_role.value}' may not {action}; "
                f"'{_MIN_LIFECYCLE_ROLE.value}' or higher is required"
            )

    @staticmethod
    def _require_state(cr: ChangeRequest, expected: ChangeRequestState, verb: str) -> None:
        """Reject an illegal transition: the CR must be in *expected* to *verb*."""
        if cr.state is not expected:
            raise ConflictError(
                f"cannot {verb} change request '{cr.id}': it is '{cr.state.value}', "
                f"expected '{expected.value}'"
            )

    async def _load(self, session: AsyncSession, cr_id: uuid.UUID) -> ChangeRequest:
        cr = await session.get(ChangeRequest, cr_id)
        if cr is None:
            raise NotFoundError(f"change request '{cr_id}' does not exist")
        return cr

    async def _transition(
        self,
        cr_id: uuid.UUID,
        *,
        expected: ChangeRequestState,
        new: ChangeRequestState,
        action: str,
        actor_id: uuid.UUID | None,
        after_state: dict[str, Any] | None = None,
    ) -> ChangeRequest:
        """Load, validate the *from* state, apply *new* + audit, commit."""
        async with self._sessionmaker() as session:
            cr = await self._load(session, cr_id)
            self._require_state(cr, expected, action)
            if after_state is not None:
                cr.after_state = after_state
            await self._apply_transition(session, cr, new=new, action=action, actor_id=actor_id)
            await session.commit()
        return await self.get(cr_id)

    async def _apply_transition(
        self,
        session: AsyncSession,
        cr: ChangeRequest,
        *,
        new: ChangeRequestState,
        action: str,
        actor_id: uuid.UUID | None,
    ) -> None:
        """Mutate ``state`` and write the before/after-stamped, trace-linked audit row.

        The caller has already validated the *from* state and owns the commit.
        ``detail`` carries the before/after lifecycle state (the audited
        transition, ADR-0020 §4) — never the secret-bearing CR ``payload``.
        """
        before = cr.state
        cr.state = new
        actor = f"user:{actor_id}" if actor_id is not None else "agent:automation"
        await audit.record(
            session,
            actor=actor,
            action=action,
            target_type=_TARGET_TYPE,
            target_id=str(cr.id),
            detail={"before_state": before.value, "after_state": new.value},
            reasoning_trace_id=cr.reasoning_trace_id,
        )
        _logger.info(
            "change_request.transition",
            cr_id=str(cr.id),
            before=before.value,
            after=new.value,
            actor=actor,
        )
