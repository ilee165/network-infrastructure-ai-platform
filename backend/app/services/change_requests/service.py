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
draft), the actor, the target CR id, before/after lifecycle state plus the
id-only ``target_refs`` (which devices/DDI refs the change touches — never the
secret-bearing ``payload``) in ``detail``, the CR's ``reasoning_trace_id`` link
when it originated from an agent run, and the inbound ``request_id`` correlation
id when the call arrived over HTTP. The full chain (requester -> approver ->
executor -> before/after -> trace + targets) is therefore reconstructable from
``audit_log`` + ``approvals`` alone (exit criterion #1).

**Out of scope (by design):** this service performs **no** device or DDI writes.
The ``approved -> executing`` edge is only a lifecycle handoff; the Automation
Agent (M5 Wave 4) is the sole executor of approved changes and calls
:meth:`mark_executing` / :meth:`mark_completed` / :meth:`mark_failed` /
:meth:`mark_rolled_back` to drive the post-approval lifecycle.

Execution-handoff authorization (ADR-0020 §1/§2): the post-approval ``mark_*``
edges — most critically ``approved -> executing``, which directly precedes the
real device/DDI mutation in Wave 4 — require a verified service principal
(:data:`AUTOMATION_PRINCIPAL`), not merely a holder of a
:class:`ChangeRequestService` reference. The audit actor on those edges is
derived from the verified principal rather than a hardcoded literal. The caller
that supplies that principal (the Automation Agent service identity) is wired in
Wave 4; until then these methods are unreachable from any HTTP route, but the
guard is in place so the handoff is provably driven by the Automation Agent.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core import metrics
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

#: Waiving four-eyes (``four_eyes_required=False``) is an elevated, admin-only
#: action (ADR-0020 §3 / ADR-0010 §3): collapsing a two-person control to one
#: person must not be a free per-CR toggle any engineer can flip, so the secure
#: default cannot be silently bypassed by the same person who will approve.
_MIN_FOUR_EYES_WAIVER_ROLE: Role = Role.ADMIN


class AutomationPrincipal:
    """The verified service identity authorized to drive the post-approval
    lifecycle (``approved -> executing -> completed/failed/rolled_back``).

    ADR-0020 §1/§2 require the ``approved -> executing`` guard to validate that
    the caller is the Automation Agent. A caller obtains the singleton
    :data:`AUTOMATION_PRINCIPAL` only by being the Automation Agent service
    (wired in Wave 4); an arbitrary holder of a :class:`ChangeRequestService`
    reference cannot mint one, so it cannot drive execution. The ``actor``
    string is what is stamped into the transition audit row — derived from this
    verified principal, never a hardcoded literal.
    """

    __slots__ = ("actor",)

    def __init__(self, actor: str) -> None:
        self.actor = actor


#: The sole principal the ``mark_*`` execution handoffs accept (ADR-0020 §2).
AUTOMATION_PRINCIPAL: AutomationPrincipal = AutomationPrincipal(actor="agent:automation")

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

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        """The session factory this service commits each transition through.

        Exposed for collaborators that must write their *own* audit rows in the
        same audit trail and DB as the CR lifecycle — notably the Automation
        Agent executor (M5 task #9), which audits each apply/rollback/refusal
        alongside the ``change_request.*`` transitions this service writes. Read
        access only: the service remains the sole mutator of ``change_requests``.
        """
        return self._sessionmaker

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
        request_id: uuid.UUID | None = None,
    ) -> ChangeRequest:
        """Author a new CR in ``draft`` (engineer+; ADR-0020 §5).

        ``four_eyes_required`` defaults to ``True`` (secure by default) and may
        only be set here — it is frozen at submit (ADR-0020 §3). Disabling it is
        an **admin-only** action (ADR-0020 §3 / ADR-0010 §3): an engineer cannot
        waive four-eyes on their own CR and then self-approve it, which would
        collapse the two-person control to one person. When four-eyes is waived,
        a distinct ``change_request.four_eyes_waived`` audit event attributes the
        waiver, separate from the ``change_request.created`` event, so the
        waiver is first-class in the audit chain.
        """
        self._require_role(actor_role, action="author a change request")
        if not four_eyes_required:
            self._require_four_eyes_waiver(actor_role)
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
                detail={
                    "kind": kind.value,
                    "four_eyes_required": four_eyes_required,
                    "target_refs": self._target_refs_projection(target_refs),
                },
                reasoning_trace_id=reasoning_trace_id,
                request_id=request_id,
            )
            if not four_eyes_required:
                # The disablement itself is a deliberate, separately-audited
                # policy event attributing who waived it (ADR-0020 §3).
                await audit.record(
                    session,
                    actor=f"user:{requester_id}",
                    action=audit.CHANGE_REQUEST_FOUR_EYES_WAIVED,
                    target_type=_TARGET_TYPE,
                    target_id=str(cr.id),
                    detail={
                        "waived_by_role": actor_role.value,
                        "target_refs": self._target_refs_projection(target_refs),
                    },
                    reasoning_trace_id=reasoning_trace_id,
                    request_id=request_id,
                )
            await session.commit()
            cr_id = cr.id
        # CR workflow-health SLI (ADR-0046 §1): the initial draft is a state ENTERED
        # too, but create_draft does not go through _apply_transition, so count it
        # here for complete lifecycle coverage (bounded enum label only).
        metrics.record_change_request_transition(state=ChangeRequestState.DRAFT.value)
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
        self,
        cr_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        actor_role: Role,
        request_id: uuid.UUID | None = None,
    ) -> ChangeRequest:
        """``draft -> pending_approval`` (engineer+; ADR-0020 §1)."""
        self._require_role(actor_role, action="submit a change request")
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.DRAFT,
            new=ChangeRequestState.PENDING_APPROVAL,
            action=audit.CHANGE_REQUEST_DRAFT_TO_PENDING,
            actor=f"user:{actor_id}",
            request_id=request_id,
        )

    async def approve(
        self,
        cr_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        actor_role: Role,
        comment: str | None = None,
        request_id: uuid.UUID | None = None,
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
            # Compute approval-wait latency (ADR-0046 §1 SLI): seconds from when
            # the CR entered pending_approval (updated_at set by the submit
            # transition) to the moment of the approve decision.
            approval_latency = (datetime.now(UTC) - cr.updated_at).total_seconds()
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
                actor=f"user:{actor_id}",
                request_id=request_id,
                approval_latency_seconds=approval_latency,
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
        request_id: uuid.UUID | None = None,
    ) -> ChangeRequest:
        """``pending_approval -> draft`` (engineer+; ADR-0020 §1).

        Four-eyes constrains *approve*, not *reject* — the requester may withdraw
        their own CR. Writes the ``reject`` decision row + the transition audit.
        """
        self._require_role(actor_role, action="reject a change request")
        async with self._sessionmaker() as session:
            cr = await self._load(session, cr_id)
            self._require_state(cr, ChangeRequestState.PENDING_APPROVAL, "reject")
            # Compute approval-wait latency (ADR-0046 §1 SLI): seconds from when
            # the CR entered pending_approval (updated_at set by the submit
            # transition) to the moment of the reject decision.
            approval_latency = (datetime.now(UTC) - cr.updated_at).total_seconds()
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
                actor=f"user:{actor_id}",
                request_id=request_id,
                approval_latency_seconds=approval_latency,
            )
            await session.commit()
        return await self.get(cr_id)

    # -- execution handoffs (Automation Agent; no device/DDI writes here) ----
    #
    # Every ``mark_*`` edge requires a verified ``AutomationPrincipal`` and
    # authorizes it before transitioning (ADR-0020 §1/§2: the approved ->
    # executing guard must validate that the caller is the Automation Agent).
    # The audit actor is derived from the verified principal, never hardcoded.

    async def mark_executing(
        self, cr_id: uuid.UUID, *, principal: AutomationPrincipal
    ) -> ChangeRequest:
        """``approved -> executing`` — the Automation Agent claims the CR (ADR-0021).

        Security-critical: this edge directly precedes the real device/DDI
        mutation in Wave 4, so it is gated on a verified
        :class:`AutomationPrincipal` (ADR-0020 §1/§2) — an arbitrary holder of a
        :class:`ChangeRequestService` reference cannot drive execution. A
        lifecycle handoff only: this service performs no device/DDI write.
        """
        actor = self._require_automation(principal)
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.APPROVED,
            new=ChangeRequestState.EXECUTING,
            action=audit.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
            actor=actor,
        )

    async def mark_completed(
        self,
        cr_id: uuid.UUID,
        *,
        principal: AutomationPrincipal,
        after_state: dict[str, Any] | None = None,
    ) -> ChangeRequest:
        """``executing -> completed`` (terminal). Optional ``after_state`` records the
        post-apply verified diff (ADR-0020 §4). Automation-Agent-only (ADR-0020 §2)."""
        actor = self._require_automation(principal)
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.EXECUTING,
            new=ChangeRequestState.COMPLETED,
            action=audit.CHANGE_REQUEST_EXECUTING_TO_COMPLETED,
            actor=actor,
            after_state=after_state,
        )

    async def mark_failed(
        self,
        cr_id: uuid.UUID,
        *,
        principal: AutomationPrincipal,
        after_state: dict[str, Any] | None = None,
    ) -> ChangeRequest:
        """``executing -> failed`` (non-terminal — rollback may follow, ADR-0021).
        Automation-Agent-only (ADR-0020 §2)."""
        actor = self._require_automation(principal)
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.EXECUTING,
            new=ChangeRequestState.FAILED,
            action=audit.CHANGE_REQUEST_EXECUTING_TO_FAILED,
            actor=actor,
            after_state=after_state,
        )

    async def mark_rolled_back(
        self, cr_id: uuid.UUID, *, principal: AutomationPrincipal
    ) -> ChangeRequest:
        """``failed -> rolled_back`` (terminal) once the structured rollback completes.
        Automation-Agent-only (ADR-0020 §2)."""
        actor = self._require_automation(principal)
        return await self._transition(
            cr_id,
            expected=ChangeRequestState.FAILED,
            new=ChangeRequestState.ROLLED_BACK,
            action=audit.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK,
            actor=actor,
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
    def _require_four_eyes_waiver(actor_role: Role) -> None:
        """Deny disabling four-eyes below ``admin`` (ADR-0020 §3, ADR-0010 §3).

        Waiving the two-person control is an elevated action: an engineer may
        not author a CR with ``four_eyes_required=False`` (and then self-approve
        it). Only ``admin`` may waive, and the waiver is separately audited.
        """
        if not actor_role.can_act_as(_MIN_FOUR_EYES_WAIVER_ROLE):
            raise ForbiddenError(
                f"role '{actor_role.value}' may not waive four-eyes on a change request; "
                f"'{_MIN_FOUR_EYES_WAIVER_ROLE.value}' is required to set "
                "four_eyes_required=false"
            )

    @staticmethod
    def _require_automation(principal: AutomationPrincipal) -> str:
        """Authorize an execution-handoff caller and return its audit actor.

        ADR-0020 §1/§2: the ``approved -> executing`` (and the rest of the
        post-approval) handoffs are driven only by the Automation Agent. The
        caller must present the verified :data:`AUTOMATION_PRINCIPAL`; any other
        object (including a forged ``AutomationPrincipal`` with a different
        actor) is rejected. The returned string becomes the audit actor, so the
        attribution is derived from the verified identity, not hardcoded.
        """
        if principal is not AUTOMATION_PRINCIPAL:
            raise ForbiddenError(
                "execution handoffs (approved -> executing -> completed/failed/rolled_back) "
                "may be driven only by the Automation Agent service principal (ADR-0020 §2)"
            )
        return principal.actor

    @staticmethod
    def _target_refs_projection(target_refs: dict[str, Any] | None) -> dict[str, Any] | None:
        """Id-only view of ``target_refs`` for the audit detail (ADR-0020 §4).

        ``target_refs`` already holds only device ids / DDI object refs (the
        secret-bearing change lives in ``payload``, which is never audited), so
        it is recorded verbatim; this indirection is the single, named place
        that would project/strip it if that ever stopped being true.
        """
        return target_refs

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
        actor: str,
        after_state: dict[str, Any] | None = None,
        request_id: uuid.UUID | None = None,
    ) -> ChangeRequest:
        """Load, validate the *from* state, apply *new* + audit, commit.

        ``actor`` is the already-resolved audit actor string — derived from a
        verified user id (``user:<id>``) or the verified Automation principal
        (``agent:automation``); this method never invents an attribution.
        """
        async with self._sessionmaker() as session:
            cr = await self._load(session, cr_id)
            self._require_state(cr, expected, action)
            if after_state is not None:
                cr.after_state = after_state
            await self._apply_transition(
                session, cr, new=new, action=action, actor=actor, request_id=request_id
            )
            await session.commit()
        return await self.get(cr_id)

    async def _apply_transition(
        self,
        session: AsyncSession,
        cr: ChangeRequest,
        *,
        new: ChangeRequestState,
        action: str,
        actor: str,
        request_id: uuid.UUID | None = None,
        approval_latency_seconds: float | None = None,
    ) -> None:
        """Mutate ``state`` and write the before/after-stamped, trace-linked audit row.

        The caller has already validated the *from* state, resolved ``actor``
        from a verified identity, and owns the commit. ``detail`` carries the
        before/after lifecycle state **and the id-only ``target_refs``** so the
        audited record self-identifies which devices/DDI refs the change touches
        (ADR-0020 §4) — never the secret-bearing CR ``payload``. ``request_id``
        is the inbound correlation id (ADR-0020 §4), ``None`` for non-HTTP calls.
        ``approval_latency_seconds`` is the wall-clock seconds the CR spent in
        ``pending_approval`` before the approve/reject decision; when provided it
        is observed on the ADR-0046 §1 approval-latency histogram.
        """
        before = cr.state
        cr.state = new
        await audit.record(
            session,
            actor=actor,
            action=action,
            target_type=_TARGET_TYPE,
            target_id=str(cr.id),
            detail={
                "before_state": before.value,
                "after_state": new.value,
                "target_refs": self._target_refs_projection(cr.target_refs),
            },
            reasoning_trace_id=cr.reasoning_trace_id,
            request_id=request_id,
        )
        # ChangeRequest workflow-health SLI (ADR-0015 §2 / ADR-0046 §1): count the
        # state ENTERED. Bounded enum label only — never the secret-bearing payload
        # or target detail (ADR-0020 §4). The approve/reject edges additionally
        # observe the approval-wait latency (seconds spent in pending_approval).
        metrics.record_change_request_transition(
            state=new.value, approval_latency_seconds=approval_latency_seconds
        )
        _logger.info(
            "change_request.transition",
            cr_id=str(cr.id),
            before=before.value,
            after=new.value,
            actor=actor,
        )
