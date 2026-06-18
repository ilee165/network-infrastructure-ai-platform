"""Approval gate for state-changing agent tools (ADR-0003, ADR-0011, ADR-0020).

Brief §5 / CLAUDE.md: any state-changing tool call requires human approval — no
exceptions, and a tool **never** applies the change itself.

The lifecycle of this seam:

- **M0–M4 (hard-reject).** :class:`DenyAllGate` denied every state-changing call
  with an audit entry, because there was no persistent ChangeRequest to create.
- **M5 (CR-creation).** :class:`ChangeRequestGate` rewires the gate from
  hard-reject to *ChangeRequest creation* (ADR-0020 §ref / M5-PLAN task #4). A
  state-changing tool invocation now CREATES a ``ChangeRequest`` in ``draft`` via
  the :class:`~app.services.change_requests.ChangeRequestService` and returns that
  CR (id/state) to the agent/user — it does **not** execute the change. Execution
  remains impossible outside an approved CR: the gate never returns
  ``approved=True``, so the tool body never runs from here; only the Automation
  Agent (Wave 4) drives an *approved* CR to execution. There is deliberately one
  spine (ADR-0020 alternative #4 rejected a parallel side-channel): the same gate
  that used to deny now creates the CR.

Invariants preserved across the rewire (M3, brief §7):

- **RBAC inheritance** — an agent can never exceed its user's role. The gate
  authors the CR with the invoking user's bound role (:func:`agent_run_context`);
  ``ChangeRequestService.create_draft`` itself rejects any author below
  ``engineer`` (ADR-0010 §3), so a viewer/operator-driven agent run cannot mint a
  CR at all.
- **Audit everything** — CR creation is audited by the service
  (``change_request.created``); the tool layer additionally records the gate
  decision on every invocation.
- **A9 redaction** — the proposed ``payload``/preview is scrubbed through the A9
  redaction layer (``llm/redaction.py``) *before* it is stored on the CR, so no
  config/DNS secret material is persisted in the CR payload or its preview.

:class:`DenyAllGate` is retained for tools that are never CR-eligible (a
state-changing action with no ChangeRequest representation): such a tool keeps the
secure hard-reject behaviour rather than creating a CR.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import NetOpsError
from app.core.security import Role
from app.llm.redaction import redact_payload
from app.models.change_requests import ChangeRequestKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.services.change_requests import ChangeRequestService


class ApprovalRequiredError(NetOpsError):
    """A state-changing tool was invoked without an approved ChangeRequest.

    Extends the :class:`~app.core.errors.NetOpsError` hierarchy so the FastAPI
    handlers render it as an RFC 7807 problem (403: the caller is
    authenticated but the action is forbidden until a human approves it).

    M5: this remains the hard-reject path for :class:`DenyAllGate` (tools that
    are never CR-eligible). The :class:`ChangeRequestGate` does **not** raise it
    — it creates a CR draft and the tool returns that CR to the caller.
    """

    status_code = 403
    title = "Approval Required"
    slug = "approval-required"


class ApprovalRequest(BaseModel):
    """What an agent is asking permission to do.

    The :class:`ChangeRequestGate` turns this into a persistent ChangeRequest:
    ``arguments`` become the proposed (redacted) ``payload``, ``kind`` selects the
    CR class, and ``target_refs`` records the device/DDI refs the change touches.
    M3 carried only the minimum needed for an auditable gate decision; M5 adds the
    fields the CR spine needs (ADR-0020 §2).
    """

    model_config = ConfigDict(frozen=True)

    #: Registered tool name (matches the audit event's ``tool_name``).
    tool_name: str
    #: Validated tool arguments as they would be executed — the proposed change.
    arguments: dict[str, Any] = Field(default_factory=dict)
    #: Which class of state-changing action this is (ADR-0020 §2). Defaults to
    #: ``config``; a DDI tool declares ``ddi_record`` (CONFIG_RESTORE vs
    #: CONFIG_DEPLOY remains a payload/target_refs distinction — Wave-1 decision).
    kind: ChangeRequestKind = ChangeRequestKind.CONFIG
    #: Id-only refs to the device(s)/DDI object(s) the change touches; recorded on
    #: the CR and (id-only) in the audit trail (never secret-bearing).
    target_refs: dict[str, Any] | None = None


class ApprovalDecision(BaseModel):
    """The gate's verdict for one :class:`ApprovalRequest`.

    Three shapes a decision can take:

    * **approved** (``approved=True``) — a human approved an existing CR; the tool
      may execute. The :class:`ChangeRequestGate` never returns this (it only
      *creates* drafts); it is produced by the execution path / tests.
    * **change-request created** (``approved=False`` + ``change_request_created``)
      — the M5 default for a state-changing tool: a CR draft now exists and the
      tool returns it to the caller instead of executing.
    * **hard reject** (``approved=False`` and not created) — :class:`DenyAllGate`
      for a tool that is never CR-eligible; the tool raises
      :class:`ApprovalRequiredError`.
    """

    model_config = ConfigDict(frozen=True)

    #: ``True`` only when a human approved the change (via an approved CR). The
    #: :class:`ChangeRequestGate` never sets this — creating a draft is not
    #: approval, so the tool body can never run off a freshly-created CR.
    approved: bool
    #: Human-readable explanation, surfaced in errors and audit events.
    reason: str | None = None
    #: The ChangeRequest this decision concerns (created draft, or the approved CR
    #: on the execution path); ``None`` only for a non-CR hard reject.
    change_request_id: str | None = None
    #: ``True`` when the gate just created a CR *draft* (M5 CR-creation path). The
    #: tool then returns the CR to the caller rather than raising or executing.
    change_request_created: bool = False
    #: Lifecycle state of the referenced CR (``draft`` for a freshly created one).
    change_request_state: str | None = None


@runtime_checkable
class ApprovalGate(Protocol):
    """Decides what happens when a state-changing tool call is attempted.

    Implementations must be side-effect-safe to call per invocation. The M5
    :class:`ChangeRequestGate` creates a ChangeRequest draft and returns a
    ``change_request_created`` decision; :class:`DenyAllGate` returns an
    immediate hard reject. A gate never itself executes the change.
    """

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Return the decision for *request*; never raise for a plain denial."""
        ...


class DenyAllGate:
    """Secure-by-default gate: every request is hard-rejected.

    Retained at M5 for tools that are **never CR-eligible** — a state-changing
    action with no ChangeRequest representation keeps this hard-reject rather than
    creating a CR. It is *not* the default for CR-eligible state-changing tools
    anymore: those are wired to a :class:`ChangeRequestGate`. There is still no
    "allow all" counterpart in production code (CLAUDE.md: human approval for
    changes).
    """

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Deny *request* with an explanation; no CR is created."""
        return ApprovalDecision(
            approved=False,
            reason=(
                f"tool '{request.tool_name}' is state-changing and not change-request "
                "eligible; it cannot be executed by an agent"
            ),
        )


class ChangeRequestGate:
    """M5 gate: a state-changing tool call CREATES a ChangeRequest draft.

    On :meth:`authorize` the gate authors a ``draft`` ChangeRequest via the
    injected :class:`~app.services.change_requests.ChangeRequestService` using the
    invoking user's bound identity/role, then returns a ``change_request_created``
    decision carrying the new CR's id and state. It **never** approves and never
    executes — execution is solely the Automation Agent's job on an *approved* CR
    (ADR-0020 §1/§2). A non-``approved`` CR therefore cannot drive execution: the
    gate hands back a ``draft``, and ``approved=False`` keeps the tool body from
    running.

    Identity & RBAC (brief §7): ``requester_id`` and ``actor_role`` are the
    invoking user's, bound by :func:`~app.agents.framework.tools.agent_run_context`.
    ``ChangeRequestService.create_draft`` enforces ``engineer``+ itself, so an
    agent run bound to a viewer/operator cannot create a CR — "an agent can never
    do what its user cannot" holds end-to-end.

    A9 redaction: the proposed tool ``arguments`` are scrubbed through
    :func:`~app.llm.redaction.redact_payload` *before* being stored as the CR
    ``payload`` and ``after_state`` preview, so no config/DNS secret material is
    persisted on the CR or rendered into its preview.
    """

    def __init__(
        self,
        service: ChangeRequestService,
        *,
        requester_id: uuid.UUID,
        actor_role: Role,
        generating_session_id: uuid.UUID | None = None,
        reasoning_trace_id: uuid.UUID | None = None,
    ) -> None:
        self._service = service
        self._requester_id = requester_id
        self._actor_role = actor_role
        self._generating_session_id = generating_session_id
        self._reasoning_trace_id = reasoning_trace_id

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        """Create a ``draft`` CR for *request* and return it (never approve)."""
        # A9: scrub secrets out of the proposed change BEFORE it is persisted on
        # the CR payload/preview. The stored payload is the redacted proposal —
        # the verbatim apply-time payload is materialised by the executor, never
        # by the gate (ADR-0020 §4, M5-PLAN risk #3).
        redacted_payload = redact_payload(request.arguments)
        cr = await self._service.create_draft(
            requester_id=self._requester_id,
            actor_role=self._actor_role,
            kind=request.kind,
            payload=redacted_payload,
            target_refs=request.target_refs,
            after_state={"proposed": redacted_payload},
            generating_session_id=self._generating_session_id,
            reasoning_trace_id=self._reasoning_trace_id,
        )
        return ApprovalDecision(
            approved=False,
            reason=(
                f"tool '{request.tool_name}' is state-changing; created change request "
                f"'{cr.id}' (draft) for human approval — the change was not executed"
            ),
            change_request_id=str(cr.id),
            change_request_created=True,
            change_request_state=cr.state.value,
        )
