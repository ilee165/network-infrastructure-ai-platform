"""Classified, audited tool wrappers — the only agents -> engines/services bridge.

ADR-0003 Decision 3 fixes three structural guarantees that this module makes
impossible to skip:

- **Classification** (:class:`ToolClassification`): every tool is declared
  ``read_only``, ``state_changing``, or ``diagnostic`` at definition time.
- **Audit** (:class:`AuditSink`): every invocation — success, denial, or
  failure — emits a :class:`ToolAuditEvent`. M0 ships the structlog sink
  (:class:`LoggingAuditSink`); the append-only ``audit_log`` sink
  (``core/audit.py``) replaces the default wiring in M3.
- **Approval** (ADR-0011, ADR-0020): a ``state_changing`` tool cannot execute
  without an approving :class:`~app.agents.framework.approval.ApprovalGate`
  decision. From M5 (TASK #4) the default gate is the
  :class:`~app.agents.framework.approval.ChangeRequestGate`: a state-changing
  call CREATES a ChangeRequest *draft* (the tool returns a
  :class:`ChangeRequestCreated`, never the change's result) and the change is
  applied only later by the Automation Agent against an *approved* CR. When no
  gate is resolvable (none bound, no explicit gate) the call falls back to the
  secure hard-reject :class:`~app.agents.framework.approval.DenyAllGate`, which
  is also retained for tools that are never CR-eligible. ``diagnostic`` is the
  narrow ADR-0014 carve-out: bounded, auto-reverting device actions (currently
  only packet captures) that execute without a ChangeRequest but always carry
  mandatory caps and an audit event.

Tools are plain LangChain :class:`~langchain_core.tools.StructuredTool`
subclasses, so LangGraph's prebuilt ``ToolNode`` executes them unchanged.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Protocol, cast, runtime_checkable

from langchain_core.callbacks import AsyncCallbackManagerForToolRun
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agents.framework.approval import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    ApprovalRequiredError,
    DenyAllGate,
)
from app.core.errors import NetOpsError
from app.core.logging import get_logger
from app.core.security import Role
from app.models.change_requests import ChangeRequestKind

_logger = get_logger(__name__)

#: Outcome of one tool invocation, as recorded in the audit event.
ToolOutcome = Literal["success", "denied", "error"]


@dataclass(frozen=True)
class AgentRunIdentity:
    """The authenticated caller behind the current agent run (brief §7).

    Bound by :func:`agent_run_context` so the tool layer can both enforce RBAC
    (``role``) and — when a state-changing tool creates a ChangeRequest (ADR-0020,
    M5) — author that CR as the real user (``user_id``), attributing it to the
    originating agent run (``session_id`` → ``generating_session_id``,
    ``reasoning_trace_id``). ``user_id`` is ``None`` for runs not tied to a
    specific user (e.g. some tests); the M5 :class:`ChangeRequestGate` requires a
    real ``user_id`` and is only wired when one is bound.
    """

    role: Role
    user_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    reasoning_trace_id: uuid.UUID | None = None


#: The invoking caller for the current agent run. ``None`` means no run context
#: is bound; RBAC then falls back to the least-privileged
#: :attr:`~app.core.security.Role.VIEWER`, so an unbound run can never exceed
#: viewer rights ("an agent can never do what its user cannot" still holds —
#: the supervisor binds the authenticated user's real identity before driving the
#: graph via :func:`agent_run_context`).
_invoking_identity: ContextVar[AgentRunIdentity | None] = ContextVar(
    "netops_invoking_identity", default=None
)


@contextmanager
def agent_run_context(
    *,
    role: Role,
    user_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    reasoning_trace_id: uuid.UUID | None = None,
) -> Iterator[None]:
    """Bind the invoking user's identity for the duration of an agent run.

    Brief §7 — "an agent can never do what its user cannot": the supervisor
    enters this context with the authenticated user's *role* before driving the
    graph, so every :class:`NetOpsTool` executed inside the run (including
    LangGraph's prebuilt ``ToolNode``, which we cannot pass kwargs to) sees the
    same caller role via the :data:`_invoking_identity` contextvar. M5 also binds
    ``user_id`` / ``session_id`` / ``reasoning_trace_id`` so a state-changing tool
    can author its ChangeRequest as the real user, attributed to this run
    (ADR-0020 §2). The token is restored on exit, so nested/concurrent runs do not
    leak identity into one another.
    """
    token = _invoking_identity.set(
        AgentRunIdentity(
            role=role,
            user_id=user_id,
            session_id=session_id,
            reasoning_trace_id=reasoning_trace_id,
        )
    )
    try:
        yield
    finally:
        _invoking_identity.reset(token)


def current_invoking_identity() -> AgentRunIdentity | None:
    """Return the identity bound by the active :func:`agent_run_context`, if any."""
    return _invoking_identity.get()


#: Builds the per-run :class:`~app.agents.framework.approval.ChangeRequestGate`
#: for a state-changing tool call, from the bound :class:`AgentRunIdentity`.
#: Returns ``None`` when CR creation is not possible for that identity (e.g. no
#: authenticated user is bound), in which case the call falls back to the secure
#: hard-reject gate. The concrete gate it returns is built by the binder at the
#: supervisor/API layer, which closes over the request-scoped CR service.
GateFactory = Callable[[AgentRunIdentity], ApprovalGate | None]

_gate_factory: ContextVar[GateFactory | None] = ContextVar(
    "netops_change_request_gate_factory", default=None
)


@contextmanager
def change_request_gate_context(factory: GateFactory) -> Iterator[None]:
    """Bind the :class:`~app.agents.framework.approval.ChangeRequestGate` factory.

    The M5 gate needs the CR service and the invoking user, neither of which can
    be baked into a tool at import time. The supervisor/API entrypoint binds
    *factory* (which closes over the request-scoped CR service) for the duration
    of a run; each state-changing :class:`NetOpsTool` call then builds its gate
    from the bound :class:`AgentRunIdentity` via :meth:`NetOpsTool._resolve_gate`.
    Without a bound factory (or an explicit per-tool gate), a state-changing call
    falls back to the secure hard-reject
    :class:`~app.agents.framework.approval.DenyAllGate`.
    """
    token = _gate_factory.set(factory)
    try:
        yield
    finally:
        _gate_factory.reset(token)


def current_invoking_role() -> Role | None:
    """Return the role bound by the active :func:`agent_run_context`, if any."""
    identity = _invoking_identity.get()
    return identity.role if identity is not None else None


class ToolDefinitionError(NetOpsError):
    """A tool was declared in a way that violates the framework contract."""

    status_code = 500
    title = "Tool Definition Error"
    slug = "tool-definition"


class RbacForbiddenError(NetOpsError):
    """A tool was invoked by a caller whose role is below the tool's minimum.

    Mirrors :class:`~app.agents.framework.approval.ApprovalRequiredError`: it
    extends :class:`~app.core.errors.NetOpsError` so the FastAPI handlers render
    it as a 403 RFC 7807 problem (the caller is authenticated but not authorized
    for this tool — brief §7, "an agent can never do what its user cannot").
    """

    status_code = 403
    title = "Forbidden"
    slug = "rbac-forbidden"


class ToolExecutionError(NetOpsError):
    """A tool breached its execution bounds (e.g. a diagnostic timeout)."""

    status_code = 502
    title = "Tool Execution Failure"
    slug = "tool-execution"


class ToolClassification(StrEnum):
    """The three-tier tool classification (ADR-0003 / ADR-0014).

    Values are wire-stable strings: they appear in audit events, reasoning
    traces, and (M5) ChangeRequest payloads.
    """

    #: Executes directly; no approval needed (e.g. topology queries).
    READ_ONLY = "read_only"
    #: Requires an approved ChangeRequest — human approval, no exceptions.
    STATE_CHANGING = "state_changing"
    #: Bounded, auto-reverting device action (ADR-0014): mandatory caps,
    #: always audited, no ChangeRequest. Currently only packet captures.
    DIAGNOSTIC = "diagnostic"


class ChangeRequestCreated(BaseModel):
    """What a state-changing tool returns to the agent/user under M5 (ADR-0020).

    The M5 :class:`~app.agents.framework.approval.ChangeRequestGate` rewires a
    state-changing tool call from "execute" / "hard reject" to "create a
    ChangeRequest draft and return it". The tool therefore yields this — the new
    CR's id and lifecycle ``state`` (``draft``) plus the human-readable reason —
    instead of the change's result: nothing was applied. The Automation Agent
    (Wave 4) is the only thing that executes the change, and only after a human
    approves the CR. The agent surfaces this to the user as "I drafted change
    request X for approval".
    """

    model_config = ConfigDict(frozen=True)

    #: The created ChangeRequest's id (string form of its UUID).
    change_request_id: str
    #: The CR's lifecycle state at creation — always ``draft``.
    change_request_state: str
    #: Human-readable explanation surfaced to the agent/user.
    reason: str | None = None


class BoundedExecution(BaseModel):
    """Mandatory execution bounds for ``diagnostic`` tools (ADR-0014).

    The framework enforces ``timeout_seconds`` in-process; the packet/byte
    caps are metadata handed to the capture engine (D14, M5), which enforces
    them on-device. At least one size cap must be set — a duration cap alone
    does not satisfy ADR-0014's "mandatory duration/size caps".
    """

    model_config = ConfigDict(frozen=True)

    #: Hard wall-clock limit for the tool call, enforced by the framework.
    timeout_seconds: float = Field(gt=0, le=3600)
    #: Maximum packets the action may capture (engine-enforced, M5).
    max_packets: int | None = Field(default=None, gt=0)
    #: Maximum bytes the action may capture (engine-enforced, M5).
    max_bytes: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _require_size_cap(self) -> BoundedExecution:
        """ADR-0014: a diagnostic action must carry at least one size cap."""
        if self.max_packets is None and self.max_bytes is None:
            raise ValueError("bounded execution requires max_packets and/or max_bytes")
        return self


class ToolAuditEvent(BaseModel):
    """One audited tool invocation (success, denial, or failure).

    M0 events flow to a pluggable :class:`AuditSink`; M3 links them to
    ``reasoning_traces`` and M5 lands them in the append-only ``audit_log``
    (ADR-0011). Arguments are recorded verbatim at M0 — the mandatory
    redaction pipeline (``llm/redaction.py``, REPO-STRUCTURE P20) is applied
    before persistence from M3 on.
    """

    model_config = ConfigDict(frozen=True)

    #: Registered tool name.
    tool_name: str
    #: Declared classification of the tool.
    classification: ToolClassification
    #: Validated arguments the tool was (or would have been) executed with.
    arguments: dict[str, Any] = Field(default_factory=dict)
    #: How the invocation ended.
    outcome: ToolOutcome
    #: Human-readable context (denial reason, error message).
    detail: str | None = None
    #: Gate decision for ``state_changing`` tools; ``None`` otherwise.
    approval: ApprovalDecision | None = None
    #: Declared bounds for ``diagnostic`` tools; ``None`` otherwise.
    bounded_execution: BoundedExecution | None = None
    #: UTC instant the event was recorded.
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


@runtime_checkable
class AuditSink(Protocol):
    """Destination for tool audit events (pluggable seam).

    M0: :class:`LoggingAuditSink`. M5: the append-only ``audit_log`` writer in
    ``core/audit.py``. A sink failure fails the tool call — "audit everything"
    means the platform never acts unaudited.
    """

    async def record(self, event: ToolAuditEvent) -> None:
        """Durably record *event*; raise on failure (never swallow)."""
        ...


class LoggingAuditSink:
    """M0 default sink: emits each audit event as one structlog line.

    The append-only database sink (ADR-0011) replaces this as the default
    wiring in M5; structlog output remains useful for log-pipeline ingestion.
    """

    async def record(self, event: ToolAuditEvent) -> None:
        """Log *event* as a structured ``tool_audit`` record."""
        _logger.info("tool_audit", **event.model_dump(mode="json"))


class NetOpsTool(StructuredTool):
    """A classified, audited, approval-gated LangChain tool.

    Built via :func:`netops_tool`; do not instantiate directly. The execution
    pipeline wraps the user coroutine with, in order: approval gating
    (``state_changing``), bounded execution (``diagnostic``), and audit
    emission (always).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    #: Declared classification; immutable for the tool's lifetime.
    classification: ToolClassification
    #: Where audit events go. Injectable per-instance (tests, M5 wiring).
    audit_sink: AuditSink = Field(default_factory=LoggingAuditSink)
    #: Gate consulted for ``state_changing`` calls; ``None`` for other tiers.
    approval_gate: ApprovalGate | None = None
    #: Mandatory bounds for ``diagnostic`` tools; ``None`` for other tiers.
    bounded_execution: BoundedExecution | None = None
    #: Minimum invoking-user role required to run this tool (D10/brief §7).
    #: Defaults to the least-privileged :attr:`~app.core.security.Role.VIEWER`.
    min_role: Role = Role.VIEWER
    #: Which class of ChangeRequest a ``state_changing`` call creates (ADR-0020
    #: §2). ``config`` by default; a DDI tool declares ``ddi_record``. Ignored for
    #: non-state-changing tiers.
    change_request_kind: ChangeRequestKind = ChangeRequestKind.CONFIG
    #: Optional projector from the tool arguments to the id-only device/DDI
    #: ``target_refs`` recorded on the CR and (id-only) in the audit trail. When
    #: ``None`` the CR carries no target refs.
    target_refs: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None

    async def _emit(
        self,
        *,
        outcome: ToolOutcome,
        arguments: dict[str, Any],
        detail: str | None = None,
        approval: ApprovalDecision | None = None,
    ) -> None:
        """Build and record the audit event for one invocation."""
        await self.audit_sink.record(
            ToolAuditEvent(
                tool_name=self.name,
                classification=self.classification,
                arguments=arguments,
                outcome=outcome,
                detail=detail,
                approval=approval,
                bounded_execution=self.bounded_execution,
            )
        )

    async def _check_rbac(self, arguments: dict[str, Any]) -> None:
        """Enforce "an agent can never do what its user cannot" (brief §7).

        Reads the invoking user's role from the active :func:`agent_run_context`,
        falling back to the least-privileged ``viewer`` when no run context is
        bound. If the effective caller role ranks below :attr:`min_role`, the
        call is denied *before execution*: a ``denied`` audit event is recorded
        (carrying required vs actual role) and a 403 :class:`RbacForbiddenError`
        is raised.
        """
        identity = _invoking_identity.get()
        caller = identity.role if identity is not None else Role.VIEWER
        if not caller.can_act_as(self.min_role):
            detail = (
                f"tool '{self.name}' requires role '{self.min_role.value}' or higher; "
                f"invoking user role is '{caller.value}'"
            )
            await self._emit(outcome="denied", arguments=arguments, detail=detail)
            raise RbacForbiddenError(detail)

    def _resolve_gate(self) -> ApprovalGate:
        """Pick the gate for this state-changing call (ADR-0020 precedence).

        1. An explicit per-tool ``approval_gate`` always wins —
           :class:`~app.agents.framework.approval.DenyAllGate` for a tool that is
           never CR-eligible, or a test gate.
        2. Otherwise the per-run :func:`change_request_gate_context` factory builds
           a :class:`~app.agents.framework.approval.ChangeRequestGate` from the
           bound :class:`AgentRunIdentity` (the M5 default — create a CR draft).
        3. If neither is available (no factory bound, or the factory declines for
           this identity), fall back to the secure hard-reject
           :class:`~app.agents.framework.approval.DenyAllGate`: a state-changing
           tool never executes unauthorised.
        """
        if self.approval_gate is not None:
            return self.approval_gate
        factory = _gate_factory.get()
        identity = _invoking_identity.get()
        if factory is not None and identity is not None:
            gate = factory(identity)
            if gate is not None:
                return gate
        return DenyAllGate()

    async def _gate(self, arguments: dict[str, Any]) -> ApprovalDecision:
        """Run a ``state_changing`` call through the approval gate (ADR-0020).

        Three outcomes, all audited here:

        * **approved** (``approved=True``) — a human approved the CR; return the
          decision and let :meth:`_arun` execute the tool body. (The M5
          :class:`ChangeRequestGate` never produces this; execution is driven by
          the Automation Agent off an already-approved CR.)
        * **CR created** (``change_request_created=True``) — the M5 default: the
          gate created a ``draft`` ChangeRequest. The call is recorded ``denied``
          (it did **not** execute) but carries the CR id; :meth:`_arun` returns
          the CR to the caller instead of raising. A non-approved CR can never
          drive execution from here.
        * **hard reject** — :class:`DenyAllGate` (a tool that is never CR-eligible):
          record ``denied`` and raise :class:`ApprovalRequiredError`.
        """
        gate = self._resolve_gate()
        decision = await gate.authorize(self._approval_request(arguments))
        if decision.approved:
            return decision
        # Not approved: the tool body will NOT run. Audit the gate outcome with
        # the (redaction-applied) arguments; the gate has already scrubbed the CR
        # payload it persisted (A9), this records the same denied invocation.
        await self._emit(
            outcome="denied", arguments=arguments, detail=decision.reason, approval=decision
        )
        if decision.change_request_created:
            # CR-creation path: hand the draft back to the agent/user; no raise,
            # no execution (ADR-0020 §1/§2 — only an approved CR is executable,
            # and only by the Automation Agent in Wave 4).
            return decision
        raise ApprovalRequiredError(
            decision.reason or f"tool '{self.name}' is state-changing and was not approved"
        )

    def _approval_request(self, arguments: dict[str, Any]) -> ApprovalRequest:
        """Build the gate request for this tool's proposed *arguments*.

        Carries the tool's :attr:`change_request_kind` and resolved
        :attr:`target_refs` (if declared) so the :class:`ChangeRequestGate` can
        classify the CR and record which devices/DDI refs it touches.
        """
        target_refs = self.target_refs(arguments) if self.target_refs is not None else None
        return ApprovalRequest(
            tool_name=self.name,
            arguments=arguments,
            kind=self.change_request_kind,
            target_refs=target_refs,
        )

    async def _arun(
        self,
        *args: Any,
        config: RunnableConfig,
        run_manager: AsyncCallbackManagerForToolRun | None = None,
        **kwargs: Any,
    ) -> Any:
        """Execute the tool through the rbac/gate/bounds/audit pipeline."""
        arguments = dict(kwargs)
        # RBAC first: a caller who may not run this tool never reaches the
        # approval gate or the tool body (brief §7).
        await self._check_rbac(arguments)
        approval: ApprovalDecision | None = None
        if self.classification is ToolClassification.STATE_CHANGING:
            approval = await self._gate(arguments)
            if not approval.approved:
                # CR-creation path (the M5 default): the gate created a draft CR
                # and did not approve, so the tool body does not run. Return the
                # CR to the caller; the ``denied`` audit event was already emitted
                # by :meth:`_gate`. (A non-CR hard reject already raised there.)
                return ChangeRequestCreated(
                    change_request_id=approval.change_request_id or "",
                    change_request_state=approval.change_request_state or "",
                    reason=approval.reason,
                )
        try:
            if self.classification is ToolClassification.DIAGNOSTIC:
                if self.bounded_execution is None:  # pragma: no cover - decorator guarantees
                    raise ToolDefinitionError(
                        f"diagnostic tool '{self.name}' is missing bounded execution metadata"
                    )
                async with asyncio.timeout(self.bounded_execution.timeout_seconds):
                    result = await super()._arun(
                        *args, config=config, run_manager=run_manager, **kwargs
                    )
            else:
                result = await super()._arun(
                    *args, config=config, run_manager=run_manager, **kwargs
                )
        except TimeoutError as exc:
            detail = (
                f"diagnostic tool '{self.name}' exceeded its "
                f"{self.bounded_execution.timeout_seconds}s timeout"
                if self.bounded_execution is not None
                else f"tool '{self.name}' timed out"
            )
            await self._emit(outcome="error", arguments=arguments, detail=detail, approval=approval)
            raise ToolExecutionError(detail) from exc
        except Exception as exc:
            await self._emit(
                outcome="error", arguments=arguments, detail=str(exc), approval=approval
            )
            raise
        await self._emit(outcome="success", arguments=arguments, approval=approval)
        return result

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous execution is not supported — the platform is async-first."""
        raise NotImplementedError(
            f"NetOpsTool '{self.name}' is async-only; use 'ainvoke' (D2: async-first backend)"
        )


def netops_tool(
    *,
    classification: ToolClassification,
    name: str | None = None,
    description: str | None = None,
    audit_sink: AuditSink | None = None,
    approval_gate: ApprovalGate | None = None,
    bounded_execution: BoundedExecution | None = None,
    min_role: Role | str = Role.VIEWER,
    change_request_kind: ChangeRequestKind = ChangeRequestKind.CONFIG,
    target_refs: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], NetOpsTool]:
    """Declare an async callable as a classified NetOps tool.

    Usage::

        @netops_tool(classification=ToolClassification.READ_ONLY)
        async def get_device_count(site: str) -> str:
            \"\"\"Count managed devices at a site.\"\"\"
            ...

    Contract enforced at definition time (:class:`ToolDefinitionError`):

    - the wrapped callable must be a coroutine function (async-first, D2);
    - a description must exist (decorator argument or docstring) — it is what
      the LLM routes on;
    - ``diagnostic`` tools must declare :class:`BoundedExecution` (ADR-0014);
    - only ``diagnostic`` tools may declare bounds;
    - only ``state_changing`` tools may carry an approval gate (a gate on a
      read-only tool indicates misclassification);
    - ``min_role`` (a :class:`~app.core.security.Role` or its wire name) must
      name a known role — an unknown name is rejected at definition time.

    ``min_role`` is the minimum invoking-user role allowed to run the tool
    (brief §7), defaulting to the least-privileged ``viewer`` for read-only
    convenience while remaining explicit-capable. RBAC is enforced in
    :meth:`NetOpsTool._arun` against the role bound by :func:`agent_run_context`.

    ``state_changing`` tools have **no gate baked in** (M5): the gate is the
    request/identity-scoped :class:`~app.agents.framework.approval.ChangeRequestGate`,
    resolved per invocation from the CR service bound by
    :func:`change_request_gate_context` plus the user bound by
    :func:`agent_run_context`. A tool may still be given an explicit
    ``approval_gate`` — e.g. :class:`~app.agents.framework.approval.DenyAllGate`
    for an action that is never CR-eligible, or a test gate. When no gate is bound
    and none is explicit, the call falls back to the secure hard-reject
    ``DenyAllGate`` (a state-changing tool never executes unauthorised).

    ``change_request_kind`` selects the CR class the gate creates (ADR-0020 §2;
    ``config`` by default, ``ddi_record`` for DDI tools). ``target_refs`` is an
    optional projector from the call arguments to the id-only device/DDI refs
    recorded on the CR.
    """
    if isinstance(min_role, Role):
        resolved_min_role = min_role
    else:
        candidate = Role.from_name(min_role)
        if candidate is None:
            raise ToolDefinitionError(
                f"unknown min_role {min_role!r}; expected one of {[r.value for r in Role]}"
            )
        resolved_min_role = candidate

    def decorate(func: Callable[..., Awaitable[Any]]) -> NetOpsTool:
        if not inspect.iscoroutinefunction(func):
            raise ToolDefinitionError(
                f"tool '{getattr(func, '__name__', func)}' must be an async def coroutine "
                "function (D2: async-first backend)"
            )
        tool_name = name or func.__name__
        tool_description = (description or inspect.getdoc(func) or "").strip()
        if not tool_description:
            raise ToolDefinitionError(
                f"tool '{tool_name}' needs a description (decorator argument or docstring); "
                "the LLM selects tools by description"
            )
        if classification is ToolClassification.DIAGNOSTIC and bounded_execution is None:
            raise ToolDefinitionError(
                f"diagnostic tool '{tool_name}' must declare BoundedExecution "
                "(ADR-0014: mandatory duration/size caps)"
            )
        if classification is not ToolClassification.DIAGNOSTIC and bounded_execution is not None:
            raise ToolDefinitionError(
                f"tool '{tool_name}' is {classification}; bounded execution applies only to "
                "diagnostic tools (ADR-0014)"
            )
        if classification is not ToolClassification.STATE_CHANGING and approval_gate is not None:
            raise ToolDefinitionError(
                f"tool '{tool_name}' is {classification}; approval gates apply only to "
                "state-changing tools — reclassify it if it mutates state"
            )
        # No gate is baked in for state-changing tools anymore: the M5
        # ChangeRequestGate is request/identity-scoped and resolved per
        # invocation (see :meth:`NetOpsTool._resolve_gate`). An explicit gate
        # (DenyAllGate for never-CR-eligible tools, or a test gate) still wins.
        return cast(
            NetOpsTool,
            NetOpsTool.from_function(
                coroutine=func,
                name=tool_name,
                description=tool_description,
                infer_schema=True,
                classification=classification,
                audit_sink=audit_sink if audit_sink is not None else LoggingAuditSink(),
                approval_gate=approval_gate,
                bounded_execution=bounded_execution,
                min_role=resolved_min_role,
                change_request_kind=change_request_kind,
                target_refs=target_refs,
            ),
        )

    return decorate
