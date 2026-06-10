"""Classified, audited tool wrappers — the only agents -> engines/services bridge.

ADR-0003 Decision 3 fixes three structural guarantees that this module makes
impossible to skip:

- **Classification** (:class:`ToolClassification`): every tool is declared
  ``read_only``, ``state_changing``, or ``diagnostic`` at definition time.
- **Audit** (:class:`AuditSink`): every invocation — success, denial, or
  failure — emits a :class:`ToolAuditEvent`. M0 ships the structlog sink
  (:class:`LoggingAuditSink`); the append-only ``audit_log`` sink
  (``core/audit.py``) replaces the default wiring in M3.
- **Approval** (ADR-0011): a ``state_changing`` tool cannot execute without an
  approving :class:`~app.agents.framework.approval.ApprovalGate` decision; the
  secure-by-default gate denies everything until the M5 ChangeRequest workflow
  lands. ``diagnostic`` is the narrow ADR-0014 carve-out: bounded,
  auto-reverting device actions (currently only packet captures) that execute
  without a ChangeRequest but always carry mandatory caps and an audit event.

Tools are plain LangChain :class:`~langchain_core.tools.StructuredTool`
subclasses, so LangGraph's prebuilt ``ToolNode`` executes them unchanged.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
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

_logger = get_logger(__name__)

#: Outcome of one tool invocation, as recorded in the audit event.
ToolOutcome = Literal["success", "denied", "error"]


class ToolDefinitionError(NetOpsError):
    """A tool was declared in a way that violates the framework contract."""

    status_code = 500
    title = "Tool Definition Error"
    slug = "tool-definition"


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

    async def _authorize(self, arguments: dict[str, Any]) -> ApprovalDecision:
        """Gate a ``state_changing`` call; raise unless a human approved it."""
        gate: ApprovalGate = self.approval_gate if self.approval_gate is not None else DenyAllGate()
        decision = await gate.authorize(ApprovalRequest(tool_name=self.name, arguments=arguments))
        if not decision.approved:
            await self._emit(
                outcome="denied", arguments=arguments, detail=decision.reason, approval=decision
            )
            raise ApprovalRequiredError(
                decision.reason or f"tool '{self.name}' is state-changing and was not approved"
            )
        return decision

    async def _arun(
        self,
        *args: Any,
        config: RunnableConfig,
        run_manager: AsyncCallbackManagerForToolRun | None = None,
        **kwargs: Any,
    ) -> Any:
        """Execute the tool through the gate/bounds/audit pipeline."""
        arguments = dict(kwargs)
        approval: ApprovalDecision | None = None
        if self.classification is ToolClassification.STATE_CHANGING:
            approval = await self._authorize(arguments)
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
      read-only tool indicates misclassification).

    ``state_changing`` tools default to the secure
    :class:`~app.agents.framework.approval.DenyAllGate`; the ChangeRequest
    gate replaces it in M5.
    """

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
        gate = approval_gate
        if classification is ToolClassification.STATE_CHANGING and gate is None:
            gate = DenyAllGate()
        return cast(
            NetOpsTool,
            NetOpsTool.from_function(
                coroutine=func,
                name=tool_name,
                description=tool_description,
                infer_schema=True,
                classification=classification,
                audit_sink=audit_sink if audit_sink is not None else LoggingAuditSink(),
                approval_gate=gate,
                bounded_execution=bounded_execution,
            ),
        )

    return decorate
