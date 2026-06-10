"""Reasoning-trace models and recorders (ADR-0003 Decision 3, ADR-0011 §4).

Every agent run must yield an inspectable reasoning trace — steps, tool calls,
evidence — so "Explain all AI decisions" is a stored artifact, not a UI
nicety. M0 ships the models plus an in-memory recorder behind the
:class:`TraceRecorder` seam; M3 adds the database-backed recorder that
persists to the ``reasoning_traces`` table and links entries from
``audit_log`` (brief §6).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.errors import NotFoundError


def _utcnow() -> datetime:
    """Return the current UTC instant (single seam for freezing in tests)."""
    return datetime.now(tz=UTC)


class TraceStepKind(StrEnum):
    """What a single reasoning step represents.

    Values are wire-stable strings: they persist to ``reasoning_traces`` (M3)
    and render in the UI trace viewer.
    """

    #: The agent decided what to do next (supervisor routing, planning).
    PLAN = "plan"
    #: The agent invoked a tool (links to the tool's audit event).
    TOOL_CALL = "tool_call"
    #: The agent ingested evidence (tool output, retrieved context).
    OBSERVATION = "observation"
    #: The agent produced a result or final answer.
    CONCLUSION = "conclusion"


class EvidenceRef(BaseModel):
    """A pointer to evidence supporting a reasoning step.

    M0 references are opaque strings; M3 resolves them against real rows
    (``raw_artifacts``, ``audit_log``, ``documents``) so the UI can deep-link.
    """

    model_config = ConfigDict(frozen=True)

    #: Evidence category, e.g. ``"raw_artifact"``, ``"audit_event"``,
    #: ``"document"``, ``"message"``.
    kind: str = Field(min_length=1)
    #: Opaque identifier or URI of the evidence.
    reference: str = Field(min_length=1)
    #: Optional human-readable label for the trace viewer.
    description: str | None = None


class TraceStep(BaseModel):
    """One ordered step inside a :class:`ReasoningTrace`."""

    model_config = ConfigDict(frozen=True)

    #: What this step represents.
    kind: TraceStepKind
    #: One-line human-readable summary of the step.
    summary: str = Field(min_length=1)
    #: Optional longer detail (model output excerpt, tool result digest).
    detail: str | None = None
    #: Tool name — required when (and only meaningful when) ``kind`` is
    #: :attr:`TraceStepKind.TOOL_CALL`.
    tool_name: str | None = None
    #: Evidence cited by this step.
    evidence: list[EvidenceRef] = Field(default_factory=list)
    #: UTC instant the step occurred.
    occurred_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _tool_call_names_its_tool(self) -> TraceStep:
        """A tool_call step without a tool name is unexplainable — reject it."""
        if self.kind is TraceStepKind.TOOL_CALL and not self.tool_name:
            raise ValueError("tool_call steps must set tool_name")
        return self


class ReasoningTrace(BaseModel):
    """The full reasoning record of one agent run.

    Mutable by design: recorders append steps while the run progresses and
    stamp ``completed_at`` when it ends. M3 persists each trace to the
    ``reasoning_traces`` table and links it from ``audit_log`` entries.
    """

    #: Opaque trace identifier (hex UUID4).
    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    #: Agent that produced the trace (string id, e.g. ``"master_architect"``).
    agent_name: str = Field(min_length=1)
    #: UTC instant the run started.
    started_at: datetime = Field(default_factory=_utcnow)
    #: UTC instant the run ended; ``None`` while in progress.
    completed_at: datetime | None = None
    #: Ordered reasoning steps.
    steps: list[TraceStep] = Field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Whether the trace has been completed by its recorder."""
        return self.completed_at is not None


@runtime_checkable
class TraceRecorder(Protocol):
    """Records reasoning traces for agent runs (pluggable seam).

    M0: :class:`InMemoryTraceRecorder`. M3: a database-backed recorder that
    persists to ``reasoning_traces`` and links from ``audit_log``
    (ADR-0011 §4) implements this same protocol.
    """

    async def start(self, agent_name: str) -> ReasoningTrace:
        """Open a new trace for *agent_name* and return it."""
        ...

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        """Append *step* to the trace and return the updated trace."""
        ...

    async def complete(self, trace_id: str) -> ReasoningTrace:
        """Mark the trace finished and return it."""
        ...


class InMemoryTraceRecorder:
    """Process-local trace recorder — the M0 implementation.

    Traces live only for the lifetime of this instance; durable persistence
    to the ``reasoning_traces`` table is M3. Suitable for unit tests and for
    attaching traces to in-process supervisor runs.
    """

    def __init__(self) -> None:
        self._traces: dict[str, ReasoningTrace] = {}

    async def start(self, agent_name: str) -> ReasoningTrace:
        """Open and retain a new trace for *agent_name*."""
        trace = ReasoningTrace(agent_name=agent_name)
        self._traces[trace.trace_id] = trace
        return trace

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        """Append *step* to the identified trace."""
        trace = self.get(trace_id)
        trace.steps.append(step)
        return trace

    async def complete(self, trace_id: str) -> ReasoningTrace:
        """Stamp ``completed_at`` on the identified trace."""
        trace = self.get(trace_id)
        if trace.completed_at is None:
            trace.completed_at = _utcnow()
        return trace

    def get(self, trace_id: str) -> ReasoningTrace:
        """Return the trace for *trace_id* or raise :class:`NotFoundError`."""
        try:
            return self._traces[trace_id]
        except KeyError:
            raise NotFoundError(f"reasoning trace '{trace_id}' does not exist") from None

    def list_traces(self) -> list[ReasoningTrace]:
        """Return all retained traces in insertion order."""
        return list(self._traces.values())
