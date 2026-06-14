"""Shared agent framework layers (ADR-0003 Decision 3).

This package is the *only* bridge from agents to engines/services
(REPO-STRUCTURE section 3.2, row 10). It provides:

- :mod:`~app.agents.framework.tools` — classified, audited tool wrappers,
- :mod:`~app.agents.framework.approval` — the human-approval gate for
  state-changing tools,
- :mod:`~app.agents.framework.traces` — reasoning-trace models and recorders,
- :mod:`~app.agents.framework.base` — the specialist-agent base class,
- :mod:`~app.agents.framework.registry` — the specialist registry,
- :mod:`~app.agents.framework.supervisor` — the Master Architect routing graph.
"""

from app.agents.framework.approval import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    ApprovalRequiredError,
    DenyAllGate,
)
from app.agents.framework.base import AgentDefinitionError, BaseSpecialistAgent
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import (
    CONSULTANT_NAME,
    SUPERVISOR_NAME,
    RoutingDecision,
    SupervisorRoutingError,
    build_supervisor_graph,
    run_supervisor,
)
from app.agents.framework.tools import (
    AuditSink,
    BoundedExecution,
    LoggingAuditSink,
    NetOpsTool,
    ToolAuditEvent,
    ToolClassification,
    ToolDefinitionError,
    ToolExecutionError,
    netops_tool,
)
from app.agents.framework.traces import (
    EvidenceRef,
    InMemoryTraceRecorder,
    ReasoningTrace,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
)

__all__ = [
    "CONSULTANT_NAME",
    "SUPERVISOR_NAME",
    "AgentDefinitionError",
    "AgentRegistry",
    "ApprovalDecision",
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalRequiredError",
    "AuditSink",
    "BaseSpecialistAgent",
    "BoundedExecution",
    "DenyAllGate",
    "EvidenceRef",
    "InMemoryTraceRecorder",
    "LoggingAuditSink",
    "NetOpsTool",
    "ReasoningTrace",
    "RoutingDecision",
    "SupervisorRoutingError",
    "ToolAuditEvent",
    "ToolClassification",
    "ToolDefinitionError",
    "ToolExecutionError",
    "TraceRecorder",
    "TraceStep",
    "TraceStepKind",
    "build_supervisor_graph",
    "netops_tool",
    "run_supervisor",
]
