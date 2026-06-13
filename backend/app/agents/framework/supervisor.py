"""Master Architect supervisor graph (ADR-0003: LangGraph supervisor pattern).

The supervisor receives user intent, asks the LLM to pick exactly one
registered specialist, runs that specialist's compiled subgraph, and returns
the conversation with a :class:`~app.agents.framework.traces.ReasoningTrace`
attached — routing decisions are always explainable (CLAUDE.md: explain all
AI decisions).

M0 scope: single-specialist routing with trace attachment. M3 adds the full
Master Architect plan -> route -> synthesize loop, Consultant escalation for
ambiguous intent, structured-output routing
(``llm.with_structured_output``), and persisted traces; routing here parses
the specialist name from the reply text so the graph runs against any chat
model, including the scripted fakes used in tests.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, SystemMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import agent_run_context
from app.agents.framework.traces import (
    InMemoryTraceRecorder,
    ReasoningTrace,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
)
from app.core.errors import NetOpsError
from app.core.security import Role
from app.llm.prompts import SUPERVISOR_ROUTING_PROMPT_ID, get_prompt

#: String id of the supervisor itself (CLAUDE.md core agent #1).
SUPERVISOR_NAME = "master_architect"


class SupervisorRoutingError(NetOpsError):
    """The supervisor could not route the request to a specialist."""

    status_code = 500
    title = "Supervisor Routing Failure"
    slug = "supervisor-routing"


class SupervisorState(MessagesState):
    """Supervisor graph state: the conversation plus routing/trace channels."""

    #: Name of the specialist chosen by the routing step.
    specialist: str
    #: Reasoning trace for this run; attached by the supervisor nodes.
    trace: ReasoningTrace | None


def _message_text(content: str | list[str | dict[str, Any]]) -> str:
    """Flatten a chat-message ``content`` payload to plain text."""
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return " ".join(parts)


def _parse_specialist_choice(reply: str, names: list[str]) -> str | None:
    """Map the router's reply onto exactly one registered specialist name.

    Exact (case-insensitive) match wins; otherwise the reply must mention
    exactly one registered name as a whole word. ``None`` means the reply is
    unroutable (unknown or ambiguous).
    """
    text = reply.strip().lower()
    for name in names:
        if text == name:
            return name
    mentioned = [name for name in names if re.search(rf"\b{re.escape(name)}\b", text)]
    if len(mentioned) == 1:
        return mentioned[0]
    return None


def build_supervisor_graph(
    llm: BaseChatModel,
    registry: AgentRegistry,
    *,
    trace_recorder: TraceRecorder | None = None,
) -> CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState]:
    """Compile the supervisor graph over the specialists in *registry*.

    Topology: ``START -> route -> <specialist subgraph> -> finalize -> END``.
    The ``route`` node starts a :class:`ReasoningTrace`, asks *llm* to choose
    a specialist (versioned routing prompt, ADR-0009), and records the
    decision as a ``plan`` step. The chosen specialist's subgraph (built via
    its ``build_graph(llm)``) processes the conversation. ``finalize``
    records ``observation``/``conclusion`` steps and completes the trace, so
    the returned state carries the result *and* its explanation.

    Raises
    ------
    SupervisorRoutingError
        At build time if *registry* is empty; at run time (from the ``route``
        node) if the model's reply cannot be mapped to exactly one
        registered specialist.
    """
    specialists = registry.list()
    if not specialists:
        raise SupervisorRoutingError(
            "cannot build the supervisor graph: no specialist agents are registered"
        )
    names = [agent.name for agent in specialists]
    recorder: TraceRecorder = (
        trace_recorder if trace_recorder is not None else InMemoryTraceRecorder()
    )
    prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
    roster = "\n".join(f"- {agent.name}: {agent.description}" for agent in specialists)
    routing_system_message = SystemMessage(content=prompt.text.format(specialists=roster))

    async def route(state: SupervisorState) -> dict[str, Any]:
        """Start the trace and pick one specialist for the conversation."""
        trace = await recorder.start(SUPERVISOR_NAME)
        response = await llm.ainvoke([routing_system_message, *state["messages"]])
        reply = _message_text(response.content)
        choice = _parse_specialist_choice(reply, names)
        if choice is None:
            await recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.PLAN,
                    summary="routing failed: reply did not name exactly one specialist",
                    detail=reply,
                ),
            )
            await recorder.complete(trace.trace_id)
            raise SupervisorRoutingError(
                f"routing reply {reply!r} does not name exactly one registered specialist "
                f"(registered: {', '.join(names)})"
            )
        trace = await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.PLAN,
                summary=f"route request to specialist '{choice}'",
                detail=reply,
            ),
        )
        return {"specialist": choice, "trace": trace}

    async def finalize(state: SupervisorState) -> dict[str, Any]:
        """Record the specialist's result and complete the trace."""
        trace = state["trace"]
        if trace is None:  # pragma: no cover - route always sets the trace
            raise SupervisorRoutingError("supervisor state lost its reasoning trace")
        specialist = state["specialist"]
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.OBSERVATION,
                summary=f"specialist '{specialist}' completed its subgraph run",
            ),
        )
        conclusion = _message_text(state["messages"][-1].content) if state["messages"] else ""
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=conclusion or "specialist produced no final message",
            ),
        )
        completed = await recorder.complete(trace.trace_id)
        return {"trace": completed}

    graph: StateGraph[SupervisorState, None, SupervisorState, SupervisorState] = StateGraph(
        SupervisorState
    )
    graph.add_node("route", route)
    graph.add_node("finalize", finalize)
    for agent in specialists:
        graph.add_node(agent.name, agent.build_graph(llm))
        graph.add_edge(agent.name, "finalize")
    graph.add_edge(START, "route")
    graph.add_conditional_edges(
        "route", lambda state: state["specialist"], {name: name for name in names}
    )
    graph.add_edge("finalize", END)
    return graph.compile(name=SUPERVISOR_NAME)


async def run_supervisor(
    graph: CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState],
    messages: Sequence[BaseMessage],
    *,
    role: Role,
) -> SupervisorState:
    """Drive the compiled supervisor *graph* as the invoking user (brief §7).

    This is the production run entrypoint: an API route resolves the
    authenticated :class:`~app.models.User` via ``get_current_user`` and passes
    that user's role (``Role.from_name(user.role.name)``) here. The role is
    bound with :func:`~app.agents.framework.tools.agent_run_context` for the
    *entire* graph invocation, so every :class:`~app.agents.framework.tools.NetOpsTool`
    executed inside any specialist subgraph sees the real caller role — a tool
    whose ``min_role`` is ``operator``/``engineer``/``admin`` is reachable
    through the agent exactly when (and only when) the user holds that rank
    ("an agent can never do what its user cannot").

    Without this binding the tool-layer RBAC contextvar stays unbound and
    falls back to :attr:`~app.core.security.Role.VIEWER`, leaving every
    higher-tier tool permanently unreachable through an agent run.

    Returns the final :class:`SupervisorState` (the conversation plus its
    completed :class:`~app.agents.framework.traces.ReasoningTrace`).
    """
    # The graph populates ``specialist`` and ``trace``; the entrypoint only
    # seeds the conversation, so the partial input is cast to the state type
    # the compiled graph accepts at its START node.
    initial_state = cast(SupervisorState, {"messages": list(messages)})
    with agent_run_context(role=role):
        final_state = await graph.ainvoke(initial_state)
    return cast(SupervisorState, final_state)
