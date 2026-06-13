"""Master Architect supervisor graph (ADR-0003: LangGraph supervisor pattern).

The supervisor receives user intent, plans, routes to exactly one registered
specialist, runs that specialist's compiled subgraph, and synthesizes the
final answer — returning the conversation with a
:class:`~app.agents.framework.traces.ReasoningTrace` attached so every routing
decision is explainable (CLAUDE.md: explain all AI decisions).

M3 scope (M3-06): the full Master Architect loop
``START -> route -> <specialist subgraph> -> synthesize -> END``. Routing is
**structured-output** routing — ``llm.with_structured_output(RoutingDecision)``
returns a typed ``specialist`` / ``ambiguous`` / ``rationale`` decision instead
of free text. When the decision is ambiguous, or names no (or an unknown)
specialist, the supervisor escalates to the **Consultant Agent**
(ADR-0003 Decision 2) rather than raising — the consultant asks the clarifying
question. The trace is recorded through an injected
:class:`~app.agents.framework.traces.TraceRecorder` (runtime default
``PostgresTraceRecorder`` from M3-02; tests use ``InMemoryTraceRecorder``), and
behaviour is deterministic under the scripted fake chat model used in tests
(which replays a structured ``RoutingDecision`` tool call).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, SystemMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

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

#: String id of the Consultant Agent — the escalation target for ambiguous or
#: unroutable intent (ADR-0003 Decision 2). The supervisor routes here instead
#: of guessing or raising; the consultant asks the clarifying question.
CONSULTANT_NAME = "consultant"


class SupervisorRoutingError(NetOpsError):
    """The supervisor could not route the request to a specialist."""

    status_code = 500
    title = "Supervisor Routing Failure"
    slug = "supervisor-routing"


class RoutingDecision(BaseModel):
    """Structured routing decision returned by ``with_structured_output``.

    The Master Architect's router emits this instead of free text: ``specialist``
    is the chosen agent's name (``None`` when no specialist fits), ``ambiguous``
    flags requests too vague to route confidently, and ``rationale`` is a short
    explanation recorded in the reasoning trace.
    """

    #: Name of the chosen specialist, or ``None`` when none clearly fits.
    specialist: str | None = Field(
        default=None,
        description="Name of the single best-fit specialist, or null if none fits.",
    )
    #: Whether the request is too ambiguous to route confidently.
    ambiguous: bool = Field(
        default=False,
        description="True when the request is too vague to route without clarification.",
    )
    #: One-sentence explanation of the decision (recorded in the trace).
    rationale: str = Field(
        default="",
        description="Short explanation of the routing decision.",
    )


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


def _resolve_target(decision: RoutingDecision, names: list[str]) -> tuple[str | None, str]:
    """Map a :class:`RoutingDecision` onto a registered specialist node name.

    Returns ``(target, summary)`` where *target* is the node to route to and
    *summary* is the human-readable route-step summary. *target* is ``None``
    only when the request must escalate to the consultant but no consultant is
    registered — the caller surfaces that as a :class:`SupervisorRoutingError`.

    The decision escalates to the consultant when it is ``ambiguous`` or when
    its ``specialist`` is ``None``/unknown; otherwise it routes to the named
    specialist (ADR-0003 Decision 2).
    """
    chosen = decision.specialist
    if not decision.ambiguous and chosen in names:
        return chosen, f"route request to specialist '{chosen}'"
    # Escalation path: ambiguous intent, or no/unknown specialist named.
    if CONSULTANT_NAME in names:
        if decision.ambiguous:
            reason = "request is ambiguous"
        elif chosen is None:
            reason = "no specialist was selected"
        else:
            reason = f"specialist '{chosen}' is not registered"
        return CONSULTANT_NAME, (f"escalate to the consultant ('{CONSULTANT_NAME}'): {reason}")
    return None, "routing failed: no specialist matched and no consultant is registered"


def build_supervisor_graph(
    llm: BaseChatModel,
    registry: AgentRegistry,
    *,
    trace_recorder: TraceRecorder | None = None,
) -> CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState]:
    """Compile the Master Architect supervisor graph over *registry*.

    Topology: ``START -> route -> <specialist subgraph> -> synthesize -> END``.

    The ``route`` node starts a :class:`ReasoningTrace`, records a ``plan``
    step, asks *llm* for a structured :class:`RoutingDecision`
    (``with_structured_output``, versioned routing prompt, ADR-0009), and
    records the routing choice as a second ``plan`` step. Ambiguous or
    unroutable intent escalates to the Consultant Agent
    (:data:`CONSULTANT_NAME`) instead of raising. The chosen specialist's
    subgraph (built via its ``build_graph(llm)``) processes the conversation.
    ``synthesize`` composes the final user-facing answer from the specialist's
    output, recording ``observation`` and ``conclusion`` steps and completing
    the trace — so the returned state carries the result *and* its explanation.

    The trace is recorded through *trace_recorder* (runtime default
    :class:`~app.agents.framework.traces.PostgresTraceRecorder`, M3-02; tests
    pass :class:`~app.agents.framework.traces.InMemoryTraceRecorder`); when
    ``None`` an in-memory recorder is used.

    Raises
    ------
    SupervisorRoutingError
        At build time if *registry* is empty; at run time (from the ``route``
        node) only when the request must escalate but no ``consultant`` agent
        is registered.
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
    router = llm.with_structured_output(RoutingDecision)

    async def route(state: SupervisorState) -> dict[str, Any]:
        """Plan, then pick one specialist (or escalate to the consultant)."""
        trace = await recorder.start(SUPERVISOR_NAME)
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.PLAN,
                summary="plan: analyze the request and select a specialist to handle it",
            ),
        )
        decision = cast(
            RoutingDecision,
            await router.ainvoke([routing_system_message, *state["messages"]]),
        )
        target, summary = _resolve_target(decision, names)
        if target is None:
            await recorder.record_step(
                trace.trace_id,
                TraceStep(kind=TraceStepKind.PLAN, summary=summary, detail=decision.rationale),
            )
            await recorder.complete(trace.trace_id)
            raise SupervisorRoutingError(
                f"intent is unroutable ({decision.rationale!r}) and no '{CONSULTANT_NAME}' "
                f"agent is registered to escalate to (registered: {', '.join(names)})"
            )
        trace = await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.PLAN,
                summary=summary,
                detail=decision.rationale or None,
            ),
        )
        return {"specialist": target, "trace": trace}

    async def synthesize(state: SupervisorState) -> dict[str, Any]:
        """Compose the final answer and complete the trace (Master Architect synthesize)."""
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
        answer = _message_text(state["messages"][-1].content) if state["messages"] else ""
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=answer or "specialist produced no final message",
            ),
        )
        completed = await recorder.complete(trace.trace_id)
        return {"trace": completed}

    graph: StateGraph[SupervisorState, None, SupervisorState, SupervisorState] = StateGraph(
        SupervisorState
    )
    graph.add_node("route", route)
    graph.add_node("synthesize", synthesize)
    for agent in specialists:
        graph.add_node(agent.name, agent.build_graph(llm))
        graph.add_edge(agent.name, "synthesize")
    graph.add_edge(START, "route")
    graph.add_conditional_edges(
        "route", lambda state: state["specialist"], {name: name for name in names}
    )
    graph.add_edge("synthesize", END)
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
