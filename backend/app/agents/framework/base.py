"""Specialist-agent base class (ADR-0003, REPO-STRUCTURE §7 step 3).

Each of the nine specialist agents subclasses :class:`BaseSpecialistAgent`,
declaring a ``name`` (string id == package name), a ``description`` written
*for the supervisor's router*, a ``system_prompt``, and a set of classified
:class:`~app.agents.framework.tools.NetOpsTool` instances. The default
:meth:`BaseSpecialistAgent.build_graph` compiles a ReAct-style LangGraph
subgraph from those declarations; specialists with bespoke topologies (e.g.
the Troubleshooting Agent's symptom -> hypothesis -> diagnosis flow, M3)
override it.

The graph is assembled from LangGraph prebuilt utilities (``ToolNode``,
``tools_condition``) rather than ``create_react_agent``, which is deprecated
since LangGraph 1.0 in favor of ``langchain.agents.create_agent`` — a package
outside the frozen dependency set (ADR-0003: contain LangGraph API churn
inside this framework layer).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from app.agents.framework.tools import NetOpsTool
from app.core.config import get_settings
from app.core.errors import NetOpsError

#: Agent ids are snake_case package names (REPO-STRUCTURE §4.1).
_AGENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

#: Marker appended when a ToolMessage body is truncated (Wave 5 / perf #11).
_TOOL_TRUNCATION_MARKER = "\n…[truncated for agent prompt budget]"


def _truncate_tool_content(content: object, max_chars: int) -> str:
    text = content if isinstance(content, str) else str(content)
    if len(text) <= max_chars:
        return text
    keep = max(0, max_chars - len(_TOOL_TRUNCATION_MARKER))
    return text[:keep] + _TOOL_TRUNCATION_MARKER


def bound_react_messages(
    messages: Sequence[BaseMessage],
    *,
    max_tool_chars: int,
    max_turns: int,
) -> list[BaseMessage]:
    """Cap ToolMessage size and keep only the last *max_turns* messages.

    Wave 5 / agents H3+H4: unbounded tool dumps and long ReAct histories
    inflate every subsequent model call. Truncation is deterministic and
    leaves a marker so the model can see that data was elided.
    """
    windowed: list[BaseMessage] = list(messages[-max_turns:]) if max_turns > 0 else list(messages)
    # Drop leading ToolMessages whose corresponding AIMessage(tool_calls) fell
    # outside the window — orphaned tool results cause OpenAI/Anthropic 400s.
    while windowed and isinstance(windowed[0], ToolMessage):
        windowed = windowed[1:]
    out: list[BaseMessage] = []
    for msg in windowed:
        if isinstance(msg, ToolMessage):
            truncated = _truncate_tool_content(msg.content, max_tool_chars)
            if truncated != msg.content:
                out.append(
                    ToolMessage(
                        content=truncated,
                        tool_call_id=msg.tool_call_id,
                        name=getattr(msg, "name", None),
                        id=getattr(msg, "id", None),
                    )
                )
            else:
                out.append(msg)
        else:
            out.append(msg)
    return out


class AgentDefinitionError(NetOpsError):
    """A specialist agent declaration violates the framework contract."""

    status_code = 500
    title = "Agent Definition Error"
    slug = "agent-definition"


class BaseSpecialistAgent(ABC):
    """Base class for the nine specialist agents (ADR-0003).

    Subclasses declare metadata via the four abstract properties; the
    framework supplies graph construction, registration, approval gating,
    and trace plumbing. Specialists never import engines/services directly —
    capability arrives exclusively through their declared
    :class:`~app.agents.framework.tools.NetOpsTool` set (REPO-STRUCTURE §3.2
    row 11).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """String id of the agent — must equal its package name (e.g. ``"discovery"``)."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Routing description, written for the supervisor's router (not for humans)."""

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt prepended to every model call inside the agent's graph."""

    @property
    @abstractmethod
    def tools(self) -> Sequence[NetOpsTool]:
        """The agent's classified tools; may be empty for pure-reasoning agents."""

    def validate_definition(self) -> None:
        """Check the declaration against the framework contract.

        Raises :class:`AgentDefinitionError` on: an invalid ``name``, an empty
        ``description`` or ``system_prompt``, or any tool that is not a
        :class:`~app.agents.framework.tools.NetOpsTool` (unclassified tools
        would bypass the audit/approval pipeline — never allowed).
        """
        if not _AGENT_NAME_RE.match(self.name):
            raise AgentDefinitionError(
                f"agent name {self.name!r} must be a snake_case identifier "
                "matching its package name (REPO-STRUCTURE §4.1)"
            )
        if not self.description.strip():
            raise AgentDefinitionError(
                f"agent '{self.name}' needs a non-empty description — the supervisor routes on it"
            )
        if not self.system_prompt.strip():
            raise AgentDefinitionError(f"agent '{self.name}' needs a non-empty system prompt")
        for tool in self.tools:
            if not isinstance(tool, NetOpsTool):
                raise AgentDefinitionError(
                    f"agent '{self.name}' declares tool "
                    f"{getattr(tool, 'name', tool)!r} that is not a NetOpsTool; all agent "
                    "tools must be built with @netops_tool so they are classified, "
                    "audited, and approval-gated (ADR-0003)"
                )

    def build_graph(
        self, llm: BaseChatModel
    ) -> CompiledStateGraph[MessagesState, None, MessagesState, MessagesState]:
        """Compile this agent's LangGraph subgraph against *llm*.

        Default topology is a ReAct loop: a model node (with the agent's
        tools bound and ``system_prompt`` prepended) alternates with a
        prebuilt ``ToolNode`` until the model stops emitting tool calls.
        Tool-less agents compile to a single model turn.

        *llm* comes from the ``llm`` provider registry (ADR-0009) — callers
        must never instantiate provider classes directly.
        """
        self.validate_definition()
        tools = list(self.tools)
        model = llm.bind_tools(tools) if tools else llm
        system_message = SystemMessage(content=self.system_prompt)

        async def call_model(state: MessagesState) -> dict[str, Any]:
            """One model turn over the conversation, system prompt prepended."""
            settings = get_settings()
            history = bound_react_messages(
                state["messages"],
                max_tool_chars=settings.agent_tool_output_max_chars,
                max_turns=settings.agent_history_max_turns,
            )
            response = await model.ainvoke([system_message, *history])
            return {"messages": [response]}

        graph: StateGraph[MessagesState, None, MessagesState, MessagesState] = StateGraph(
            MessagesState
        )
        graph.add_node("agent", call_model)
        graph.add_edge(START, "agent")
        if tools:
            graph.add_node("tools", ToolNode(tools))
            graph.add_conditional_edges("agent", tools_condition)
            graph.add_edge("tools", "agent")
        else:
            graph.add_edge("agent", END)
        return graph.compile(name=self.name)
