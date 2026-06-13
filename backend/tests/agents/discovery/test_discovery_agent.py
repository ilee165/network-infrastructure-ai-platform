"""Tests for the Discovery Agent (M3-12).

Three mandatory behaviours:

1. Tool classification — every tool on the agent is READ_ONLY; no
   STATE_CHANGING tool is present (the spec explicitly forbids write tools
   on the Discovery Agent in M3).
2. Agent graph runs deterministically under ScriptedChatModel with faked
   tools; the agent can be built, registered, and its graph executed fully
   offline.
3. Registration — the package-level singleton registers cleanly into an
   AgentRegistry without conflicts.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from app.agents.discovery import DiscoveryAgent, discovery_agent, registry
from app.agents.discovery.agent import DiscoveryAgent as _AgentImpl
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import ToolClassification
from tests.agents.conftest import scripted_model

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent() -> DiscoveryAgent:
    """Return a fresh DiscoveryAgent (separate from the module singleton)."""
    return DiscoveryAgent()


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestDiscoveryAgentIdentity:
    def test_name_is_discovery(self) -> None:
        agent = _make_agent()
        assert agent.name == "discovery"

    def test_description_is_non_empty(self) -> None:
        agent = _make_agent()
        assert agent.description.strip(), "description must not be empty"

    def test_description_mentions_discovery_or_inventory(self) -> None:
        agent = _make_agent()
        desc = agent.description.lower()
        assert any(w in desc for w in ("discover", "inventory", "device", "neighbor")), (
            f"description does not mention discovery context: {agent.description!r}"
        )

    def test_system_prompt_is_non_empty(self) -> None:
        agent = _make_agent()
        assert agent.system_prompt.strip(), "system_prompt must not be empty"

    def test_validate_definition_passes(self) -> None:
        """validate_definition() must not raise for a well-formed agent."""
        _make_agent().validate_definition()


# ---------------------------------------------------------------------------
# Tool classification — all READ_ONLY, no STATE_CHANGING
# ---------------------------------------------------------------------------


class TestDiscoveryToolClassification:
    def test_has_at_least_one_tool(self) -> None:
        agent = _make_agent()
        assert len(agent.tools) >= 1, "Discovery Agent must expose at least one tool"

    def test_all_tools_are_read_only(self) -> None:
        agent = _make_agent()
        for tool in agent.tools:
            assert tool.classification is ToolClassification.READ_ONLY, (
                f"tool '{tool.name}' is {tool.classification}; "
                "Discovery Agent tools must all be READ_ONLY"
            )

    def test_no_state_changing_tool_present(self) -> None:
        """A STATE_CHANGING tool must never appear on the Discovery Agent."""
        agent = _make_agent()
        state_changing = [
            tool.name
            for tool in agent.tools
            if tool.classification is ToolClassification.STATE_CHANGING
        ]
        assert not state_changing, (
            f"STATE_CHANGING tools found on Discovery Agent: {state_changing}"
        )

    def test_no_diagnostic_tool_present(self) -> None:
        """DIAGNOSTIC tools (ADR-0014 bounded captures) are not a Discovery Agent concern."""
        agent = _make_agent()
        diagnostic = [
            tool.name
            for tool in agent.tools
            if tool.classification is ToolClassification.DIAGNOSTIC
        ]
        assert not diagnostic, f"DIAGNOSTIC tools found on Discovery Agent: {diagnostic}"

    def test_trigger_discovery_run_tool_present(self) -> None:
        names = {t.name for t in _make_agent().tools}
        assert "trigger_discovery_run" in names, (
            "expected 'trigger_discovery_run' tool on DiscoveryAgent"
        )

    def test_list_devices_tool_present(self) -> None:
        names = {t.name for t in _make_agent().tools}
        assert "list_devices" in names, "expected 'list_devices' tool on DiscoveryAgent"

    def test_get_device_tool_present(self) -> None:
        names = {t.name for t in _make_agent().tools}
        assert "get_device" in names, "expected 'get_device' tool on DiscoveryAgent"

    def test_query_neighbors_tool_present(self) -> None:
        names = {t.name for t in _make_agent().tools}
        assert "query_neighbors" in names, "expected 'query_neighbors' tool on DiscoveryAgent"

    def test_all_tools_are_netops_tool_instances(self) -> None:
        from app.agents.framework.tools import NetOpsTool

        agent = _make_agent()
        for tool in agent.tools:
            assert isinstance(tool, NetOpsTool), (
                f"tool '{tool.name}' is not a NetOpsTool; "
                "all agent tools must be built with @netops_tool"
            )

    def test_all_tools_have_non_empty_description(self) -> None:
        agent = _make_agent()
        for tool in agent.tools:
            assert tool.description.strip(), f"tool '{tool.name}' has an empty description"


# ---------------------------------------------------------------------------
# Graph construction and offline execution
# ---------------------------------------------------------------------------


class TestDiscoveryAgentGraph:
    async def test_build_graph_returns_compiled_graph(self) -> None:
        """build_graph() should compile without raising."""
        agent = _make_agent()
        llm = scripted_model([AIMessage(content="Discovery complete.")])
        graph = agent.build_graph(llm)
        assert graph is not None

    async def test_graph_runs_with_scripted_model(self) -> None:
        """Agent graph executes a single model turn fully offline."""
        agent = _make_agent()
        # Script a plain text response — no tool calls — so the graph
        # terminates in one model turn.
        llm = scripted_model([AIMessage(content="I found 3 devices in inventory.")])
        graph = agent.build_graph(llm)
        result = await graph.ainvoke(
            {"messages": [HumanMessage(content="How many devices are in the inventory?")]}
        )
        messages = result["messages"]
        assert any("3 devices" in str(m.content) for m in messages), (
            f"Expected scripted reply in messages; got {messages}"
        )

    async def test_graph_name_matches_agent_name(self) -> None:
        agent = _make_agent()
        llm = scripted_model([AIMessage(content="ok")])
        graph = agent.build_graph(llm)
        # CompiledStateGraph.name is set from the name argument of graph.compile()
        assert graph.name == "discovery"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestDiscoveryAgentRegistration:
    def test_package_singleton_is_discovery_agent(self) -> None:
        assert isinstance(discovery_agent, _AgentImpl)

    def test_package_singleton_name_is_discovery(self) -> None:
        assert discovery_agent.name == "discovery"

    def test_package_registry_contains_discovery(self) -> None:
        assert "discovery" in registry

    def test_register_fresh_instance_in_new_registry(self) -> None:
        """A fresh registry can register a new DiscoveryAgent instance."""
        fresh_registry = AgentRegistry()
        agent = _make_agent()
        fresh_registry.register(agent)
        assert "discovery" in fresh_registry

    def test_double_register_raises_conflict(self) -> None:
        """Registering two agents with the same name raises ConflictError."""
        from app.core.errors import ConflictError

        fresh_registry = AgentRegistry()
        fresh_registry.register(_make_agent())
        try:
            fresh_registry.register(_make_agent())
            raise AssertionError("expected ConflictError from double-register")
        except ConflictError:
            pass
