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

import json
from typing import Annotated

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from pydantic import Field

from app.agents.discovery import DiscoveryAgent, discovery_agent, registry
from app.agents.discovery.agent import DiscoveryAgent as _AgentImpl
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import ToolClassification, netops_tool
from tests.agents.conftest import scripted_model

# ---------------------------------------------------------------------------
# Module-level stub tool for tool-dispatch test (Finding 3)
# ---------------------------------------------------------------------------
# Defined at module scope so Pydantic's annotation resolution (which uses
# eval() against the function's module globals) can see ``Annotated`` and
# ``Field`` without NameError.

_STUB_LIST_DEVICES_PAYLOAD = json.dumps(
    {"total": 1, "limit": 50, "offset": 0, "items": [{"id": "abc", "hostname": "sw1"}]}
)


@netops_tool(classification=ToolClassification.READ_ONLY, name="list_devices")
async def _stub_list_devices(
    status_filter: Annotated[str | None, Field(default=None)] = None,
    vendor_id: Annotated[str | None, Field(default=None)] = None,
    limit: Annotated[int, Field(ge=1, le=500)] = 50,
    offset: Annotated[int, Field(ge=0)] = 0,
) -> str:
    """List inventory devices (stub for offline graph-execution test)."""
    return _STUB_LIST_DEVICES_PAYLOAD


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

    def test_description_states_diagnosis_boundary(self) -> None:
        """Discovery must disclaim fault diagnosis so the router does not grab it
        for troubleshooting questions (regression: routed 'read the routing table
        to find why X is broken' to discovery instead of troubleshooting)."""
        desc = _make_agent().description.lower()
        # Still owns enumeration:
        assert "inventory" in desc
        assert "neighbor" in desc
        # Now explicitly NOT diagnosis:
        assert "diagnos" in desc  # "not for diagnosing ..."
        assert "troubleshooting" in desc  # points the router at the right specialist

    def test_description_uses_enumeration_framing(self) -> None:
        """Description must frame the agent's role as enumeration so the v3
        routing prompt's 'discovery = enumeration' rule maps cleanly."""
        desc = _make_agent().description.lower()
        assert "enumerat" in desc  # "ENUMERATES what exists"

    def test_description_explicitly_not_for_reading_device_state(self) -> None:
        """Description must explicitly disclaim reading routing/BGP/OSPF/ACL
        state, since that is what caused the mis-routing regression."""
        desc = _make_agent().description.lower()
        # The new text names the specific domains that belong to troubleshooting
        assert "routing" in desc
        assert "bgp" in desc or "ospf" in desc or "acl" in desc

    def test_description_redirects_router_to_troubleshooting_specialist(self) -> None:
        """The description must explicitly name 'troubleshooting' as the right
        specialist for diagnosis, so the router has a clear redirect target."""
        desc = _make_agent().description
        # Case-insensitive check — the actual text uses lowercase "troubleshooting"
        assert "troubleshooting" in desc.lower()

    def test_description_read_only_claim_present(self) -> None:
        """Read-only claim must survive after the description update."""
        desc = _make_agent().description.lower()
        assert "read-only" in desc or "read only" in desc

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

    async def test_tool_node_executes_on_tool_call(self) -> None:
        """ToolNode branch fires when the model emits a tool_calls AIMessage.

        The test:
        1. Replaces ``list_devices`` in DISCOVERY_TOOLS with the module-level
           ``_stub_list_devices`` that returns a canned JSON payload without
           touching the DB or Celery.
        2. Scripts the model to emit one tool-call turn followed by a plain-
           text final reply.
        3. Asserts that a ToolMessage (produced by ToolNode) is present in
           the result, confirming the conditional-edge ToolNode branch executed.
        """
        import app.agents.discovery.tools as _tools_mod

        # Patch the module-level DISCOVERY_TOOLS list used by the agent so that
        # the ToolNode resolves the stub coroutine instead of the real DB-hitting
        # list_devices implementation.
        original_tools = _tools_mod.DISCOVERY_TOOLS[:]
        patched_tools = [
            _stub_list_devices if t.name == "list_devices" else t for t in original_tools
        ]
        _tools_mod.DISCOVERY_TOOLS[:] = patched_tools

        try:
            agent = _make_agent()

            # Script: first reply carries a tool call, second is a plain-text finish.
            tool_call_msg = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call-001",
                        "name": "list_devices",
                        "args": {"limit": 50},
                        "type": "tool_call",
                    }
                ],
            )
            final_msg = AIMessage(content="There is 1 device: sw1.")
            llm = scripted_model([tool_call_msg, final_msg])

            graph = agent.build_graph(llm)
            result = await graph.ainvoke({"messages": [HumanMessage(content="List all devices.")]})
        finally:
            # Restore original tools list regardless of test outcome.
            _tools_mod.DISCOVERY_TOOLS[:] = original_tools

        messages = result["messages"]
        tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
        assert tool_messages, (
            "Expected at least one ToolMessage from ToolNode; got: "
            f"{[type(m).__name__ for m in messages]}"
        )
        # Confirm the stub payload reached the ToolMessage content.
        assert any("sw1" in str(m.content) for m in tool_messages), (
            f"Expected stub payload in ToolMessage content; tool messages: {tool_messages}"
        )


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
