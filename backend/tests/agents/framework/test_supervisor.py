"""Tests for the Master Architect supervisor graph
(app/agents/framework/supervisor.py), driven by a scripted fake chat model."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import (
    SUPERVISOR_NAME,
    SupervisorRoutingError,
    build_supervisor_graph,
    run_supervisor,
)
from app.agents.framework.tools import (
    NetOpsTool,
    RbacForbiddenError,
    ToolClassification,
    netops_tool,
)
from app.agents.framework.traces import InMemoryTraceRecorder, ReasoningTrace, TraceStepKind
from app.core.security import Role
from tests.agents.conftest import RecordingAuditSink, SpecialistFactory, scripted_model


def _bgp_tool(sink: RecordingAuditSink) -> NetOpsTool:
    @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=sink)
    async def get_bgp_peers(device: str) -> str:
        """Read BGP peer status from a device."""
        return f"{device}: peer 10.0.0.2 is Idle"

    return get_bgp_peers


def _engineer_bgp_tool(sink: RecordingAuditSink) -> NetOpsTool:
    @netops_tool(
        classification=ToolClassification.READ_ONLY,
        audit_sink=sink,
        min_role=Role.ENGINEER,
    )
    async def get_bgp_peers(device: str) -> str:
        """Read BGP peer status from a device (engineer-tier diagnostic read)."""
        return f"{device}: peer 10.0.0.2 is Idle"

    return get_bgp_peers


def _two_specialist_registry(
    specialist_factory: SpecialistFactory, sink: RecordingAuditSink
) -> AgentRegistry:
    registry = AgentRegistry()
    registry.register(
        specialist_factory("discovery", description="Discovers devices, interfaces, and neighbors.")
    )
    registry.register(
        specialist_factory(
            "troubleshooting",
            description="Diagnoses routing, BGP, OSPF, DNS, and DHCP problems.",
            tools=[_bgp_tool(sink)],
        )
    )
    return registry


class TestBuildSupervisorGraph:
    def test_empty_registry_fails_at_build_time(self) -> None:
        llm = scripted_model([])
        with pytest.raises(SupervisorRoutingError, match="no specialist"):
            build_supervisor_graph(llm, AgentRegistry())

    def test_graph_compiles_with_registered_specialists(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _two_specialist_registry(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model([]), registry)
        node_names = set(graph.get_graph().nodes)
        assert {"route", "discovery", "troubleshooting", "finalize"} <= node_names


class TestRouting:
    async def test_supervisor_routes_and_attaches_trace(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _two_specialist_registry(specialist_factory, audit_sink)
        recorder = InMemoryTraceRecorder()
        llm = scripted_model(
            [
                # 1. routing decision
                AIMessage(content="troubleshooting"),
                # 2. specialist requests its tool
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "get_bgp_peers", "args": {"device": "edge-1"}, "id": "call-1"}
                    ],
                ),
                # 3. specialist concludes
                AIMessage(content="BGP peer 10.0.0.2 on edge-1 is down (Idle)."),
            ]
        )
        graph = build_supervisor_graph(llm, registry, trace_recorder=recorder)
        result = await graph.ainvoke(
            {"messages": [HumanMessage(content="why is BGP down on edge-1?")]}
        )

        assert result["specialist"] == "troubleshooting"
        assert result["messages"][-1].content == "BGP peer 10.0.0.2 on edge-1 is down (Idle)."

        trace = result["trace"]
        assert isinstance(trace, ReasoningTrace)
        assert trace.agent_name == SUPERVISOR_NAME
        assert trace.is_complete is True
        assert [step.kind for step in trace.steps] == [
            TraceStepKind.PLAN,
            TraceStepKind.OBSERVATION,
            TraceStepKind.CONCLUSION,
        ]
        assert "troubleshooting" in trace.steps[0].summary
        assert trace.steps[-1].summary == "BGP peer 10.0.0.2 on edge-1 is down (Idle)."
        # The recorder retains the same trace for later retrieval (M3: DB).
        assert recorder.get(trace.trace_id).is_complete is True
        # The specialist's classified tool was audited during the run.
        assert audit_sink.events[-1].tool_name == "get_bgp_peers"
        assert audit_sink.events[-1].outcome == "success"

    async def test_routing_reply_with_surrounding_text_still_routes(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _two_specialist_registry(specialist_factory, audit_sink)
        llm = scripted_model(
            [
                AIMessage(content="I choose discovery."),
                AIMessage(content="Found 3 new switches."),
            ]
        )
        graph = build_supervisor_graph(llm, registry)
        result = await graph.ainvoke({"messages": [HumanMessage(content="scan the network")]})
        assert result["specialist"] == "discovery"
        assert result["messages"][-1].content == "Found 3 new switches."

    async def test_unroutable_reply_raises_and_completes_the_trace(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _two_specialist_registry(specialist_factory, audit_sink)
        recorder = InMemoryTraceRecorder()
        llm = scripted_model([AIMessage(content="make me a sandwich")])
        graph = build_supervisor_graph(llm, registry, trace_recorder=recorder)
        with pytest.raises(SupervisorRoutingError, match="does not name exactly one"):
            await graph.ainvoke({"messages": [HumanMessage(content="hello")]})
        traces = recorder.list_traces()
        assert len(traces) == 1
        assert traces[0].is_complete is True
        assert traces[0].steps[0].kind is TraceStepKind.PLAN
        assert "routing failed" in traces[0].steps[0].summary

    async def test_ambiguous_reply_naming_two_specialists_raises(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _two_specialist_registry(specialist_factory, audit_sink)
        llm = scripted_model([AIMessage(content="either discovery or troubleshooting")])
        graph = build_supervisor_graph(llm, registry)
        with pytest.raises(SupervisorRoutingError):
            await graph.ainvoke({"messages": [HumanMessage(content="help")]})


def _engineer_tool_registry(
    specialist_factory: SpecialistFactory, sink: RecordingAuditSink
) -> AgentRegistry:
    """A registry whose troubleshooting specialist carries an engineer-tier tool."""
    registry = AgentRegistry()
    registry.register(
        specialist_factory("discovery", description="Discovers devices, interfaces, and neighbors.")
    )
    registry.register(
        specialist_factory(
            "troubleshooting",
            description="Diagnoses routing, BGP, OSPF, DNS, and DHCP problems.",
            tools=[_engineer_bgp_tool(sink)],
        )
    )
    return registry


def _engineer_run_script() -> list[AIMessage]:
    return [
        # 1. routing decision
        AIMessage(content="troubleshooting"),
        # 2. specialist requests its engineer-tier tool
        AIMessage(
            content="",
            tool_calls=[{"name": "get_bgp_peers", "args": {"device": "edge-1"}, "id": "call-1"}],
        ),
        # 3. specialist concludes
        AIMessage(content="BGP peer 10.0.0.2 on edge-1 is down (Idle)."),
    ]


class TestRunSupervisorBindsRole:
    """run_supervisor binds the invoking user's role for the whole graph run.

    Brief §7 / finding M3-03: the run entrypoint enters ``agent_run_context``
    with the authenticated user's role, so a non-viewer-tier tool is reachable
    through a real agent run (not just via direct ``tool.ainvoke``).
    """

    async def test_engineer_role_reaches_engineer_tier_tool_through_the_run(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _engineer_tool_registry(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model(_engineer_run_script()), registry)

        result = await run_supervisor(
            graph,
            [HumanMessage(content="why is BGP down on edge-1?")],
            role=Role.ENGINEER,
        )

        # The engineer-tier tool actually executed inside the supervised run.
        assert result["specialist"] == "troubleshooting"
        assert result["messages"][-1].content == "BGP peer 10.0.0.2 on edge-1 is down (Idle)."
        assert audit_sink.events[-1].tool_name == "get_bgp_peers"
        assert audit_sink.events[-1].outcome == "success"

    async def test_viewer_role_is_denied_the_engineer_tier_tool_through_the_run(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        # Without the role binding the run would fall back to viewer; assert the
        # binding is honoured by showing a viewer caller is denied mid-run.
        registry = _engineer_tool_registry(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model(_engineer_run_script()), registry)

        with pytest.raises(RbacForbiddenError):
            await run_supervisor(
                graph,
                [HumanMessage(content="why is BGP down on edge-1?")],
                role=Role.VIEWER,
            )
        assert audit_sink.events[-1].outcome == "denied"
