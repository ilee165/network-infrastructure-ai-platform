"""Tests for the Master Architect supervisor graph
(app/agents/framework/supervisor.py), driven by a scripted fake chat model.

M3-06 upgrades routing from M0 text parsing to structured-output routing
(``llm.with_structured_output(RoutingDecision)``) plus the full
plan -> route -> specialist -> synthesize loop and Consultant escalation for
ambiguous / unroutable intent. The scripted model replays a structured routing
decision as an ``AIMessage`` carrying a ``RoutingDecision`` tool call, which is
exactly what ``with_structured_output`` parses against ``ScriptedChatModel``.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

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
    NetOpsTool,
    RbacForbiddenError,
    ToolClassification,
    netops_tool,
)
from app.agents.framework.traces import InMemoryTraceRecorder, ReasoningTrace, TraceStepKind
from app.core.security import Role
from tests.agents.conftest import RecordingAuditSink, SpecialistFactory, scripted_model


def _routing_reply(
    *, specialist: str | None, ambiguous: bool = False, rationale: str = "best fit"
) -> AIMessage:
    """A scripted structured-routing reply (a ``RoutingDecision`` tool call).

    ``with_structured_output(RoutingDecision)`` binds ``RoutingDecision`` as a
    tool and parses the chosen call's args into the model, so a deterministic
    routing decision is expressed as a tool call rather than free text.
    """
    args: dict[str, Any] = {
        "specialist": specialist,
        "ambiguous": ambiguous,
        "rationale": rationale,
    }
    return AIMessage(
        content="",
        tool_calls=[{"name": "RoutingDecision", "args": args, "id": "route-1"}],
    )


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


def _registry_with_consultant(
    specialist_factory: SpecialistFactory, sink: RecordingAuditSink
) -> AgentRegistry:
    """A registry with discovery, troubleshooting, and the consultant escalation target."""
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
    registry.register(
        specialist_factory(
            CONSULTANT_NAME,
            description="Asks clarifying questions when the request is ambiguous.",
        )
    )
    return registry


def _registry_without_consultant(
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


class TestRoutingDecision:
    def test_routing_decision_is_a_structured_schema(self) -> None:
        decision = RoutingDecision(specialist="discovery", ambiguous=False, rationale="scan ask")
        assert decision.specialist == "discovery"
        assert decision.ambiguous is False
        assert decision.rationale == "scan ask"

    def test_routing_decision_allows_no_specialist_when_ambiguous(self) -> None:
        decision = RoutingDecision(specialist=None, ambiguous=True, rationale="unclear intent")
        assert decision.specialist is None
        assert decision.ambiguous is True


class TestBuildSupervisorGraph:
    def test_empty_registry_fails_at_build_time(self) -> None:
        llm = scripted_model([])
        with pytest.raises(SupervisorRoutingError, match="no specialist"):
            build_supervisor_graph(llm, AgentRegistry())

    def test_graph_has_route_synthesize_and_specialist_nodes(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model([]), registry)
        node_names = set(graph.get_graph().nodes)
        expected = {"route", "synthesize", "discovery", "troubleshooting", CONSULTANT_NAME}
        assert expected <= node_names


class TestStructuredRouting:
    async def test_structured_route_selects_the_named_specialist(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        recorder = InMemoryTraceRecorder()
        llm = scripted_model(
            [
                # 1. structured routing decision -> troubleshooting
                _routing_reply(specialist="troubleshooting", rationale="BGP fault question"),
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
        assert "BGP peer 10.0.0.2 on edge-1 is down (Idle)." in result["messages"][-1].content
        # The specialist's classified tool was audited during the run.
        assert audit_sink.events[-1].tool_name == "get_bgp_peers"
        assert audit_sink.events[-1].outcome == "success"

    async def test_structured_route_to_discovery(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        llm = scripted_model(
            [
                _routing_reply(specialist="discovery", rationale="network scan request"),
                AIMessage(content="Found 3 new switches."),
            ]
        )
        graph = build_supervisor_graph(llm, registry)
        result = await graph.ainvoke({"messages": [HumanMessage(content="scan the network")]})
        assert result["specialist"] == "discovery"
        assert "Found 3 new switches." in result["messages"][-1].content


class TestConsultantEscalation:
    async def test_ambiguous_intent_routes_to_consultant_not_exception(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        llm = scripted_model(
            [
                # routing says ambiguous, no specialist named
                _routing_reply(specialist=None, ambiguous=True, rationale="goal is unclear"),
                # the consultant specialist asks a clarifying question
                AIMessage(content="Which device or service is failing, and how?"),
            ]
        )
        graph = build_supervisor_graph(llm, registry)
        result = await graph.ainvoke({"messages": [HumanMessage(content="fix the network")]})
        assert result["specialist"] == CONSULTANT_NAME
        assert "Which device or service is failing" in result["messages"][-1].content

    async def test_unknown_specialist_routes_to_consultant(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        llm = scripted_model(
            [
                # names a specialist that is not registered
                _routing_reply(specialist="weather_bot", ambiguous=False, rationale="???"),
                AIMessage(content="I can help with network operations — what is the problem?"),
            ]
        )
        graph = build_supervisor_graph(llm, registry)
        result = await graph.ainvoke({"messages": [HumanMessage(content="make me a sandwich")]})
        assert result["specialist"] == CONSULTANT_NAME

    async def test_ambiguous_without_consultant_raises_routing_error(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_without_consultant(specialist_factory, audit_sink)
        recorder = InMemoryTraceRecorder()
        llm = scripted_model([_routing_reply(specialist=None, ambiguous=True, rationale="unclear")])
        graph = build_supervisor_graph(llm, registry, trace_recorder=recorder)
        with pytest.raises(SupervisorRoutingError, match="consultant"):
            await graph.ainvoke({"messages": [HumanMessage(content="hello")]})
        # The trace is still completed so the failed run remains explainable.
        traces = recorder.list_traces()
        assert len(traces) == 1
        assert traces[0].is_complete is True


class TestTrace:
    async def test_completed_run_trace_has_plan_route_observation_conclusion(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        recorder = InMemoryTraceRecorder()
        llm = scripted_model(
            [
                _routing_reply(specialist="troubleshooting", rationale="BGP fault question"),
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "get_bgp_peers", "args": {"device": "edge-1"}, "id": "call-1"}
                    ],
                ),
                AIMessage(content="BGP peer 10.0.0.2 on edge-1 is down (Idle)."),
            ]
        )
        graph = build_supervisor_graph(llm, registry, trace_recorder=recorder)
        result = await graph.ainvoke(
            {"messages": [HumanMessage(content="why is BGP down on edge-1?")]}
        )

        trace = result["trace"]
        assert isinstance(trace, ReasoningTrace)
        assert trace.agent_name == SUPERVISOR_NAME
        assert trace.is_complete is True

        kinds = [step.kind for step in trace.steps]
        # The full Master Architect loop: a plan step, the routing decision
        # (also a PLAN-kind step), the specialist observation, and the
        # synthesized conclusion — in that order.
        assert kinds[0] is TraceStepKind.PLAN
        assert TraceStepKind.PLAN in kinds
        assert kinds[-2] is TraceStepKind.OBSERVATION
        assert kinds[-1] is TraceStepKind.CONCLUSION
        assert kinds.count(TraceStepKind.PLAN) >= 2  # plan + route are distinct steps

        # A distinct "route" PLAN step names the chosen specialist.
        route_steps = [
            s
            for s in trace.steps
            if s.kind is TraceStepKind.PLAN and "troubleshooting" in s.summary
        ]
        assert route_steps, "expected a route step naming the chosen specialist"
        # The conclusion is the synthesized, user-facing answer.
        assert "BGP peer 10.0.0.2 on edge-1 is down (Idle)." in trace.steps[-1].summary
        # The recorder retains the same completed trace for later retrieval (M3: DB).
        assert recorder.get(trace.trace_id).is_complete is True

    async def test_consultant_run_trace_is_complete(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        registry = _registry_with_consultant(specialist_factory, audit_sink)
        recorder = InMemoryTraceRecorder()
        llm = scripted_model(
            [
                _routing_reply(specialist=None, ambiguous=True, rationale="ambiguous"),
                AIMessage(content="Could you clarify which device is affected?"),
            ]
        )
        graph = build_supervisor_graph(llm, registry, trace_recorder=recorder)
        result = await graph.ainvoke({"messages": [HumanMessage(content="help")]})
        trace = result["trace"]
        assert trace.is_complete is True
        assert trace.steps[-1].kind is TraceStepKind.CONCLUSION
        # The route step records that escalation went to the consultant.
        assert any(CONSULTANT_NAME in s.summary for s in trace.steps)


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
    registry.register(
        specialist_factory(
            CONSULTANT_NAME,
            description="Asks clarifying questions when the request is ambiguous.",
        )
    )
    return registry


def _engineer_run_script() -> list[AIMessage]:
    return [
        # 1. structured routing decision
        _routing_reply(specialist="troubleshooting", rationale="engineer-tier BGP read"),
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
        assert "BGP peer 10.0.0.2 on edge-1 is down (Idle)." in result["messages"][-1].content
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
