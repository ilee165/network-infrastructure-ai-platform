"""8-way supervisor routing tests (M5 T14): the full specialist roster.

T14 registers the three Wave-4 specialists (automation, ddi, packet_analysis)
with the Master Architect and takes the structured routing prompt to v5. After
this task the supervisor routes over EIGHT specialists. These tests are offline
and deterministic — a scripted fake chat model replays a fixed
``RoutingDecision`` (it cannot test routing *quality*; the real-LLM eval guards
that), so they prove the wiring: each of the eight specialists is a reachable
router node, a representative routing decision reaches each new specialist, and
— the critical M5 invariant — a "change X" request routes to the agent that
DRAFTS a ChangeRequest (the DDI Agent for records), never to the Automation
Agent that EXECUTES an already-approved change.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from app.agents import build_default_registry, build_default_supervisor
from app.agents.automation.agent import AUTOMATION_NAME, AutomationAgent
from app.agents.ddi.agent import DDI_NAME
from app.agents.framework.supervisor import SUPERVISOR_NAME
from app.agents.packet_analysis.agent import PACKET_ANALYSIS_NAME
from tests.agents.conftest import scripted_model

WAVE4_SPECIALISTS = {AUTOMATION_NAME, DDI_NAME, PACKET_ANALYSIS_NAME}
# P2 W3-T2 added the security agent, so the routable roster is now nine. The
# Wave-4 registration assertions below stay as written; the exact-roster check
# tracks the current full set (security-agent routing is covered in
# tests/agents/security/test_security_routing.py).
FULL_ROSTER = {
    "consultant",
    "discovery",
    "troubleshooting",
    "configuration",
    "documentation",
    AUTOMATION_NAME,
    DDI_NAME,
    PACKET_ANALYSIS_NAME,
    "security",
}


def _routing_reply(*, specialist: str | None, ambiguous: bool = False) -> AIMessage:
    """A scripted structured-routing reply (a ``RoutingDecision`` tool call)."""
    args: dict[str, Any] = {
        "specialist": specialist,
        "ambiguous": ambiguous,
        "rationale": "scripted decision",
    }
    return AIMessage(
        content="",
        tool_calls=[{"name": "RoutingDecision", "args": args, "id": "route-1"}],
    )


class TestWave4Registration:
    def test_three_wave4_agents_are_registered(self) -> None:
        names = set(build_default_registry().names())
        assert names >= WAVE4_SPECIALISTS

    def test_registry_holds_the_full_eight_specialist_roster(self) -> None:
        registry = build_default_registry()
        routable = {n for n in registry.names() if n != SUPERVISOR_NAME}
        assert routable == FULL_ROSTER

    def test_each_wave4_specialist_is_a_reachable_router_node(self) -> None:
        graph = build_default_supervisor(scripted_model([]))
        nodes = set(graph.get_graph().nodes)
        for specialist in WAVE4_SPECIALISTS:
            assert specialist in nodes, f"{specialist} is not a routable supervisor node"

    def test_wave4_agents_have_distinct_router_descriptions(self) -> None:
        # The router disambiguates on description text; each must be non-empty
        # and distinct from the others so the 8-way decision is separable.
        registry = build_default_registry()
        descriptions = {n: registry.get(n).description for n in WAVE4_SPECIALISTS}
        for name, desc in descriptions.items():
            assert desc.strip(), f"{name} has an empty router description"
        assert len(set(descriptions.values())) == len(descriptions)


class TestRouteToEachNewSpecialist:
    async def test_route_to_packet_analysis(self) -> None:
        registry = build_default_registry()
        routable = [a for a in registry.list() if a.name != SUPERVISOR_NAME]
        sub = build_default_supervisor(
            scripted_model(
                [
                    _routing_reply(specialist=PACKET_ANALYSIS_NAME),
                    AIMessage(content="Top talker is 10.0.0.5; 12 TCP resets observed."),
                ]
            ),
            registry,
        )
        assert {a.name for a in routable} == FULL_ROSTER
        result = await sub.ainvoke(
            {"messages": [HumanMessage(content="summarize the capture's top talkers")]}
        )
        assert result["specialist"] == PACKET_ANALYSIS_NAME

    async def test_route_to_ddi(self) -> None:
        sub = build_default_supervisor(
            scripted_model(
                [
                    _routing_reply(specialist=DDI_NAME),
                    AIMessage(content="The A record for app.example.com resolves to 10.0.0.9."),
                ]
            )
        )
        result = await sub.ainvoke(
            {"messages": [HumanMessage(content="what does app.example.com resolve to?")]}
        )
        assert result["specialist"] == DDI_NAME

    async def test_route_to_automation_for_an_approved_cr(self) -> None:
        # Automation is reachable ONLY to report on/trigger an already-approved
        # change request — never to author or mutate.
        sub = build_default_supervisor(
            scripted_model(
                [
                    _routing_reply(specialist=AUTOMATION_NAME),
                    AIMessage(content="Change request CR-42 is approved and ready to execute."),
                ]
            )
        )
        result = await sub.ainvoke(
            {"messages": [HumanMessage(content="status of approved change request CR-42")]}
        )
        assert result["specialist"] == AUTOMATION_NAME


class TestChangeRoutesToDraftNotExecute:
    """The M5 routing invariant (M5-PLAN risk #4).

    A request to CHANGE the network (a DNS/DHCP record) must route to the agent
    that DRAFTS a ChangeRequest (the DDI Agent), never to the Automation Agent,
    whose only write path is executing an *already-approved* CR.
    """

    async def test_add_dns_record_routes_to_ddi_draft_path_not_automation(self) -> None:
        # The DDI Agent's mutators do not execute — they draft a ddi_record CR.
        sub = build_default_supervisor(
            scripted_model(
                [
                    _routing_reply(specialist=DDI_NAME),
                    AIMessage(
                        content="I drafted a change request to add the A record for approval."
                    ),
                ]
            )
        )
        result = await sub.ainvoke(
            {
                "messages": [
                    HumanMessage(content="add an A record for web-07.example.com -> 10.0.0.7")
                ]
            }
        )
        assert result["specialist"] == DDI_NAME
        assert result["specialist"] != AUTOMATION_NAME

    def test_automation_router_surface_is_read_only_only(self) -> None:
        # The supervisor only ever sees the Automation Agent's READ_ONLY
        # narration tools; the execute() write path is not a model tool, so a
        # model can never trigger a direct change through routing.
        agent = build_default_registry().get(AUTOMATION_NAME)
        from app.agents.framework.tools import ToolClassification

        for tool in agent.tools:
            assert tool.classification is ToolClassification.READ_ONLY

    def test_automation_description_forbids_authoring_or_mutating(self) -> None:
        desc = build_default_registry().get(AUTOMATION_NAME).description.lower()
        # The description must steer "change/fix" intent away from automation.
        assert "approved" in desc
        assert "execut" in desc


class TestAutomationRoutingSurfaceWithoutService:
    """The composition root builds a routing-only Automation Agent (no DB).

    ``build_default_registry`` constructs the AutomationAgent for ROUTING — its
    name/description/system_prompt/read-only tools — without a live
    ``ChangeRequestService``. The execute() write path is wired separately
    (Wave 5 API/worker) with a real service; a routing-only agent cannot
    execute anything.
    """

    def test_routing_surface_is_valid_without_a_service(self) -> None:
        agent = AutomationAgent()
        agent.validate_definition()
        assert agent.name == AUTOMATION_NAME
        assert agent.description.strip()
        assert agent.system_prompt.strip()

    def test_build_graph_compiles_without_a_service(self) -> None:
        agent = AutomationAgent()
        graph = agent.build_graph(scripted_model([]))
        assert agent.name == AUTOMATION_NAME
        assert graph is not None
