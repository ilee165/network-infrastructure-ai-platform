"""Tests for the Troubleshooting Agent (M3-13).

Mandatory behaviours (task M3-13):

1. Read-only contract — every tool is READ_ONLY; no STATE_CHANGING (or
   DIAGNOSTIC) tool is ever declared on this agent.
2. Grounded diagnosis — a "why is BGP peer X down on device Y" run returns an
   answer that cites the collected evidence as ``EvidenceRef`` entries on the
   reasoning trace (peer FSM state, route presence, etc.).
3. Offline determinism — the bespoke ``symptom -> hypothesis -> diagnosis``
   graph runs fully offline under ``ScriptedChatModel`` with fixture-backed
   fake tools (no network, no DB).
4. Registration — the package singleton registers cleanly.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Any

from langchain_core.messages import AIMessage, HumanMessage
from pydantic import Field

from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import NetOpsTool, ToolClassification, netops_tool
from app.agents.framework.traces import InMemoryTraceRecorder, TraceStepKind
from app.agents.troubleshooting import (
    TroubleshootingAgent,
    registry,
    troubleshooting_agent,
)
from app.agents.troubleshooting.agent import (
    AnalysisDomain,
    SymptomClassification,
)
from app.agents.troubleshooting.agent import (
    TroubleshootingAgent as _AgentImpl,
)
from tests.agents.conftest import scripted_model

DEVICE_Y = "11111111-1111-1111-1111-111111111111"
PEER_X = "10.0.0.2"

# ---------------------------------------------------------------------------
# Fixture-backed fake tools (module scope so Pydantic annotation eval sees
# Annotated/Field — the same constraint the discovery test documents).
# ---------------------------------------------------------------------------

_BGP_PEER_DOWN_PAYLOAD = json.dumps(
    {
        "device_id": DEVICE_Y,
        "peers": [
            {
                "peer_address": PEER_X,
                "remote_as": 65002,
                "local_as": 65001,
                "state": "idle",
                "vrf": None,
                "address_family": "ipv4_unicast",
                "prefixes_received": 0,
                "uptime_seconds": None,
            },
            {
                "peer_address": "10.0.0.3",
                "remote_as": 65003,
                "local_as": 65001,
                "state": "established",
                "vrf": None,
                "address_family": "ipv4_unicast",
                "prefixes_received": 12,
                "uptime_seconds": 4200,
            },
        ],
    }
)


@netops_tool(classification=ToolClassification.READ_ONLY, name="read_live_bgp_peers")
async def _fake_bgp_peers(
    device_id: Annotated[str, Field(description="device UUID")],
) -> str:
    """Fixture-backed BGP read: peer 10.0.0.2 is Idle, 10.0.0.3 Established."""
    return _BGP_PEER_DOWN_PAYLOAD


def _classification_reply(
    *, domain: str, device_id: str | None, target: str | None = None
) -> AIMessage:
    """A scripted structured ``SymptomClassification`` (a tool call).

    ``with_structured_output(SymptomClassification)`` binds the schema as a
    tool and parses the call's args into the model — exactly the supervisor
    routing pattern, applied to the symptom classifier.
    """
    args: dict[str, Any] = {
        "domain": domain,
        "device_id": device_id,
        "target": target,
        "rationale": "scripted classification",
    }
    return AIMessage(
        content="",
        tool_calls=[{"name": "SymptomClassification", "args": args, "id": "sym-1"}],
    )


def _make_agent(**kwargs: Any) -> TroubleshootingAgent:
    return TroubleshootingAgent(**kwargs)


@contextmanager
def _bgp_tool_patched() -> Iterator[None]:
    """Swap the real BGP tool for the fixture-backed fake on the agent's tool list.

    The agent imports the ``TROUBLESHOOTING_TOOLS`` list object by reference, so
    the swap is done *in place* (``list[:] = ...``) rather than by rebinding the
    module attribute — the established discovery-agent test pattern. The original
    contents are always restored, even on failure.
    """
    import app.agents.troubleshooting.tools as _tools_mod

    original = _tools_mod.TROUBLESHOOTING_TOOLS[:]
    _tools_mod.TROUBLESHOOTING_TOOLS[:] = [
        _fake_bgp_peers if t.name == "read_live_bgp_peers" else t for t in original
    ]
    try:
        yield
    finally:
        _tools_mod.TROUBLESHOOTING_TOOLS[:] = original


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestTroubleshootingIdentity:
    def test_name_is_troubleshooting(self) -> None:
        assert _make_agent().name == "troubleshooting"

    def test_description_non_empty_and_on_topic(self) -> None:
        desc = _make_agent().description.lower()
        assert desc.strip()
        assert any(w in desc for w in ("bgp", "ospf", "acl", "routing", "diagnos"))

    def test_system_prompt_non_empty(self) -> None:
        assert _make_agent().system_prompt.strip()

    def test_validate_definition_passes(self) -> None:
        _make_agent().validate_definition()


# ---------------------------------------------------------------------------
# Read-only contract — no STATE_CHANGING / DIAGNOSTIC tools
# ---------------------------------------------------------------------------


class TestTroubleshootingToolClassification:
    def test_has_tools(self) -> None:
        assert len(_make_agent().tools) >= 1

    def test_all_tools_read_only(self) -> None:
        for tool in _make_agent().tools:
            assert tool.classification is ToolClassification.READ_ONLY, (
                f"tool '{tool.name}' is {tool.classification}; all tools must be READ_ONLY"
            )

    def test_no_state_changing_tool_declared(self) -> None:
        """The spec forbids any STATE_CHANGING tool on the read-only Troubleshooting Agent."""
        offenders = [
            t.name
            for t in _make_agent().tools
            if t.classification is ToolClassification.STATE_CHANGING
        ]
        assert not offenders, f"STATE_CHANGING tools found: {offenders}"

    def test_no_diagnostic_tool_declared(self) -> None:
        offenders = [
            t.name for t in _make_agent().tools if t.classification is ToolClassification.DIAGNOSTIC
        ]
        assert not offenders, f"DIAGNOSTIC tools found: {offenders}"

    def test_expected_analysis_tools_present(self) -> None:
        names = {t.name for t in _make_agent().tools}
        for expected in (
            "get_device_routes",
            "read_live_bgp_peers",
            "read_live_ospf_neighbors",
            "read_live_acls",
        ):
            assert expected in names, f"missing analysis tool {expected!r}"

    def test_all_tools_are_netops_tool(self) -> None:
        for tool in _make_agent().tools:
            assert isinstance(tool, NetOpsTool)


# ---------------------------------------------------------------------------
# Bespoke symptom -> hypothesis -> diagnosis graph + grounded answer
# ---------------------------------------------------------------------------


class TestBgpPeerDownDiagnosis:
    async def test_graph_name_matches_agent(self) -> None:
        agent = _make_agent()
        graph = agent.build_graph(
            scripted_model([_classification_reply(domain="bgp", device_id=None)])
        )
        assert graph.name == "troubleshooting"

    async def test_why_bgp_peer_down_returns_grounded_answer(self) -> None:
        """'why is BGP peer X down on device Y' -> answer cites the Idle peer evidence."""
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)

        llm = scripted_model(
            [_classification_reply(domain="bgp", device_id=DEVICE_Y, target=PEER_X)]
        )
        graph = agent.build_graph(llm)
        with _bgp_tool_patched():
            result = await graph.ainvoke(
                {
                    "messages": [
                        HumanMessage(content=f"Why is BGP peer {PEER_X} down on device {DEVICE_Y}?")
                    ]
                }
            )

        # 1. A final answer was produced and it references the observed state.
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        text = str(final.content).lower()
        assert PEER_X in str(final.content)
        assert "idle" in text, f"answer should cite the Idle peer state; got {final.content!r}"

        # 2. The answer is grounded: evidence refs were recorded on the trace.
        traces = recorder.list_traces()
        assert len(traces) == 1
        trace = traces[0]
        assert trace.is_complete
        all_evidence = [ref for step in trace.steps for ref in step.evidence]
        assert all_evidence, "expected EvidenceRef entries grounding the answer"
        peer_refs = [r for r in all_evidence if r.kind == "bgp_peer"]
        assert peer_refs, f"expected a bgp_peer evidence ref; got {all_evidence}"
        # The cited evidence is the specific down peer the user asked about.
        assert any(PEER_X in r.reference for r in peer_refs)
        assert any("idle" in (r.description or "").lower() for r in peer_refs)

    async def test_trace_has_symptom_hypothesis_diagnosis_steps(self) -> None:
        """The bespoke flow records plan (symptom), tool_call (hypothesis), conclusion."""
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        llm = scripted_model(
            [_classification_reply(domain="bgp", device_id=DEVICE_Y, target=PEER_X)]
        )
        graph = agent.build_graph(llm)
        with _bgp_tool_patched():
            await graph.ainvoke(
                {"messages": [HumanMessage(content=f"BGP {PEER_X} down on {DEVICE_Y}?")]}
            )
        kinds = [step.kind for step in recorder.list_traces()[0].steps]
        assert TraceStepKind.PLAN in kinds
        assert TraceStepKind.TOOL_CALL in kinds
        assert TraceStepKind.CONCLUSION in kinds

    async def test_tool_call_step_names_the_tool(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        llm = scripted_model(
            [_classification_reply(domain="bgp", device_id=DEVICE_Y, target=PEER_X)]
        )
        graph = agent.build_graph(llm)
        with _bgp_tool_patched():
            await graph.ainvoke({"messages": [HumanMessage(content="bgp down?")]})
        tool_steps = [
            s for s in recorder.list_traces()[0].steps if s.kind is TraceStepKind.TOOL_CALL
        ]
        assert tool_steps
        assert tool_steps[0].tool_name == "read_live_bgp_peers"

    async def test_no_device_named_yields_ungrounded_honest_answer(self) -> None:
        """When no device is named, the agent refuses to guess and says so."""
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        llm = scripted_model([_classification_reply(domain="bgp", device_id=None)])
        result = await agent.build_graph(llm).ainvoke(
            {"messages": [HumanMessage(content="Why is BGP broken?")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        assert "could not ground" in str(final.content).lower()
        # No fabricated evidence.
        all_evidence = [ref for step in recorder.list_traces()[0].steps for ref in step.evidence]
        assert not all_evidence


# ---------------------------------------------------------------------------
# Evidence extraction unit behaviour
# ---------------------------------------------------------------------------


class TestEvidenceExtraction:
    def test_target_filters_to_the_named_peer(self) -> None:
        from app.agents.troubleshooting.agent import _evidence_from_tool_output

        refs = _evidence_from_tool_output(
            tool_name="read_live_bgp_peers",
            device_id=DEVICE_Y,
            target=PEER_X,
            raw=_BGP_PEER_DOWN_PAYLOAD,
        )
        assert len(refs) == 1
        assert PEER_X in refs[0].reference

    def test_tool_error_becomes_unavailable_evidence(self) -> None:
        from app.agents.troubleshooting.agent import _evidence_from_tool_output

        refs = _evidence_from_tool_output(
            tool_name="read_live_bgp_peers",
            device_id=DEVICE_Y,
            target=None,
            raw=json.dumps({"device_id": DEVICE_Y, "error": "device not found"}),
        )
        assert len(refs) == 1
        assert refs[0].kind == "bgp_peer_unavailable"
        assert "not found" in (refs[0].description or "")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestTroubleshootingRegistration:
    def test_package_singleton_type(self) -> None:
        assert isinstance(troubleshooting_agent, _AgentImpl)

    def test_package_registry_contains_agent(self) -> None:
        assert "troubleshooting" in registry

    def test_register_fresh_instance(self) -> None:
        fresh = AgentRegistry()
        fresh.register(_make_agent())
        assert "troubleshooting" in fresh

    def test_double_register_conflicts(self) -> None:
        from app.core.errors import ConflictError

        fresh = AgentRegistry()
        fresh.register(_make_agent())
        try:
            fresh.register(_make_agent())
            raise AssertionError("expected ConflictError")
        except ConflictError:
            pass

    def test_classification_schema_round_trips(self) -> None:
        c = SymptomClassification(domain=AnalysisDomain.BGP, device_id=DEVICE_Y, target=PEER_X)
        assert c.domain.value == "bgp"
