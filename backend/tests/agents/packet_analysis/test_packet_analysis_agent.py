"""Tests for the Packet Analysis Agent (M5 task #11, ADR-0023 §1).

Mandatory behaviours (task T11 / M5-PLAN row #11):

1. Read-only contract — every declared tool is READ_ONLY; no STATE_CHANGING or
   DIAGNOSTIC tool is ever declared on this agent. The agent never invokes a
   capture (that is the ``diagnostic`` capture tier, T8) — it reads already
   produced packet-analysis output only.
2. LLM-safe boundary — the agent operates exclusively over the normalized
   :class:`~app.engines.packet.PacketFindings` (top talkers, protocol
   hierarchy, TCP anomaly counts); it never receives raw packet bytes.
3. Summarization — over a fixture analysis result, the agent reports top
   talkers, the protocol breakdown, and errors/retransmissions.
4. Filter-style Q&A — the agent answers questions over the analysis result
   (talkers involving a host, protocol counts, reset/retransmission totals).
5. Findings attach to a troubleshooting session — a run records its findings as
   steps on the injected :class:`TraceRecorder` (the same session/trace model
   M3 uses), so the session owns an inspectable, grounded record.
6. Registration — the package singleton registers cleanly.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import NetOpsTool, ToolClassification
from app.agents.framework.traces import InMemoryTraceRecorder, TraceStepKind
from app.agents.packet_analysis import (
    PacketAnalysisAgent,
    packet_analysis_agent,
    registry,
)
from app.agents.packet_analysis.agent import PacketAnalysisAgent as _AgentImpl
from app.agents.packet_analysis.tools import (
    PACKET_ANALYSIS_TOOLS,
    query_capture,
    summarize_capture,
)
from app.engines.packet import (
    Conversation,
    PacketFindings,
    ProtocolCount,
)
from tests.agents.conftest import scripted_model

HOST_A = "10.0.0.1"
HOST_B = "10.0.0.2"
HOST_C = "10.0.0.3"


def _findings() -> PacketFindings:
    """A representative analysis result: three talkers, mixed protocols, anomalies."""
    return PacketFindings(
        packet_count=180,
        top_talkers=[
            Conversation(src=HOST_A, dst=HOST_B, packets=120, bytes=96000),
            Conversation(src=HOST_C, dst=HOST_B, packets=40, bytes=30000),
            Conversation(src=HOST_A, dst=HOST_C, packets=20, bytes=4000),
        ],
        protocol_hierarchy=[
            ProtocolCount(protocol="tcp", packets=140),
            ProtocolCount(protocol="dns", packets=30),
            ProtocolCount(protocol="icmp", packets=10),
        ],
        tcp_resets=7,
        tcp_retransmissions=12,
    )


def _findings_payload() -> dict[str, Any]:
    return _findings().model_dump(mode="json")


def _make_agent(**kwargs: Any) -> PacketAnalysisAgent:
    return PacketAnalysisAgent(**kwargs)


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestPacketAnalysisIdentity:
    def test_name_is_packet_analysis(self) -> None:
        assert _make_agent().name == "packet_analysis"

    def test_description_non_empty_and_on_topic(self) -> None:
        desc = _make_agent().description.lower()
        assert desc.strip()
        assert "packet" in desc
        assert "talker" in desc or "protocol" in desc

    def test_description_disambiguates_from_siblings(self) -> None:
        desc = _make_agent().description.lower()
        # Packet analysis is read-only over capture output — not generic
        # device troubleshooting and not inventory discovery.
        assert "capture" in desc
        assert "discover" in desc

    def test_system_prompt_non_empty(self) -> None:
        assert _make_agent().system_prompt.strip()

    def test_system_prompt_forbids_raw_bytes(self) -> None:
        prompt = _make_agent().system_prompt.lower()
        # The boundary must be stated: the agent reasons over findings, never
        # raw packet bytes/payloads.
        assert "payload" in prompt or "raw" in prompt

    def test_validate_definition_passes(self) -> None:
        _make_agent().validate_definition()


# ---------------------------------------------------------------------------
# Tool classification — strictly read-only over analysis output
# ---------------------------------------------------------------------------


class TestPacketAnalysisToolClassification:
    _READ_ONLY = {"summarize_capture", "query_capture"}

    def test_declared_tools_are_read_only(self) -> None:
        by_name = {t.name: t for t in _make_agent().tools}
        for name in self._READ_ONLY:
            assert name in by_name, f"missing read-only tool {name}"
            assert by_name[name].classification is ToolClassification.READ_ONLY

    def test_no_state_changing_tool_declared(self) -> None:
        offenders = [
            t.name
            for t in _make_agent().tools
            if t.classification is ToolClassification.STATE_CHANGING
        ]
        assert not offenders, f"STATE_CHANGING tools found: {offenders}"

    def test_no_diagnostic_capture_tool_declared(self) -> None:
        # The agent must NOT be able to launch a capture itself — that is the
        # diagnostic capture tier (T8), not this read-only analysis agent.
        offenders = [
            t.name
            for t in _make_agent().tools
            if t.classification is ToolClassification.DIAGNOSTIC
        ]
        assert not offenders, f"DIAGNOSTIC tools found: {offenders}"

    def test_all_tools_are_netops_tool(self) -> None:
        for tool in _make_agent().tools:
            assert isinstance(tool, NetOpsTool)

    def test_tool_list_exported(self) -> None:
        assert {t.name for t in PACKET_ANALYSIS_TOOLS} == self._READ_ONLY


# ---------------------------------------------------------------------------
# Summarization tool — top talkers, protocols, errors/retransmissions
# ---------------------------------------------------------------------------


class TestSummarizeCaptureTool:
    async def test_summarizes_top_talkers(self) -> None:
        raw = await summarize_capture.ainvoke({"findings": _findings_payload()})
        out = json.loads(raw)
        talkers = out["top_talkers"]
        # Most active conversation first.
        assert talkers[0]["src"] == HOST_A
        assert talkers[0]["dst"] == HOST_B
        assert talkers[0]["packets"] == 120
        # Ordering is preserved (descending by packets).
        assert [t["packets"] for t in talkers] == [120, 40, 20]

    async def test_summarizes_protocol_breakdown(self) -> None:
        raw = await summarize_capture.ainvoke({"findings": _findings_payload()})
        out = json.loads(raw)
        protos = {p["protocol"]: p["packets"] for p in out["protocol_breakdown"]}
        assert protos == {"tcp": 140, "dns": 30, "icmp": 10}

    async def test_summarizes_errors_and_retransmissions(self) -> None:
        raw = await summarize_capture.ainvoke({"findings": _findings_payload()})
        out = json.loads(raw)
        assert out["tcp_resets"] == 7
        assert out["tcp_retransmissions"] == 12
        assert out["packet_count"] == 180

    async def test_respects_top_n_limit(self) -> None:
        raw = await summarize_capture.ainvoke(
            {"findings": _findings_payload(), "top_n": 1}
        )
        out = json.loads(raw)
        assert len(out["top_talkers"]) == 1
        assert out["top_talkers"][0]["src"] == HOST_A

    async def test_empty_findings_summarize_cleanly(self) -> None:
        raw = await summarize_capture.ainvoke(
            {"findings": PacketFindings().model_dump(mode="json")}
        )
        out = json.loads(raw)
        assert out["packet_count"] == 0
        assert out["top_talkers"] == []
        assert out["protocol_breakdown"] == []
        assert out["tcp_resets"] == 0


# ---------------------------------------------------------------------------
# Filter-style Q&A tool — questions over the analysis result
# ---------------------------------------------------------------------------


class TestQueryCaptureTool:
    async def test_filter_talkers_by_host(self) -> None:
        raw = await query_capture.ainvoke(
            {"findings": _findings_payload(), "host": HOST_C}
        )
        out = json.loads(raw)
        talkers = out["top_talkers"]
        # Only conversations that involve HOST_C (as src or dst).
        assert talkers
        for t in talkers:
            assert HOST_C in (t["src"], t["dst"])
        # HOST_A<->HOST_B (no HOST_C) is filtered out.
        assert not any(t["src"] == HOST_A and t["dst"] == HOST_B for t in talkers)

    async def test_filter_by_protocol(self) -> None:
        raw = await query_capture.ainvoke(
            {"findings": _findings_payload(), "protocol": "dns"}
        )
        out = json.loads(raw)
        protos = out["protocol_breakdown"]
        assert protos == [{"protocol": "dns", "packets": 30}]

    async def test_protocol_filter_is_case_insensitive(self) -> None:
        raw = await query_capture.ainvoke(
            {"findings": _findings_payload(), "protocol": "DNS"}
        )
        out = json.loads(raw)
        assert out["protocol_breakdown"] == [{"protocol": "dns", "packets": 30}]

    async def test_anomaly_counts_always_present(self) -> None:
        # Even a host/protocol filtered query reports the capture-wide anomaly
        # totals so the model can answer "were there resets?".
        raw = await query_capture.ainvoke(
            {"findings": _findings_payload(), "host": HOST_A}
        )
        out = json.loads(raw)
        assert out["tcp_resets"] == 7
        assert out["tcp_retransmissions"] == 12

    async def test_no_filter_returns_whole_capture(self) -> None:
        raw = await query_capture.ainvoke({"findings": _findings_payload()})
        out = json.loads(raw)
        assert len(out["top_talkers"]) == 3
        assert len(out["protocol_breakdown"]) == 3

    async def test_unmatched_host_yields_empty_talkers(self) -> None:
        raw = await query_capture.ainvoke(
            {"findings": _findings_payload(), "host": "192.0.2.99"}
        )
        out = json.loads(raw)
        assert out["top_talkers"] == []
        # Anomaly totals still reported.
        assert out["tcp_resets"] == 7


# ---------------------------------------------------------------------------
# Findings attach to a troubleshooting session (M3 trace/session model)
# ---------------------------------------------------------------------------


class TestFindingsAttachToSession:
    async def test_summarize_findings_records_trace_steps(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)

        summary = await agent.summarize_findings(_findings())

        # A grounded summary is returned to the caller.
        assert summary.packet_count == 180
        assert summary.top_talkers[0].src == HOST_A
        assert summary.tcp_resets == 7

        # Exactly one trace was opened and completed (the "session" record).
        traces = recorder.list_traces()
        assert len(traces) == 1
        trace = traces[0]
        assert trace.agent_name == "packet_analysis"
        assert trace.is_complete

    async def test_trace_has_plan_observation_conclusion(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        await agent.summarize_findings(_findings())
        kinds = [s.kind for s in recorder.list_traces()[0].steps]
        assert TraceStepKind.PLAN in kinds
        assert TraceStepKind.OBSERVATION in kinds
        assert TraceStepKind.CONCLUSION in kinds

    async def test_findings_are_cited_as_evidence(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        await agent.summarize_findings(_findings())
        all_evidence = [
            ref for step in recorder.list_traces()[0].steps for ref in step.evidence
        ]
        assert all_evidence, "expected the findings to be cited as evidence on the trace"
        kinds = {ref.kind for ref in all_evidence}
        # Top talkers and the anomaly counts are both grounded as evidence.
        assert "top_talker" in kinds
        assert any(k in kinds for k in ("tcp_anomaly", "protocol"))

    async def test_conclusion_reports_talkers_and_anomalies(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        await agent.summarize_findings(_findings())
        conclusion = next(
            s
            for s in recorder.list_traces()[0].steps
            if s.kind is TraceStepKind.CONCLUSION
        )
        assert HOST_A in conclusion.summary
        # The headline numbers appear in the narrative.
        assert "180" in conclusion.summary
        assert "7" in conclusion.summary  # resets

    async def test_recorder_shared_across_session(self) -> None:
        # The same recorder accumulates multiple captures' findings for one
        # session, so a troubleshooting session owns every attached finding.
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        await agent.summarize_findings(_findings())
        await agent.summarize_findings(_findings())
        assert len(recorder.list_traces()) == 2


# ---------------------------------------------------------------------------
# Bespoke / default graph wiring — the agent compiles and runs offline
# ---------------------------------------------------------------------------


class _RecordingModel:
    """Scripted chat model that retains every message it is asked to generate over."""

    def __init__(self, replies: list[AIMessage]) -> None:
        self._inner = scripted_model(replies)
        self.seen: list[BaseMessage] = []

    def __getattr__(self, item: str):  # pragma: no cover - delegation glue
        return getattr(self._inner, item)

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self

    async def ainvoke(self, messages: Any, *a: Any, **k: Any) -> Any:
        self.seen.extend(messages)
        return await self._inner.ainvoke(messages, *a, **k)


class TestPacketAnalysisGraph:
    async def test_graph_name_matches_agent(self) -> None:
        agent = _make_agent()
        graph = agent.build_graph(scripted_model([AIMessage(content="ok")]))
        assert graph.name == "packet_analysis"

    async def test_graph_runs_a_read_only_turn(self) -> None:
        agent = _make_agent()
        model = _RecordingModel([AIMessage(content="The top talker is 10.0.0.1.")])
        result = await agent.build_graph(model).ainvoke(
            {"messages": [HumanMessage(content="who are the top talkers in this capture?")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        assert "talker" in str(final.content).lower()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestPacketAnalysisRegistration:
    def test_package_singleton_type(self) -> None:
        assert isinstance(packet_analysis_agent, _AgentImpl)

    def test_package_registry_contains_agent(self) -> None:
        assert "packet_analysis" in registry

    def test_register_fresh_instance(self) -> None:
        fresh = AgentRegistry()
        fresh.register(_make_agent())
        assert "packet_analysis" in fresh

    def test_double_register_conflicts(self) -> None:
        from app.core.errors import ConflictError

        fresh = AgentRegistry()
        fresh.register(_make_agent())
        with pytest.raises(ConflictError):
            fresh.register(_make_agent())
