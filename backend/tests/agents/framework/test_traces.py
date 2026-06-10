"""Tests for reasoning-trace models and recorders (app/agents/framework/traces.py)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.agents.framework.traces import (
    EvidenceRef,
    InMemoryTraceRecorder,
    ReasoningTrace,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
)
from app.core.errors import NotFoundError


def _step(kind: TraceStepKind = TraceStepKind.PLAN, summary: str = "a step") -> TraceStep:
    return TraceStep(kind=kind, summary=summary)


class TestModels:
    def test_tool_call_step_requires_tool_name(self) -> None:
        with pytest.raises(ValidationError):
            TraceStep(kind=TraceStepKind.TOOL_CALL, summary="called something")

    def test_tool_call_step_accepts_tool_name_and_evidence(self) -> None:
        step = TraceStep(
            kind=TraceStepKind.TOOL_CALL,
            summary="queried interface inventory",
            tool_name="get_interfaces",
            evidence=[EvidenceRef(kind="raw_artifact", reference="artifact-42")],
        )
        assert step.tool_name == "get_interfaces"
        assert step.evidence[0].reference == "artifact-42"

    def test_new_trace_is_incomplete_with_unique_id(self) -> None:
        first = ReasoningTrace(agent_name="troubleshooting")
        second = ReasoningTrace(agent_name="troubleshooting")
        assert first.is_complete is False
        assert first.trace_id != second.trace_id
        assert first.steps == []

    def test_step_kind_values_are_wire_stable(self) -> None:
        assert [k.value for k in TraceStepKind] == [
            "plan",
            "tool_call",
            "observation",
            "conclusion",
        ]


class TestInMemoryTraceRecorder:
    async def test_start_creates_trace_for_agent(self) -> None:
        recorder = InMemoryTraceRecorder()
        trace = await recorder.start("discovery")
        assert trace.agent_name == "discovery"
        assert recorder.get(trace.trace_id) is trace

    async def test_record_step_appends_in_order(self) -> None:
        recorder = InMemoryTraceRecorder()
        trace = await recorder.start("discovery")
        await recorder.record_step(trace.trace_id, _step(TraceStepKind.PLAN, "first"))
        updated = await recorder.record_step(
            trace.trace_id, _step(TraceStepKind.CONCLUSION, "second")
        )
        assert [s.summary for s in updated.steps] == ["first", "second"]

    async def test_complete_stamps_completed_at_once(self) -> None:
        recorder = InMemoryTraceRecorder()
        trace = await recorder.start("discovery")
        completed = await recorder.complete(trace.trace_id)
        assert completed.is_complete is True
        first_stamp = completed.completed_at
        again = await recorder.complete(trace.trace_id)
        assert again.completed_at == first_stamp

    async def test_unknown_trace_id_raises_not_found(self) -> None:
        recorder = InMemoryTraceRecorder()
        with pytest.raises(NotFoundError):
            recorder.get("missing")
        with pytest.raises(NotFoundError):
            await recorder.record_step("missing", _step())
        with pytest.raises(NotFoundError):
            await recorder.complete("missing")

    async def test_list_traces_returns_all_in_insertion_order(self) -> None:
        recorder = InMemoryTraceRecorder()
        first = await recorder.start("discovery")
        second = await recorder.start("troubleshooting")
        assert [t.trace_id for t in recorder.list_traces()] == [
            first.trace_id,
            second.trace_id,
        ]

    def test_recorder_satisfies_the_protocol(self) -> None:
        assert isinstance(InMemoryTraceRecorder(), TraceRecorder)
