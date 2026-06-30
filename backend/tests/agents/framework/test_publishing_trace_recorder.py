"""W2-T2 fix — the trace recorder is the production producer for the fan-out.

ADR-0044 §2/§6: a session running on any ``api`` replica must fan its live
reasoning frames onto the per-session Redis pub/sub channel as it records them,
so a peer subscribing on another replica is served the live stream (not only the
DB-replayed steps). :class:`PublishingTraceRecorder` is that producer: it wraps
any :class:`TraceRecorder`, persists the step through the inner recorder (Postgres
stays the durable source), then publishes an :class:`AgentStreamFrame` carrying
the step read-model + the trace/audit-join id onto the session channel.

These prove the producer half end-to-end at the recorder layer:

- A recorded step is published as a frame on the session's channel, received by a
  *separate* fan-out instance (a second replica) — the criterion the cross-replica
  test previously faked with a test-only ``replica_a.publish(...)``.
- The published frame's ``data`` is the step read-model and carries the trace id.
- The bearer token / any credential never rides the produced frame.
- A publish failure never breaks persistence (Postgres is the durable record).
"""

from __future__ import annotations

import asyncio

from app.agents.framework.traces import (
    InMemoryTraceRecorder,
    PublishingTraceRecorder,
    TraceStep,
    TraceStepKind,
)
from app.services.agent_stream import (
    AgentStreamFrame,
    InMemoryAgentStreamFanout,
)
from app.services.agent_stream.fanout import _InMemoryBus

SESSION_ID = "11111111-1111-1111-1111-111111111111"


def _plan_step(summary: str = "routing decision") -> TraceStep:
    return TraceStep(kind=TraceStepKind.PLAN, summary=summary, detail="picked discovery")


async def _first_frame(sub: object, *, timeout: float = 1.0) -> AgentStreamFrame:
    return await asyncio.wait_for(sub.__anext__(), timeout=timeout)  # type: ignore[attr-defined]


class _ExplodingFanout:
    """A fan-out whose publish always raises (to prove publish never breaks record)."""

    async def publish(self, frame: AgentStreamFrame) -> None:
        raise RuntimeError("redis is down")

    def subscribe(self, session_id: str):  # pragma: no cover - unused in these tests
        raise NotImplementedError


class TestProducerFansLiveFramesCrossReplica:
    async def test_recorded_step_is_published_to_a_second_replica(self) -> None:
        """record_step on replica A fans a live frame to a subscriber on replica B.

        This is the production producer path — no test-only ``replica_a.publish``.
        The recorder IS the producer; a peer on a different fan-out instance over
        the same bus receives the frame (any-replica-serves-any-session).
        """
        bus = _InMemoryBus()
        producer_fanout = InMemoryAgentStreamFanout(bus)  # replica A
        consumer_fanout = InMemoryAgentStreamFanout(bus)  # replica B

        inner = InMemoryTraceRecorder()
        recorder = PublishingTraceRecorder(inner, fanout=producer_fanout, session_id=SESSION_ID)
        trace = await recorder.start("discovery")

        async with consumer_fanout.subscribe(SESSION_ID) as frames_on_b:
            await asyncio.sleep(0)  # let B attach to the channel
            await recorder.record_step(trace.trace_id, _plan_step("from the run"))
            received = await _first_frame(frames_on_b)

        assert received.session_id == SESSION_ID
        # The trace/audit-join id rides the produced frame (G-OBS).
        assert received.trace_id == trace.trace_id
        # The frame data is the step read-model, identical to a DB-replayed step.
        assert received.data["kind"] == "plan"
        assert received.data["summary"] == "from the run"
        assert received.data["detail"] == "picked discovery"
        assert "occurred_at" in received.data

    async def test_inner_recorder_still_persists_the_step(self) -> None:
        """The wrapper delegates persistence; the inner trace gains the step."""
        inner = InMemoryTraceRecorder()
        recorder = PublishingTraceRecorder(
            inner, fanout=InMemoryAgentStreamFanout(), session_id=SESSION_ID
        )
        trace = await recorder.start("discovery")
        await recorder.record_step(trace.trace_id, _plan_step())
        assert len(inner.get(trace.trace_id).steps) == 1

    async def test_no_credential_rides_the_produced_frame(self) -> None:
        """The produced frame's read-model carries no credential-shaped key."""
        bus = _InMemoryBus()
        recorder = PublishingTraceRecorder(
            InMemoryTraceRecorder(),
            fanout=InMemoryAgentStreamFanout(bus),
            session_id=SESSION_ID,
        )
        trace = await recorder.start("discovery")
        consumer = InMemoryAgentStreamFanout(bus)
        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            await recorder.record_step(trace.trace_id, _plan_step())
            received = await _first_frame(frames)
        payload = received.to_payload().lower()
        for forbidden in ("token", "jwt", "authorization", "bearer", "password", "secret"):
            assert forbidden not in payload

    async def test_publish_failure_does_not_break_persistence(self) -> None:
        """A live-publish failure is swallowed — Postgres remains the durable record."""
        inner = InMemoryTraceRecorder()
        recorder = PublishingTraceRecorder(inner, fanout=_ExplodingFanout(), session_id=SESSION_ID)
        trace = await recorder.start("discovery")
        # Must NOT raise even though the fan-out publish blows up.
        result = await recorder.record_step(trace.trace_id, _plan_step())
        assert len(result.steps) == 1
        assert len(inner.get(trace.trace_id).steps) == 1

    async def test_complete_delegates_to_inner(self) -> None:
        """complete() delegates to the inner recorder (terminal frame is WS-synthesized)."""
        inner = InMemoryTraceRecorder()
        recorder = PublishingTraceRecorder(
            inner, fanout=InMemoryAgentStreamFanout(), session_id=SESSION_ID
        )
        trace = await recorder.start("discovery")
        completed = await recorder.complete(trace.trace_id)
        assert completed.is_complete is True
        assert inner.get(trace.trace_id).is_complete is True

    def test_is_a_trace_recorder(self) -> None:
        """The wrapper satisfies the TraceRecorder protocol (drop-in)."""
        from app.agents.framework.traces import TraceRecorder

        recorder = PublishingTraceRecorder(
            InMemoryTraceRecorder(),
            fanout=InMemoryAgentStreamFanout(),
            session_id=SESSION_ID,
        )
        assert isinstance(recorder, TraceRecorder)

    async def test_publishes_one_frame_per_recorded_step(self) -> None:
        """Each recorded step produces exactly one frame, in order."""
        bus = _InMemoryBus()
        recorder = PublishingTraceRecorder(
            InMemoryTraceRecorder(),
            fanout=InMemoryAgentStreamFanout(bus),
            session_id=SESSION_ID,
        )
        trace = await recorder.start("discovery")
        consumer = InMemoryAgentStreamFanout(bus)
        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            await recorder.record_step(trace.trace_id, _plan_step("one"))
            await recorder.record_step(trace.trace_id, _plan_step("two"))
            first = await _first_frame(frames)
            second = await _first_frame(frames)
        assert first.data["summary"] == "one"
        assert second.data["summary"] == "two"
