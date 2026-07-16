"""W2-T2 — stateless agent-session fan-out over Redis pub/sub (ADR-0044).

These prove the ADR-0044 §2/§3/§4/§5 contract at the fan-out layer:

- **Any-replica-serves-any-session** — a frame published through "replica A" is
  received by a subscriber on "replica B" over the shared bus (cross-replica sim).
- **Token never on a shared channel** — the serialized payload never contains a
  token/JWT/secret; a frame that tries to carry a credential key is *refused* at
  the serialization boundary (the secret-surface bite, with a negative control).
- **Trace continuity** — the trace/audit-join id rides every fanned-out frame.
- **Delivery semantics** — best-effort, at-most-once: a frame published with no
  subscriber attached is not delivered (ADR-0044 §5), never silently buffered.
- **Redis call-shape contract** — the production :class:`RedisAgentStreamFanout`
  uses the exact ``redis.asyncio`` SDK surface (``publish`` / ``pubsub().subscribe``
  / ``get_message``) so the real path is not vacuously covered by the fake.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from app.services.agent_stream import (
    AgentStreamFrame,
    FramePayloadError,
    InMemoryAgentStreamFanout,
    RedisAgentStreamFanout,
    channel_for,
)
from app.services.agent_stream.fanout import _InMemoryBus

SESSION_ID = "11111111-1111-1111-1111-111111111111"
TRACE_ID = "deadbeefdeadbeefdeadbeefdeadbeef"
SECRET_TOKEN = "super-secret-jwt.header.payload.signature"


def _step_frame(summary: str = "routing decision") -> AgentStreamFrame:
    return AgentStreamFrame(
        session_id=SESSION_ID,
        trace_id=TRACE_ID,
        data={"kind": "plan", "summary": summary, "occurred_at": "2026-06-30T00:00:00Z"},
    )


async def _first_frame(sub: Any, *, timeout: float = 1.0) -> AgentStreamFrame:
    """Pull exactly one frame from an open subscription iterator under a timeout."""
    return await asyncio.wait_for(sub.__anext__(), timeout=timeout)


class TestCrossReplicaDelivery:
    async def test_session_opened_on_replica_a_is_served_from_replica_b(self) -> None:
        """A frame published on replica A reaches a subscriber on replica B (no affinity)."""
        bus = _InMemoryBus()
        replica_a = InMemoryAgentStreamFanout(bus)
        replica_b = InMemoryAgentStreamFanout(bus)

        async with replica_b.subscribe(SESSION_ID) as frames_on_b:
            await asyncio.sleep(0)  # let B attach to the channel
            await replica_a.publish(_step_frame("from A"))
            received = await _first_frame(frames_on_b)

        assert received.session_id == SESSION_ID
        assert received.data["summary"] == "from A"

    async def test_distinct_instances_are_not_in_process_affine(self) -> None:
        """The producer and consumer are different fan-out instances (different replicas)."""
        bus = _InMemoryBus()
        producer = InMemoryAgentStreamFanout(bus)
        consumer = InMemoryAgentStreamFanout(bus)
        assert producer is not consumer

        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            await producer.publish(_step_frame("cross"))
            got = await _first_frame(frames)
        assert got.data["summary"] == "cross"

    async def test_negative_control_isolated_bus_does_not_cross_deliver(self) -> None:
        """A subscriber on a *different* bus must NOT receive the frame (proves the test bites).

        If cross-replica delivery were faked by a process-global rather than the
        shared bus, this would wrongly receive the frame.
        """
        producer = InMemoryAgentStreamFanout(_InMemoryBus())
        consumer = InMemoryAgentStreamFanout(_InMemoryBus())  # separate bus

        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            await producer.publish(_step_frame("should not arrive"))
            with pytest.raises(asyncio.TimeoutError):
                await _first_frame(frames, timeout=0.2)

    async def test_subscription_is_scoped_to_its_own_session(self) -> None:
        """A replica subscribed to session X does not receive session Y's frames."""
        bus = _InMemoryBus()
        producer = InMemoryAgentStreamFanout(bus)
        consumer = InMemoryAgentStreamFanout(bus)
        other_session = "22222222-2222-2222-2222-222222222222"

        async with consumer.subscribe(other_session) as frames:
            await asyncio.sleep(0)
            await producer.publish(_step_frame("for session X"))  # SESSION_ID, not other
            with pytest.raises(asyncio.TimeoutError):
                await _first_frame(frames, timeout=0.2)


class TestTokenNeverOnChannel:
    def test_serialized_payload_never_contains_the_token(self) -> None:
        """The bearer token is absent from every published payload (the secret-surface bite)."""
        frame = _step_frame()
        payload = frame.to_payload()
        assert SECRET_TOKEN not in payload
        # And no credential-shaped key is present anywhere in the envelope.
        envelope = json.loads(payload)
        assert set(envelope) == {"session_id", "trace_id", "data"}
        for forbidden in ("token", "jwt", "authorization", "bearer", "ticket", "password"):
            assert forbidden not in payload.lower()

    def test_frame_carrying_a_token_field_is_refused(self) -> None:
        """A frame whose data smuggles a credential key fails closed (negative control).

        This is the bite: if the refusal regressed, a token would reach the bus and
        this test would go red.
        """
        leaky = AgentStreamFrame(
            session_id=SESSION_ID,
            trace_id=TRACE_ID,
            data={"kind": "plan", "summary": "hi", "token": SECRET_TOKEN},
        )
        with pytest.raises(FramePayloadError):
            leaky.to_payload()

    def test_nested_credential_key_is_refused(self) -> None:
        """A credential key nested deep inside data is still refused."""
        leaky = AgentStreamFrame(
            session_id=SESSION_ID,
            trace_id=TRACE_ID,
            data={"kind": "plan", "evidence": [{"authorization": "Bearer x"}]},
        )
        with pytest.raises(FramePayloadError):
            leaky.to_payload()

    async def test_token_never_appears_on_the_in_memory_bus(self) -> None:
        """End-to-end: nothing published over the fan-out carries the token."""
        bus = _InMemoryBus()
        producer = InMemoryAgentStreamFanout(bus)
        consumer = InMemoryAgentStreamFanout(bus)

        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            await producer.publish(_step_frame())
            received = await _first_frame(frames)

        # The roundtripped frame and its re-serialization carry no credential.
        assert SECRET_TOKEN not in received.to_payload()


class TestTraceContinuity:
    async def test_trace_id_rides_the_fanout(self) -> None:
        """The trace/audit-join id propagates through publish -> subscribe (G-OBS)."""
        bus = _InMemoryBus()
        producer = InMemoryAgentStreamFanout(bus)
        consumer = InMemoryAgentStreamFanout(bus)

        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            await producer.publish(_step_frame())
            received = await _first_frame(frames)

        assert received.trace_id == TRACE_ID, "trace/audit-join id must survive the fan-out"


class TestDeliverySemantics:
    async def test_frame_with_no_subscriber_is_not_delivered(self) -> None:
        """At-most-once: a frame published before anyone subscribes is dropped, not buffered.

        ADR-0044 §5 — Postgres is the durable replay source; a late subscriber does
        NOT receive a frame that was published while it was detached.
        """
        bus = _InMemoryBus()
        producer = InMemoryAgentStreamFanout(bus)
        consumer = InMemoryAgentStreamFanout(bus)

        await producer.publish(_step_frame("missed"))  # nobody attached yet
        async with consumer.subscribe(SESSION_ID) as frames:
            await asyncio.sleep(0)
            with pytest.raises(asyncio.TimeoutError):
                await _first_frame(frames, timeout=0.2)


# --------------------------------------------------------------------------- #
# Redis SDK call-shape contract: pin the exact production calls so the fake does
# not hide a broken Redis path (no vacuous coverage). A minimal fake redis records
# the calls RedisAgentStreamFanout makes.
# --------------------------------------------------------------------------- #
class _FakePubSub:
    def __init__(self) -> None:
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []
        self.closed = False
        self.get_message_calls: list[dict[str, Any]] = []
        self._messages: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def subscribe(self, channel: str) -> None:
        self.subscribed.append(channel)
        self._messages.put_nowait(
            {"type": "subscribe", "channel": channel.encode(), "data": len(self.subscribed)}
        )

    async def unsubscribe(self, channel: str) -> None:
        self.unsubscribed.append(channel)

    async def aclose(self) -> None:
        self.closed = True

    def feed(self, channel: str, payload: str) -> None:
        self._messages.put_nowait({"type": "message", "channel": channel, "data": payload.encode()})

    async def get_message(
        self, *, ignore_subscribe_messages: bool, timeout: float
    ) -> dict[str, Any] | None:
        self.get_message_calls.append(
            {"ignore_subscribe_messages": ignore_subscribe_messages, "timeout": timeout}
        )
        try:
            return self._messages.get_nowait()
        except asyncio.QueueEmpty:
            return None


class _FakeRedis:
    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []
        self._pubsub = _FakePubSub()

    async def publish(self, channel: str, payload: str) -> int:
        self.published.append((channel, payload))
        # Deliver to the (single) pubsub so a subscriber sees it, as Redis would.
        self._pubsub.feed(channel, payload)
        return 1

    def pubsub(self) -> _FakePubSub:
        return self._pubsub


class _ControlledAckPubSub(_FakePubSub):
    """Holds the server's SUBSCRIBE acknowledgement until the test releases it."""

    def __init__(self) -> None:
        super().__init__()
        self.ack_read_started = asyncio.Event()
        self.release_ack = asyncio.Event()
        self.ack_consumed = False

    async def get_message(
        self, *, ignore_subscribe_messages: bool, timeout: float
    ) -> dict[str, Any] | None:
        self.get_message_calls.append(
            {"ignore_subscribe_messages": ignore_subscribe_messages, "timeout": timeout}
        )
        self.ack_read_started.set()
        await self.release_ack.wait()
        self.ack_consumed = True
        return {
            "type": "subscribe",
            "channel": self.subscribed[0].encode(),
            "data": 1,
        }


class TestRedisCallShapeContract:
    async def test_publish_calls_redis_publish_with_channel_and_serialized_frame(self) -> None:
        fake = _FakeRedis()
        fanout = RedisAgentStreamFanout(fake)  # type: ignore[arg-type]

        await fanout.publish(_step_frame("contract"))

        assert len(fake.published) == 1
        channel, payload = fake.published[0]
        assert channel == channel_for(SESSION_ID)  # opaque-session-id keyed channel
        envelope = json.loads(payload)
        assert envelope["trace_id"] == TRACE_ID
        assert envelope["data"]["summary"] == "contract"
        assert SECRET_TOKEN not in payload

    async def test_subscribe_uses_pubsub_subscribe_and_get_message(self) -> None:
        fake = _FakeRedis()
        fanout = RedisAgentStreamFanout(fake)  # type: ignore[arg-type]

        async with fanout.subscribe(SESSION_ID) as frames:
            # The production path opened a PubSub and subscribed to THIS session's channel.
            assert fake._pubsub.subscribed == [channel_for(SESSION_ID)]
            await fanout.publish(_step_frame("via redis"))
            received = await _first_frame(frames)

        assert received.trace_id == TRACE_ID
        assert received.data["summary"] == "via redis"
        # The production poll passes ignore_subscribe_messages=True and a positive
        # timeout; without those the subscribe-confirmation message would stall the
        # iterator on the first read. Pin the exact call shape (F-fanouttest-224).
        assert any(
            c["ignore_subscribe_messages"] is True and c["timeout"] > 0
            for c in fake._pubsub.get_message_calls
        ), "get_message must be called with ignore_subscribe_messages=True and a positive timeout"
        # Subscription cleaned up on exit (unsubscribe + close).
        assert fake._pubsub.unsubscribed == [channel_for(SESSION_ID)]
        assert fake._pubsub.closed is True

    async def test_subscribe_waits_for_server_ack_before_yielding_frames(self) -> None:
        """The context cannot expose its iterator until Redis confirms SUBSCRIBE."""
        fake = _FakeRedis()
        controlled = _ControlledAckPubSub()
        fake._pubsub = controlled
        fanout = RedisAgentStreamFanout(fake)  # type: ignore[arg-type]
        subscription = fanout.subscribe(SESSION_ID)
        enter_task = asyncio.create_task(subscription.__aenter__())

        try:
            await asyncio.sleep(0)
            assert not enter_task.done(), "subscription yielded before Redis acknowledged it"
            await asyncio.wait_for(controlled.ack_read_started.wait(), timeout=0.2)
            assert controlled.ack_consumed is False
            controlled.release_ack.set()
            await asyncio.wait_for(enter_task, timeout=0.2)
            assert controlled.ack_consumed is True
            assert controlled.get_message_calls[0]["ignore_subscribe_messages"] is False
        finally:
            controlled.release_ack.set()
            await asyncio.wait_for(enter_task, timeout=0.2)
            await subscription.__aexit__(None, None, None)

    async def test_subscribe_fails_closed_when_server_ack_never_arrives(self) -> None:
        """A missing SUBSCRIBE acknowledgement times out and closes the PubSub."""
        fake = _FakeRedis()
        controlled = _ControlledAckPubSub()
        fake._pubsub = controlled
        fanout = RedisAgentStreamFanout(fake)  # type: ignore[arg-type]
        fanout._SUBSCRIBE_ACK_TIMEOUT_SECONDS = 0.01

        with pytest.raises(RuntimeError, match="subscription acknowledgement"):
            async with fanout.subscribe(SESSION_ID):
                pass

        assert controlled.unsubscribed == [channel_for(SESSION_ID)]
        assert controlled.closed is True
