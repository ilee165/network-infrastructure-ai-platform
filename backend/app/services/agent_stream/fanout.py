"""Redis pub/sub fan-out for the stateless agent-session WebSocket stream (W2-T2).

ADR-0044 §2/§5: session content is fanned out over a Redis pub/sub channel keyed
by the opaque session id, so **any ``api`` replica can serve any session**. The
producer (the LangGraph run, ADR-0003) publishes ordered frames to the channel;
every replica currently serving a WebSocket for that session subscribes to the
channel and relays each frame to its peer. No replica holds session affinity.

Delivery semantics (ADR-0044 §5) — **best-effort live, at-most-once on the wire**:
Redis pub/sub does not persist or redeliver, so a frame published while no
subscriber is attached (a handoff, a replica restart, a brief Sentinel failover)
is simply not delivered live. That is the right trade for an interactive token
stream; **Postgres is the durable replay source** — a reconnecting client re-reads
the persisted trace to backfill anything missed on the wire (the existing
DB-backed read path), then resumes the live stream. We never silently buffer chat
tokens unboundedly nor drop a delivered frame.

Two implementations behind one :class:`AgentStreamFanout` protocol:

- :class:`RedisAgentStreamFanout` — production. Built over a **Sentinel-aware**
  ``redis.asyncio`` client (``from_url(settings.redis_url)`` — W1-T4 wires the URL
  at the Sentinel service, so there is no static host pin here). ``publish`` is one
  ``PUBLISH``; ``subscribe`` opens a ``PubSub`` scoped to the single served session
  channel (subscribe-on-accept / unsubscribe-on-disconnect, ADR-0044 §2) so a
  replica never sees content for sessions it is not serving.
- :class:`InMemoryAgentStreamFanout` — the unit-suite fan-out. It models a
  **shared bus across replicas**: two instances constructed over the same
  :class:`_InMemoryBus` ("replica A" and "replica B") deliver each other's
  published frames, which is exactly what proves any-replica-serves-any-session
  without a live Redis. The real Redis call shape is pinned by a contract test
  (``test_agent_stream_fanout`` asserts ``publish`` / ``pubsub().subscribe`` /
  ``get_message``), so the production path is not vacuously covered.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING, Protocol

from app.services.agent_stream.frame import AgentStreamFrame, channel_for

if TYPE_CHECKING:
    from redis.asyncio import Redis

#: An open subscription: an async context manager yielding a frame iterator scoped
#: to one session's channel. ``@asynccontextmanager``-decorated ``subscribe``
#: implementations produce exactly this type.
StreamSubscription = AbstractAsyncContextManager[AsyncIterator[AgentStreamFrame]]


class AgentStreamFanout(Protocol):
    """Publish/subscribe seam for per-session fan-out (Redis in prod; in-memory tests)."""

    async def publish(self, frame: AgentStreamFrame) -> None:
        """Publish *frame* to its session's channel (best-effort, at-most-once)."""
        ...

    def subscribe(self, session_id: str) -> StreamSubscription:
        """Open a subscription scoped to *session_id*'s channel (async context manager)."""
        ...


# --------------------------------------------------------------------------- #
# Production: Redis pub/sub, Sentinel-aware client (no static host pin).
# --------------------------------------------------------------------------- #
class RedisAgentStreamFanout:
    """Redis pub/sub fan-out over a Sentinel-aware ``redis.asyncio`` client (ADR-0044).

    The client is injected (``from_url(settings.redis_url)`` at the composition
    root) so this class never pins a host: W1-T4 points ``redis_url`` at the
    Sentinel-fronted service, so an ``api`` replica re-points to the promoted
    primary without a code change.
    """

    #: How long ``get_message`` blocks for the next frame before yielding control
    #: back to the relay loop so it can observe a cancelled/closed WebSocket.
    _POLL_TIMEOUT_SECONDS = 0.5
    #: Maximum time to wait for Redis to confirm the SUBSCRIBE command.  The
    #: context must not yield before this acknowledgement: publishing through a
    #: different connection sooner can race registration and lose the first frame.
    _SUBSCRIBE_ACK_TIMEOUT_SECONDS = 5.0

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def publish(self, frame: AgentStreamFrame) -> None:
        """One ``PUBLISH`` of the serialized frame onto the session's channel.

        Best-effort by design (ADR-0044 §5): ``PUBLISH`` returns the number of
        subscribers that received it; zero subscribers (a handoff) is not an error
        — Postgres is the durable replay source. The frame is serialized via
        :meth:`AgentStreamFrame.to_payload`, which refuses any credential-shaped
        key, so a token can never reach the bus.
        """
        await self._redis.publish(channel_for(frame.session_id), frame.to_payload())

    @asynccontextmanager
    async def subscribe(self, session_id: str) -> AsyncIterator[AsyncIterator[AgentStreamFrame]]:
        """Open a ``PubSub`` scoped to this session only and yield a frame iterator.

        Subscribe-on-accept / unsubscribe-on-disconnect (ADR-0044 §2): the
        subscription is bound to exactly one channel — the served session — so the
        replica never receives content for sessions it is not serving. The channel
        is unsubscribed and the ``PubSub`` closed on exit even if the WebSocket
        relay raises or is cancelled.
        """
        channel = channel_for(session_id)
        pubsub = self._redis.pubsub()
        subscribe_sent = False

        try:
            await pubsub.subscribe(channel)
            subscribe_sent = True
            try:
                acknowledgement = await asyncio.wait_for(
                    pubsub.get_message(
                        ignore_subscribe_messages=False,
                        timeout=self._SUBSCRIBE_ACK_TIMEOUT_SECONDS,
                    ),
                    timeout=self._SUBSCRIBE_ACK_TIMEOUT_SECONDS,
                )
            except TimeoutError as exc:
                raise RuntimeError("Redis subscription acknowledgement timed out") from exc

            acknowledged_channel = (
                None if acknowledgement is None else acknowledgement.get("channel")
            )
            if isinstance(acknowledged_channel, bytes):
                acknowledged_channel = acknowledged_channel.decode("utf-8")
            if (
                acknowledgement is None
                or acknowledgement.get("type") != "subscribe"
                or acknowledged_channel != channel
            ):
                raise RuntimeError("Redis subscription acknowledgement was not received")

            async def _frames() -> AsyncIterator[AgentStreamFrame]:
                while True:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=self._POLL_TIMEOUT_SECONDS
                    )
                    if message is None:
                        # Timeout with no frame: yield control (lets the relay loop
                        # check for a closed socket) and poll again.
                        await asyncio.sleep(0)
                        continue
                    if message.get("type") != "message":
                        continue
                    yield AgentStreamFrame.from_payload(message["data"])

            yield _frames()
        finally:
            try:
                if subscribe_sent:
                    await pubsub.unsubscribe(channel)
            finally:
                await pubsub.aclose()


# --------------------------------------------------------------------------- #
# Tests / single-process fallback: a shared in-memory bus across "replicas".
# --------------------------------------------------------------------------- #
class _InMemoryBus:
    """A process-local pub/sub bus shared by several :class:`InMemoryAgentStreamFanout`.

    Models the shared Redis: every subscriber on a channel — whichever "replica"
    instance opened it — receives every frame published to that channel. This is
    what lets a two-instance test prove any-replica-serves-any-session.
    """

    def __init__(self) -> None:
        #: channel -> set of subscriber queues currently attached.
        self._subscribers: dict[str, set[asyncio.Queue[AgentStreamFrame]]] = defaultdict(set)

    async def publish(self, channel: str, frame: AgentStreamFrame) -> None:
        # At-most-once: a frame with no attached subscriber is simply not delivered
        # (ADR-0044 §5), matching Redis pub/sub. Snapshot to avoid mutation during
        # iteration if a subscriber detaches concurrently.
        for queue in list(self._subscribers.get(channel, ())):
            queue.put_nowait(frame)

    def attach(self, channel: str) -> asyncio.Queue[AgentStreamFrame]:
        queue: asyncio.Queue[AgentStreamFrame] = asyncio.Queue()
        self._subscribers[channel].add(queue)
        return queue

    def detach(self, channel: str, queue: asyncio.Queue[AgentStreamFrame]) -> None:
        subs = self._subscribers.get(channel)
        if subs is not None:
            subs.discard(queue)


class InMemoryAgentStreamFanout:
    """In-memory fan-out over a shared :class:`_InMemoryBus` (tests + single process).

    Two instances built over the *same* bus behave like two ``api`` replicas on the
    same Redis: a frame published through instance A is delivered to a subscriber
    on instance B. Constructed with no bus, it makes its own (single-process
    fallback). It honours the same best-effort, at-most-once semantics as the Redis
    implementation, so the delivery-semantics behaviour the unit suite asserts is
    the real one.
    """

    def __init__(self, bus: _InMemoryBus | None = None) -> None:
        self._bus = bus if bus is not None else _InMemoryBus()

    @property
    def bus(self) -> _InMemoryBus:
        return self._bus

    async def publish(self, frame: AgentStreamFrame) -> None:
        # Serialize + re-parse through the wire contract so the same
        # credential-key refusal and JSON round-trip the Redis path enforces is
        # exercised in tests (no token can ride even the in-memory bus).
        wire = frame.to_payload()
        await self._bus.publish(channel_for(frame.session_id), AgentStreamFrame.from_payload(wire))

    @asynccontextmanager
    async def subscribe(self, session_id: str) -> AsyncIterator[AsyncIterator[AgentStreamFrame]]:
        channel = channel_for(session_id)
        queue = self._bus.attach(channel)

        async def _frames() -> AsyncIterator[AgentStreamFrame]:
            while True:
                yield await queue.get()

        try:
            yield _frames()
        finally:
            self._bus.detach(channel, queue)
