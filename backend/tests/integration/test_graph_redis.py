"""Live Redis proofs for the graph-integration service gate (Wave 7 T2).

The ordinary backend suite keeps using deterministic in-memory/fake Redis
implementations.  These function-scoped integration tests exercise the real
``redis.asyncio`` wire path selected by the graph-integration CI job.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.redis import create_redis_client
from app.services.agent_stream import AgentStreamFrame, RedisAgentStreamFanout
from app.services.rate_limit import RedisRateLimiter


@pytest.fixture()
async def real_redis_client_factory() -> AsyncIterator[Callable[[], Redis]]:
    """Return tracked clients connected through the production construction seam.

    The default unit run has no service and skips immediately.  The dedicated
    graph-integration job sets ``NETOPS_REDIS_URL`` and rejects any selected skip
    from JUnit, so an unavailable CI service is a red gate rather than a silent
    pass.
    """
    if "NETOPS_REDIS_URL" not in os.environ:
        pytest.skip("NETOPS_REDIS_URL is not set; live Redis test is integration-only")

    get_settings.cache_clear()
    settings = get_settings()
    clients: list[Redis] = []

    def make_client() -> Redis:
        client = create_redis_client(settings)
        clients.append(client)
        return client

    probe = make_client()
    try:
        await asyncio.wait_for(probe.ping(), timeout=5)
    except Exception as exc:  # noqa: BLE001 - unreachable service is a local skip
        await probe.aclose()
        pytest.skip(
            "Redis unreachable at NETOPS_REDIS_URL; "
            f"live integration test skipped ({type(exc).__name__})"
        )
    try:
        yield make_client
    finally:
        for client in clients:
            await client.aclose()
        get_settings.cache_clear()


@pytest.mark.integration
@pytest.mark.redis
async def test_real_redis_lua_enforces_limit_and_ttl(
    real_redis_client_factory: Callable[[], Redis],
) -> None:
    """The Wave 5 Lua path atomically increments, expires, and enforces a limit."""
    client = real_redis_client_factory()
    limiter = RedisRateLimiter(client)
    key = f"graph-ci:lua:{uuid4()}"
    redis_key = f"netops:rl:{key}"
    try:
        first = await limiter.hit(key, limit=1, window_secs=30)
        second = await limiter.hit(key, limit=1, window_secs=30)

        assert (first.count, first.allowed) == (1, False)
        assert (second.count, second.allowed) == (2, False)
        assert 0 < second.retry_after_secs <= 30
        assert 0 < await client.ttl(redis_key) <= 30
    finally:
        await limiter.reset(key)


@pytest.mark.integration
@pytest.mark.redis
async def test_real_redis_lua_rearms_counter_without_ttl(
    real_redis_client_factory: Callable[[], Redis],
) -> None:
    """The Lua recovery branch restores expiry on a pre-existing immortal counter."""
    client = real_redis_client_factory()
    limiter = RedisRateLimiter(client)
    key = f"graph-ci:lua-rearm:{uuid4()}"
    redis_key = f"netops:rl:{key}"
    try:
        await client.set(redis_key, 5)
        assert await client.ttl(redis_key) == -1

        result = await limiter.hit(key, limit=10, window_secs=30)

        assert result.count == 6
        assert result.allowed is True
        assert 0 < await client.ttl(redis_key) <= 30
    finally:
        await limiter.reset(key)


@pytest.mark.integration
@pytest.mark.redis
async def test_real_redis_pubsub_relays_between_distinct_clients(
    real_redis_client_factory: Callable[[], Redis],
) -> None:
    """A frame published by one client reaches a subscriber on another client."""
    producer = RedisAgentStreamFanout(real_redis_client_factory())
    consumer = RedisAgentStreamFanout(real_redis_client_factory())
    session_id = str(uuid4())
    frame = AgentStreamFrame(
        session_id=session_id,
        trace_id="feedfacefeedfacefeedfacefeedface",
        data={"kind": "plan", "summary": "real Redis relay"},
    )

    async with consumer.subscribe(session_id) as frames:
        await producer.publish(frame)
        received = await asyncio.wait_for(frames.__anext__(), timeout=5)

    assert received.session_id == frame.session_id
    assert received.trace_id == frame.trace_id
    assert received.data == frame.data
