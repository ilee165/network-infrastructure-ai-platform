"""Unit tests for the rate-limit counter primitive (W6-T6).

The in-memory limiter must honour the same fixed-window semantics the Redis one
does (so the suite exercises real over-limit / rollover behaviour without a
broker), and the Redis limiter must wrap every backend error in the typed
:class:`RateLimitBackendError` — never leaking the raw SDK exception or a DSN.
"""

from __future__ import annotations

import pytest

from app.services.rate_limit import (
    InMemoryRateLimiter,
    RateLimitBackendError,
    RedisRateLimiter,
    api_principal_key,
    api_token_key,
    login_lockout_key,
    login_lockout_state_key,
    login_source_key,
    login_source_lock_key,
    oidc_callback_key,
)
from app.services.rate_limit.limiter import _Clock


class _FakeClock:
    """Manually advanced monotonic clock for deterministic window tests."""

    def __init__(self) -> None:
        self._t = 1000.0

    def now(self) -> float:
        return self._t

    def advance(self, secs: float) -> None:
        self._t += secs


def test_fake_clock_satisfies_clock_protocol() -> None:
    """``_Clock`` is a Protocol; assert the fake satisfies it (mypy + runtime)."""
    clock: _Clock = _FakeClock()
    assert clock.now() == 1000.0


async def test_in_memory_allows_up_to_limit_then_blocks() -> None:
    limiter = InMemoryRateLimiter()
    results = [await limiter.hit("k", limit=3, window_secs=60) for _ in range(4)]

    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[-1].count == 4
    # Over-limit hit reports a coarse, window-bounded Retry-After.
    assert 0 < results[-1].retry_after_secs <= 60
    # Allowed hits carry no Retry-After.
    assert all(r.retry_after_secs == 0 for r in results[:3])


async def test_in_memory_window_rolls_over() -> None:
    clock = _FakeClock()
    limiter = InMemoryRateLimiter(clock=clock)

    assert (await limiter.hit("k", limit=1, window_secs=60)).allowed is True
    assert (await limiter.hit("k", limit=1, window_secs=60)).allowed is False

    clock.advance(61)
    # Fresh window: the budget resets.
    assert (await limiter.hit("k", limit=1, window_secs=60)).allowed is True


async def test_in_memory_peek_does_not_increment() -> None:
    limiter = InMemoryRateLimiter()
    await limiter.hit("k", limit=5, window_secs=60)
    await limiter.hit("k", limit=5, window_secs=60)

    assert await limiter.peek("k") == 2
    assert await limiter.peek("k") == 2  # idempotent read
    assert await limiter.peek("absent") == 0


async def test_in_memory_peek_expires_with_window() -> None:
    clock = _FakeClock()
    limiter = InMemoryRateLimiter(clock=clock)
    await limiter.hit("k", limit=5, window_secs=30)
    assert await limiter.peek("k") == 1
    clock.advance(31)
    assert await limiter.peek("k") == 0


async def test_in_memory_reset_clears_counter() -> None:
    limiter = InMemoryRateLimiter()
    await limiter.hit("k", limit=1, window_secs=60)
    await limiter.reset("k")
    assert await limiter.peek("k") == 0
    assert (await limiter.hit("k", limit=1, window_secs=60)).allowed is True


# ---------------------------------------------------------------------------
# Redis limiter: O(1) op shape + typed-error wrapping (no SDK/DSN leak)
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Minimal async stand-in for ``redis.asyncio.Redis`` (INCR/EXPIRE/TTL/GET)."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.ttls: dict[str, int] = {}
        self.expire_calls = 0
        self.incr_calls = 0

    async def incr(self, key: str) -> int:
        self.incr_calls += 1
        self.store[key] = self.store.get(key, 0) + 1
        return self.store[key]

    async def expire(self, key: str, secs: int) -> bool:
        self.expire_calls += 1
        self.ttls[key] = secs
        return True

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)

    async def get(self, key: str) -> str | None:
        return str(self.store[key]) if key in self.store else None

    async def delete(self, key: str) -> int:
        self.store.pop(key, None)
        self.ttls.pop(key, None)
        return 1


class _BrokenRedis:
    """Every op raises — simulates a Redis outage with a credentialed message."""

    _LEAK = "redis://user:s3cr3t@redis:6379/0 connection refused"

    async def incr(self, key: str) -> int:
        raise ConnectionError(self._LEAK)

    async def expire(self, key: str, secs: int) -> bool:
        raise ConnectionError(self._LEAK)

    async def ttl(self, key: str) -> int:
        raise ConnectionError(self._LEAK)

    async def get(self, key: str) -> str | None:
        raise ConnectionError(self._LEAK)

    async def delete(self, key: str) -> int:
        raise ConnectionError(self._LEAK)


async def test_redis_limiter_sets_ttl_once_per_window() -> None:
    redis = _FakeRedis()
    limiter = RedisRateLimiter(redis)  # type: ignore[arg-type]

    for _ in range(3):
        await limiter.hit("k", limit=10, window_secs=60)

    # O(1): one INCR per hit, EXPIRE only on the first hit of the window.
    assert redis.incr_calls == 3
    assert redis.expire_calls == 1


async def test_redis_limiter_blocks_over_limit_with_retry_after() -> None:
    redis = _FakeRedis()
    limiter = RedisRateLimiter(redis)  # type: ignore[arg-type]

    first = await limiter.hit("k", limit=1, window_secs=45)
    second = await limiter.hit("k", limit=1, window_secs=45)

    assert first.allowed is True
    assert second.allowed is False
    assert second.retry_after_secs == 45


async def test_redis_limiter_wraps_backend_error_without_leaking_dsn() -> None:
    limiter = RedisRateLimiter(_BrokenRedis())  # type: ignore[arg-type]

    with pytest.raises(RateLimitBackendError) as exc_info:
        await limiter.hit("k", limit=1, window_secs=60)

    # The typed error message carries no DSN/credential material.
    message = str(exc_info.value)
    assert "s3cr3t" not in message
    assert "redis://" not in message


async def test_redis_peek_and_reset_wrap_backend_error() -> None:
    limiter = RedisRateLimiter(_BrokenRedis())  # type: ignore[arg-type]
    with pytest.raises(RateLimitBackendError):
        await limiter.peek("k")
    with pytest.raises(RateLimitBackendError):
        await limiter.reset("k")


async def test_redis_peek_returns_current_count() -> None:
    redis = _FakeRedis()
    limiter = RedisRateLimiter(redis)  # type: ignore[arg-type]
    await limiter.hit("k", limit=10, window_secs=60)
    await limiter.hit("k", limit=10, window_secs=60)
    assert await limiter.peek("k") == 2
    assert await limiter.peek("absent") == 0


async def test_redis_peek_non_integer_value_is_zero() -> None:
    """A corrupt/non-integer counter value reads as 0 (never raises)."""

    class _GarbageRedis:
        async def get(self, key: str) -> str | None:
            return "not-a-number"

    limiter = RedisRateLimiter(_GarbageRedis())  # type: ignore[arg-type]
    assert await limiter.peek("k") == 0


async def test_redis_limiter_rearms_missing_ttl() -> None:
    """A counter that lost its TTL (crash between INCR/EXPIRE) is re-armed."""
    redis = _FakeRedis()
    redis.store["netops:rl:k"] = 5  # pre-existing counter, no TTL recorded
    limiter = RedisRateLimiter(redis)  # type: ignore[arg-type]

    await limiter.hit("k", limit=10, window_secs=60)

    assert redis.ttls["netops:rl:k"] == 60


# ---------------------------------------------------------------------------
# Keys: no secret material, stable normalisation
# ---------------------------------------------------------------------------


def test_keys_are_distinct_per_dimension() -> None:
    assert api_principal_key("u1") != api_token_key("u1")
    assert login_lockout_key("alice", "1.2.3.4") != login_source_key("1.2.3.4")
    assert oidc_callback_key("1.2.3.4").startswith("oidc:cb:")


def test_lock_state_keys_are_distinct_from_failure_counter_keys() -> None:
    """The duration-TTL lock keys must not collide with the failure-window counters."""
    assert login_lockout_state_key("alice", "1.2.3.4") != login_lockout_key("alice", "1.2.3.4")
    assert login_source_lock_key("1.2.3.4") != login_source_key("1.2.3.4")
    assert login_lockout_state_key("alice", "1.2.3.4").startswith("login:lock:")
    assert login_source_lock_key("1.2.3.4").startswith("login:srclock:")


def test_login_keys_normalise_case_and_whitespace() -> None:
    assert login_lockout_key("Alice", "1.2.3.4") == login_lockout_key(" alice ", "1.2.3.4")
    assert login_source_key("1.2.3.4 ") == login_source_key("1.2.3.4")
    assert login_lockout_state_key("Alice", "1.2.3.4") == login_lockout_state_key(
        " alice ", "1.2.3.4"
    )
    assert login_source_lock_key("1.2.3.4 ") == login_source_lock_key("1.2.3.4")
