"""Shared, Redis-backed counter primitive for rate-limiting + login lockout.

W6-T6 (PRODUCTION.md §5, ADR-0008, ADR-0028 §2). The platform needs two related
behaviours backed by the *shared* Redis (so a limit holds across ``api``
replicas — D13 — instead of resetting per pod):

- **API rate limiting** — a fixed-window request budget keyed per authenticated
  principal (``user:<id>``) and per token id (``token:<jti>``), returning
  ``429 + Retry-After`` when exceeded.
- **Login throttle / lockout** — a sliding-ish failure counter per account +
  per source that, once it crosses a threshold, trips a temporary lockout.

The contract is captured by :class:`RateLimiter` so callers depend on the
abstraction; production binds :class:`RedisRateLimiter` (one ``INCR`` + one
``EXPIRE`` per hit — O(1), keyed by principal/token so there is **no single
global hot key** to contend on, satisfying the §11 G-SCA load shape), and the
unit suite uses :class:`InMemoryRateLimiter` (no Redis, no network).

Fail-mode is the caller's decision, not the limiter's: :class:`RedisRateLimiter`
raises a typed :class:`RateLimitBackendError` (never the raw redis SDK exception)
on backend failure, and each call site chooses fail-open (availability — the API
limiter) or fail-closed (security — login lockout). No key/token material is ever
placed in a key, log, or the wrapped error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redis.asyncio import Redis


class RateLimitBackendError(Exception):
    """The rate-limit backend (Redis) was unreachable or rejected the op.

    Raised by :class:`RedisRateLimiter` in place of the raw redis SDK exception
    so no SDK detail (which may echo a DSN with credentials) ever surfaces to a
    caller, log, or response. Callers translate it into their chosen fail-mode.
    """


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Outcome of one counter hit against a fixed window.

    ``allowed`` is ``False`` once ``count`` exceeds ``limit`` within the window;
    ``retry_after_secs`` is the coarse, window-bounded wait the caller surfaces
    in a ``Retry-After`` header (never a precise per-key countdown — that would
    be a faint timing oracle, and §5 wants it coarse).
    """

    allowed: bool
    count: int
    limit: int
    retry_after_secs: int


class RateLimiter(Protocol):
    """Shared fixed-window counter (ADR-0008 Redis; in-memory for tests)."""

    async def hit(self, key: str, *, limit: int, window_secs: int) -> RateLimitResult:
        """Increment the counter for *key* and report whether it stays within *limit*.

        The first hit in a fresh window starts the ``window_secs`` expiry; the
        ``limit+1``-th hit in the same window returns ``allowed=False``.
        """
        ...

    async def peek(self, key: str) -> int:
        """Read the current counter for *key* without incrementing it (0 if absent)."""
        ...

    async def reset(self, key: str) -> None:
        """Drop the counter for *key* (e.g. clear a login window after success)."""
        ...


class InMemoryRateLimiter:
    """Process-local fixed-window counter (tests + single-process fallback).

    Honours the same window/expiry semantics as :class:`RedisRateLimiter` so the
    unit suite exercises the real over-limit / window-rollover behaviour without
    a broker. A monotonic clock keeps it independent of wall-clock changes; the
    clock is injectable so tests can advance windows deterministically.
    """

    def __init__(self, clock: _Clock | None = None) -> None:
        self._clock = clock if clock is not None else _MonotonicClock()
        #: key -> (count, window_expires_at_monotonic)
        self._counters: dict[str, tuple[int, float]] = {}

    async def hit(self, key: str, *, limit: int, window_secs: int) -> RateLimitResult:
        now = self._clock.now()
        count, expires_at = self._counters.get(key, (0, 0.0))
        if now >= expires_at:
            count, expires_at = 0, now + float(window_secs)
        count += 1
        self._counters[key] = (count, expires_at)
        remaining = max(0, int(round(expires_at - now)))
        return RateLimitResult(
            allowed=count <= limit,
            count=count,
            limit=limit,
            # Coarse: the whole remaining window, not a precise per-key value.
            retry_after_secs=remaining if count > limit else 0,
        )

    async def peek(self, key: str) -> int:
        now = self._clock.now()
        count, expires_at = self._counters.get(key, (0, 0.0))
        return count if now < expires_at else 0

    async def reset(self, key: str) -> None:
        self._counters.pop(key, None)


class RedisRateLimiter:
    """Redis-backed fixed-window counter shared across ``api`` replicas (ADR-0008).

    One ``INCR`` plus (on the first hit of a window) one ``EXPIRE`` — O(1), no
    read-modify-write race, and keyed by principal/token so load spreads across
    keys rather than contending on one global counter (G-SCA). Any backend error
    is wrapped in :class:`RateLimitBackendError`; the raw SDK exception (which
    can contain a credentialed DSN) is never re-raised or logged here.
    """

    #: Key namespace so rate-limit counters never collide with other Redis users
    #: (Celery broker, OIDC pending-auth) sharing the same instance/DB.
    _PREFIX = "netops:rl:"

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def hit(self, key: str, *, limit: int, window_secs: int) -> RateLimitResult:
        redis_key = f"{self._PREFIX}{key}"
        try:
            count = int(await self._redis.incr(redis_key))
            if count == 1:
                # First hit starts the window's TTL; subsequent hits ride it out.
                await self._redis.expire(redis_key, window_secs)
                ttl = window_secs
            else:
                ttl = int(await self._redis.ttl(redis_key))
                if ttl < 0:
                    # No TTL set (e.g. a crash between INCR and EXPIRE): re-arm so
                    # the counter cannot become a permanent lock.
                    await self._redis.expire(redis_key, window_secs)
                    ttl = window_secs
        except Exception as exc:  # noqa: BLE001 — wrap *any* SDK/transport error
            raise RateLimitBackendError("rate-limit backend unavailable") from exc
        return RateLimitResult(
            allowed=count <= limit,
            count=count,
            limit=limit,
            retry_after_secs=max(0, ttl) if count > limit else 0,
        )

    async def peek(self, key: str) -> int:
        try:
            raw = await self._redis.get(f"{self._PREFIX}{key}")
        except Exception as exc:  # noqa: BLE001 — wrap *any* SDK/transport error
            raise RateLimitBackendError("rate-limit backend unavailable") from exc
        if raw is None:
            return 0
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    async def reset(self, key: str) -> None:
        try:
            await self._redis.delete(f"{self._PREFIX}{key}")
        except Exception as exc:  # noqa: BLE001 — wrap *any* SDK/transport error
            raise RateLimitBackendError("rate-limit backend unavailable") from exc


class _Clock(Protocol):
    """Monotonic time source (injectable so tests can advance windows)."""

    def now(self) -> float: ...


class _MonotonicClock:
    """Default :class:`_Clock` backed by :func:`time.monotonic`."""

    def now(self) -> float:
        import time

        return time.monotonic()
