"""Shared single-use stream-ticket store (W2-T2, ADR-0044 §2).

The WebSocket handshake cannot carry an ``Authorization`` header, so the client
exchanges its JWT (over the normal REST surface) for a short-lived, single-use,
opaque ticket and presents that ticket on the socket — the bearer JWT never
appears in a URL. ADR-0010 auth still happens **at the edge**: the ticket binds
(user, session) and is redeemed once at the serving replica.

The redemption store **must be shared across ``api`` replicas** (ADR-0044 §2): a
ticket issued on replica A has to be redeemable on replica B, or the in-process
dict re-introduces the very affinity the fan-out removes. Production binds
:class:`RedisStreamTicketStore` — an atomic ``SET key val NX EX`` to issue and a
``GETDEL`` to redeem-once over the **Sentinel-aware** Redis client (no host pin).
The unit suite uses :class:`InMemoryStreamTicketStore` (same single-use + TTL
semantics, no network). The ticket value stored is only the issuing ``user_id``;
no JWT/secret is ever placed in a Redis key or value.
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    from redis.asyncio import Redis

#: Redis key namespace for stream tickets (kept distinct from rate-limit / OIDC
#: keys sharing the instance). The opaque ticket string is the only variable part.
_KEY_PREFIX: Final = "netops:agent-stream-ticket:"


def _redis_key(ticket: str) -> str:
    return f"{_KEY_PREFIX}{ticket}"


#: ``{session_id}:{user_id}`` is the stored value — both opaque ids, never a secret.
def _encode(session_id: uuid.UUID, user_id: uuid.UUID) -> str:
    return f"{session_id}:{user_id}"


def _decode(value: str, session_id: uuid.UUID) -> uuid.UUID | None:
    stored_session, _, stored_user = value.partition(":")
    if stored_session != str(session_id):
        return None
    try:
        return uuid.UUID(stored_user)
    except ValueError:
        return None


class StreamTicketStore(Protocol):
    """Issue + single-use redeem of opaque stream tickets, shared across replicas."""

    async def issue(self, *, user_id: uuid.UUID, session_id: uuid.UUID, ttl_seconds: int) -> str:
        """Mint an opaque single-use ticket binding (user, session), TTL-bounded."""
        ...

    async def consume(self, *, ticket: str, session_id: uuid.UUID) -> uuid.UUID | None:
        """Redeem *ticket* once for its issuing ``user_id``, or ``None``.

        Returns ``None`` for an unknown, expired, already-used, or
        session-mismatched ticket — callers must not distinguish these cases.
        """
        ...


class RedisStreamTicketStore:
    """Redis-backed single-use ticket store (atomic ``SET NX EX`` + ``GETDEL``).

    Shared across ``api`` replicas via the Sentinel-aware client, so a ticket
    issued on one replica is redeemable on another (ADR-0044 §2). ``GETDEL`` makes
    redemption atomic single-use — two racing sockets cannot both redeem the same
    ticket — and the TTL guarantees an unredeemed ticket cannot linger.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def issue(self, *, user_id: uuid.UUID, session_id: uuid.UUID, ttl_seconds: int) -> str:
        ticket = uuid.uuid4().hex + uuid.uuid4().hex  # 256 bits of opaque entropy
        # ``SET NX`` returns falsy (``None``) when the key already held a value: the
        # write did NOT happen, so the key still binds a PRIOR (session, user) pair
        # and this ticket would hand back a handle the caller can never validly
        # redeem. Refuse rather than return an unredeemable / mis-bound ticket
        # (F-tickets-114). A genuine 256-bit collision is astronomically improbable,
        # so we fail closed rather than retry.
        created = await self._redis.set(
            _redis_key(ticket), _encode(session_id, user_id), nx=True, ex=ttl_seconds
        )
        if not created:
            raise RuntimeError("stream-ticket id collision: SET NX did not write a new key")
        return ticket

    async def consume(self, *, ticket: str, session_id: uuid.UUID) -> uuid.UUID | None:
        raw = await self._redis.getdel(_redis_key(ticket))
        if raw is None:
            return None
        value = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
        return _decode(value, session_id)


class InMemoryStreamTicketStore:
    """Process-local single-use ticket store (tests + single-process fallback).

    Same single-use + TTL semantics as :class:`RedisStreamTicketStore` so the unit
    suite exercises real redemption behaviour without Redis.
    """

    def __init__(self) -> None:
        #: ticket -> (session_id, user_id, expiry_epoch_monotonic)
        self._store: dict[str, tuple[uuid.UUID, uuid.UUID, float]] = {}

    async def issue(self, *, user_id: uuid.UUID, session_id: uuid.UUID, ttl_seconds: int) -> str:
        now = time.monotonic()
        # Purge expired entries so a long-lived process cannot grow unboundedly.
        for key in [k for k, (_, _, exp) in self._store.items() if exp <= now]:
            del self._store[key]
        ticket = uuid.uuid4().hex + uuid.uuid4().hex
        self._store[ticket] = (session_id, user_id, now + float(ttl_seconds))
        return ticket

    async def consume(self, *, ticket: str, session_id: uuid.UUID) -> uuid.UUID | None:
        entry = self._store.pop(ticket, None)  # single-use: removed on first read
        if entry is None:
            return None
        stored_session, user_id, expiry = entry
        if time.monotonic() > expiry:
            return None
        if stored_session != session_id:
            return None
        return user_id
