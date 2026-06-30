"""W2-T2 — shared single-use stream-ticket store (ADR-0044 §2).

The store must redeem a ticket issued on one ``api`` replica from another (so the
fan-out is genuinely stateless), redeem once (single-use), expire, and never
distinguish unknown/expired/mismatched tickets to the caller. It never stores a
JWT/secret — only the opaque (session_id, user_id) binding.
"""

from __future__ import annotations

import uuid

from app.services.agent_stream.tickets import (
    InMemoryStreamTicketStore,
    _redis_key,
)

SESSION = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_SESSION = uuid.UUID("22222222-2222-2222-2222-222222222222")
USER = uuid.UUID("33333333-3333-3333-3333-333333333333")


class TestInMemoryStreamTicketStore:
    async def test_ticket_issued_on_one_store_redeems_on_another(self) -> None:
        """Cross-replica: a ticket from store A redeems on store B over a shared backend.

        The in-memory store is one process; production shares via Redis. We model
        the shared backend by issuing and consuming through stores that share the
        same dict, proving redemption is not pinned to the issuing instance.
        """
        store_a = InMemoryStreamTicketStore()
        store_b = InMemoryStreamTicketStore()
        store_b._store = store_a._store  # shared backend (the Redis instance in prod)

        ticket = await store_a.issue(user_id=USER, session_id=SESSION, ttl_seconds=30)
        redeemed = await store_b.consume(ticket=ticket, session_id=SESSION)
        assert redeemed == USER

    async def test_single_use_second_consume_returns_none(self) -> None:
        store = InMemoryStreamTicketStore()
        ticket = await store.issue(user_id=USER, session_id=SESSION, ttl_seconds=30)
        assert await store.consume(ticket=ticket, session_id=SESSION) == USER
        assert await store.consume(ticket=ticket, session_id=SESSION) is None

    async def test_expired_ticket_returns_none(self) -> None:
        store = InMemoryStreamTicketStore()
        ticket = await store.issue(user_id=USER, session_id=SESSION, ttl_seconds=30)
        # Force the stored expiry into the past (deterministic, no real sleep).
        session_id, user_id, _ = store._store[ticket]
        store._store[ticket] = (session_id, user_id, 0.0)
        assert await store.consume(ticket=ticket, session_id=SESSION) is None

    async def test_session_mismatch_returns_none(self) -> None:
        store = InMemoryStreamTicketStore()
        ticket = await store.issue(user_id=USER, session_id=SESSION, ttl_seconds=30)
        assert await store.consume(ticket=ticket, session_id=OTHER_SESSION) is None

    async def test_unknown_ticket_returns_none(self) -> None:
        store = InMemoryStreamTicketStore()
        assert await store.consume(ticket="nope", session_id=SESSION) is None

    async def test_no_secret_in_key_or_value(self) -> None:
        """The Redis key namespace and stored value carry only opaque ids."""
        store = InMemoryStreamTicketStore()
        ticket = await store.issue(user_id=USER, session_id=SESSION, ttl_seconds=30)
        # The opaque ticket is high-entropy and not the user's id/secret.
        assert str(USER) not in ticket
        assert _redis_key(ticket).startswith("netops:agent-stream-ticket:")


class _FakeRedis:
    """Minimal SET NX EX + GETDEL fake to pin the RedisStreamTicketStore call shape."""

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}
        self.set_calls: list[tuple[str, str, bool, int]] = []
        self.getdel_calls: list[str] = []

    async def set(self, key: str, value: str, *, nx: bool, ex: int) -> bool:
        self.set_calls.append((key, value, nx, ex))
        if nx and key in self._kv:
            return False
        self._kv[key] = value
        return True

    async def getdel(self, key: str) -> bytes | None:
        self.getdel_calls.append(key)
        val = self._kv.pop(key, None)
        return val.encode() if val is not None else None


class TestRedisStreamTicketStoreContract:
    async def test_issue_uses_set_nx_ex_and_consume_uses_getdel(self) -> None:
        from app.services.agent_stream.tickets import RedisStreamTicketStore

        fake = _FakeRedis()
        store = RedisStreamTicketStore(fake)  # type: ignore[arg-type]

        ticket = await store.issue(user_id=USER, session_id=SESSION, ttl_seconds=30)
        # Real SDK shape: SET key value nx=True ex=ttl.
        assert len(fake.set_calls) == 1
        key, value, nx, ex = fake.set_calls[0]
        assert key == _redis_key(ticket)
        assert nx is True and ex == 30
        assert str(USER) in value and str(SESSION) in value
        # No secret/JWT in the stored value.
        for forbidden in ("jwt", "bearer", "password", "token"):
            assert forbidden not in value.lower()

        redeemed = await store.consume(ticket=ticket, session_id=SESSION)
        assert redeemed == USER
        assert fake.getdel_calls == [_redis_key(ticket)]
        # Single-use: GETDEL removed it.
        assert await store.consume(ticket=ticket, session_id=SESSION) is None
