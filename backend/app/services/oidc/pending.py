"""Short-TTL, single-use pending-auth store keyed by ``state`` (ADR-0028 §2/§3).

Between the authorize redirect and the callback the platform must remember,
**server-side only**, the ``code_verifier``, ``nonce``, and ``redirect_uri`` it
issued for a given ``state``. ADR-0028 §2 specifies a short-TTL Redis entry; the
contract is captured by :class:`PendingAuthStore` so the route depends on the
abstraction, the prod wiring binds the Redis-backed store, and the unit suite
uses :class:`InMemoryPendingAuthStore` (no Redis, no network).

Two security properties are baked into the contract:

- **Single-use** — :meth:`PendingAuthStore.consume` deletes on first lookup, so
  a replayed ``state`` finds nothing and is rejected (ADR-0028 §3). Absence is
  treated as forged.
- **Never client-side** — the ``code_verifier`` / ``nonce`` live only here; they
  are never put in a cookie, response body, or log line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class PendingAuth:
    """The server-held secrets for one in-flight login, keyed by ``state``.

    ``verifier`` and ``nonce`` are sensitive (they bind the token exchange and
    the ID token to *this* login) and must never be logged or returned to the
    browser.
    """

    verifier: str
    nonce: str
    redirect_uri: str
    created_at: float


class PendingAuthStore(Protocol):
    """Server-side, single-use store for in-flight OIDC logins (ADR-0028 §2)."""

    async def put(self, state: str, pending: PendingAuth) -> None:
        """Persist *pending* under *state* with a bounded TTL."""
        ...

    async def consume(self, state: str) -> PendingAuth | None:
        """Atomically fetch-and-delete the entry for *state*, or ``None``.

        Returns ``None`` when *state* is unknown or already consumed/expired —
        the caller rejects the callback uniformly (no oracle).
        """
        ...


class InMemoryPendingAuthStore:
    """Process-local single-use store with TTL expiry (tests + local fallback).

    Honours the same single-use + TTL contract as the Redis-backed store so the
    unit suite exercises the real replay/expiry semantics without a broker.
    """

    def __init__(self, ttl_secs: float = 300.0) -> None:
        self._ttl_secs = ttl_secs
        self._entries: dict[str, PendingAuth] = {}

    def _now(self) -> float:
        return time.monotonic()

    async def put(self, state: str, pending: PendingAuth) -> None:
        self._entries[state] = pending

    async def consume(self, state: str) -> PendingAuth | None:
        pending = self._entries.pop(state, None)
        if pending is None:
            return None
        if self._now() - pending.created_at > self._ttl_secs:
            return None
        return pending
