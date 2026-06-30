"""The wire frame and channel naming for the stateless agent-session fan-out.

W2-T2 (ADR-0044 §2/§3/§4). The agent-session WebSocket stream is made stateless
by fanning session content out over a Redis pub/sub channel keyed by an **opaque
session id**, so any ``api`` replica can serve any session. This module owns the
two pure-data pieces of that contract:

- :func:`channel_for` — the channel name derived from the ``agent_sessions`` UUID
  (``netops:agent-session:{session_id}``). The session id is an opaque,
  capability-checked handle (ADR-0044 §3) — never a bearer secret — so its
  presence on the channel is not a credential leak.
- :class:`AgentStreamFrame` — what rides the channel: the session content
  (``data``: one reasoning-step or terminal frame) plus the **opaque session id**
  and the **trace/audit-join id** (ADR-0015) that keeps the run end-to-end traced
  across the fan-out. The bearer token (or any credential) is **NEVER** part of a
  frame — :meth:`AgentStreamFrame.to_payload` enforces that invariant at the
  serialization boundary so a regression that smuggles a token onto the bus fails
  loudly rather than silently leaking it onto a shared, AOF-persisted channel.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

#: Channel namespace for the per-session fan-out (ADR-0044 §2). One channel per
#: session, keyed by the opaque ``agent_sessions`` UUID.
_CHANNEL_PREFIX: Final = "netops:agent-session:"

#: Payload keys whose presence would mean a credential was published onto the
#: shared bus (ADR-0044 §3 — the central security trap). Frames carry only
#: opaque content + the opaque session id + the trace/audit-join id; any of these
#: keys appearing in a serialized frame is a leak and is refused.
_FORBIDDEN_PAYLOAD_KEYS: Final = frozenset(
    {"token", "jwt", "access_token", "authorization", "bearer", "ticket", "password", "secret"}
)


def channel_for(session_id: str) -> str:
    """Return the pub/sub channel name for *session_id* (opaque-id keyed, ADR-0044 §2)."""
    return f"{_CHANNEL_PREFIX}{session_id}"


class FramePayloadError(ValueError):
    """A frame payload violated the wire contract (e.g. carried a credential key).

    Raised at the serialization boundary so a regression that would publish a
    token/secret onto the shared channel fails closed instead of leaking it.
    """


@dataclass(frozen=True, slots=True)
class AgentStreamFrame:
    """One ordered frame fanned out over a session's pub/sub channel (ADR-0044 §2/§4).

    A frame carries only:

    - ``session_id`` — the **opaque** ``agent_sessions`` UUID the channel is keyed
      by (capability-checked at the edge, never a bearer secret, ADR-0044 §3);
    - ``trace_id`` — the **OTel trace / audit-join correlation id** (ADR-0015) so
      the relaying replica keeps the streamed frames joined to the producing run's
      trace and audit entries even across replicas (G-OBS); a correlation id, not
      a secret;
    - ``data`` — the session **content**: one reasoning-step read model or the
      terminal end marker, exactly the JSON a peer already receives.

    The bearer token is **never** a field here. :meth:`to_payload` re-checks that
    invariant on every serialization so it cannot regress silently.
    """

    session_id: str
    trace_id: str
    data: dict[str, Any]

    def to_payload(self) -> str:
        """Serialize to the JSON published on the channel, refusing any credential key.

        The ``data`` content is the only free-form part; it is the reasoning-step /
        terminal read model the API already emits (no credential). We still scan
        the whole serialized envelope for forbidden credential-shaped keys so a
        future producer that accidentally folds a token into ``data`` (or adds a
        token field) is caught here and never reaches the shared bus.
        """
        envelope = {"session_id": self.session_id, "trace_id": self.trace_id, "data": self.data}
        _assert_no_credential(envelope)
        return json.dumps(envelope, separators=(",", ":"), default=str)

    @classmethod
    def from_payload(cls, payload: str | bytes) -> AgentStreamFrame:
        """Parse a channel payload back into a frame (used by the subscribing replica)."""
        raw = payload.decode() if isinstance(payload, bytes) else payload
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise FramePayloadError("agent-stream frame payload must be a JSON object")
        return cls(
            session_id=str(obj["session_id"]),
            trace_id=str(obj["trace_id"]),
            data=dict(obj["data"]),
        )


def _assert_no_credential(value: object) -> None:
    """Recursively refuse any forbidden credential-shaped key in the wire envelope."""
    if isinstance(value, dict):
        for key, sub in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_PAYLOAD_KEYS:
                # The message is generic on purpose: it must never echo the value.
                raise FramePayloadError(
                    "refusing to publish a frame containing a credential-shaped key "
                    "onto the shared agent-session channel (ADR-0044 §3)"
                )
            _assert_no_credential(sub)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_no_credential(item)
