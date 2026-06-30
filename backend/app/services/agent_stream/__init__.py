"""Stateless agent-session WebSocket fan-out over Redis pub/sub (W2-T2, ADR-0044).

Exposes the per-session fan-out seam (Redis in prod, in-memory for tests), the
wire frame + opaque-session-id channel naming, and the shared single-use
stream-ticket store that lets a ticket issued on one ``api`` replica be redeemed
on another (replacing the in-process ticket dict that breaks at replica > 1).
"""

from app.services.agent_stream.fanout import (
    AgentStreamFanout,
    InMemoryAgentStreamFanout,
    RedisAgentStreamFanout,
)
from app.services.agent_stream.frame import (
    AgentStreamFrame,
    FramePayloadError,
    channel_for,
)
from app.services.agent_stream.tickets import (
    InMemoryStreamTicketStore,
    RedisStreamTicketStore,
    StreamTicketStore,
)

__all__ = [
    "AgentStreamFanout",
    "AgentStreamFrame",
    "FramePayloadError",
    "InMemoryAgentStreamFanout",
    "InMemoryStreamTicketStore",
    "RedisAgentStreamFanout",
    "RedisStreamTicketStore",
    "StreamTicketStore",
    "channel_for",
]
