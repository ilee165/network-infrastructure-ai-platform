"""Normalized packet-analysis findings (M5; ADR-0023 §1 — data minimization).

Analysis produces **structured Pydantic findings** — conversations/endpoints
(top talkers), a protocol hierarchy, and basic TCP-anomaly counts — derived from
tshark's machine-readable output. The LLM (the Packet Analysis Agent, M5 task
#11) receives these *summarized findings*, **never raw packet bytes** (ADR-0014
§3, ADR-0009 minimization). Payload bytes never leave the sandbox worker.

This module is pure transformation over already-parsed tshark JSON — no
subprocess, no filesystem, no Celery. The subprocess that produced the JSON, and
its sandbox, live in :mod:`app.engines.packet.sandbox`.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "Conversation",
    "PacketFindings",
    "ProtocolCount",
    "summarize_packets",
]


class Conversation(BaseModel):
    """One src→dst endpoint pair and how many packets/bytes it carried."""

    src: str
    dst: str
    packets: int
    bytes: int


class ProtocolCount(BaseModel):
    """Packet count for one protocol in the capture's protocol hierarchy."""

    protocol: str
    packets: int


class PacketFindings(BaseModel):
    """Normalized, LLM-safe summary of one pcap (no raw payload bytes).

    ``top_talkers`` is the conversation list ordered by packet volume (most
    active first), ``protocol_hierarchy`` the per-protocol counts, and
    ``tcp_resets``/``tcp_retransmissions`` coarse anomaly indicators. Everything
    here is an aggregate — individual packet payloads are never represented.
    """

    packet_count: int = 0
    top_talkers: list[Conversation] = Field(default_factory=list)
    protocol_hierarchy: list[ProtocolCount] = Field(default_factory=list)
    tcp_resets: int = 0
    tcp_retransmissions: int = 0


def summarize_packets(packets: list[dict[str, Any]], *, top_n: int = 10) -> PacketFindings:
    """Summarize tshark ``-T json`` packet records into normalized findings.

    *packets* is the decoded tshark JSON array (each element a per-packet
    ``{"_source": {"layers": {...}}}`` record). Aggregates conversations by
    ``(ip.src, ip.dst)``, tallies the highest-layer protocol per packet, and
    counts TCP resets/retransmissions from the ``tcp.flags`` / expert fields. No
    payload bytes are read or retained — only addressing/metadata aggregates,
    which is what the LLM boundary is allowed to receive (ADR-0023 §1).
    """
    conversations: Counter[tuple[str, str]] = Counter()
    conv_bytes: Counter[tuple[str, str]] = Counter()
    protocols: Counter[str] = Counter()
    tcp_resets = 0
    tcp_retransmissions = 0

    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        ip = layers.get("ip", {})
        src = ip.get("ip.src")
        dst = ip.get("ip.dst")
        length = _as_int(layers.get("frame", {}).get("frame.len"))
        if src and dst:
            key = (src, dst)
            conversations[key] += 1
            conv_bytes[key] += length

        proto = _highest_protocol(layers)
        if proto:
            protocols[proto] += 1

        tcp = layers.get("tcp", {})
        if tcp:
            flags = _as_int(tcp.get("tcp.flags_tree", {}).get("tcp.flags.reset")) or _as_int(
                tcp.get("tcp.flags.reset")
            )
            if flags:
                tcp_resets += 1
            analysis = tcp.get("tcp.analysis", {})
            if "tcp.analysis.retransmission" in analysis or analysis.get(
                "tcp.analysis.retransmission"
            ):
                tcp_retransmissions += 1

    top_talkers = [
        Conversation(src=src, dst=dst, packets=count, bytes=conv_bytes[(src, dst)])
        for (src, dst), count in conversations.most_common(top_n)
    ]
    protocol_hierarchy = [
        ProtocolCount(protocol=proto, packets=count) for proto, count in protocols.most_common()
    ]
    return PacketFindings(
        packet_count=len(packets),
        top_talkers=top_talkers,
        protocol_hierarchy=protocol_hierarchy,
        tcp_resets=tcp_resets,
        tcp_retransmissions=tcp_retransmissions,
    )


def _highest_protocol(layers: dict[str, Any]) -> str | None:
    """Coarsest "highest layer" protocol name present in a packet's layers."""
    for proto in ("tls", "http", "dns", "tcp", "udp", "icmp", "arp", "ip"):
        if proto in layers:
            return proto
    return None


def _as_int(value: Any) -> int:
    """Best-effort int from a tshark field (strings, hex strings, or None)."""
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return 0
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return 0
