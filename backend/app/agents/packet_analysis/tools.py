"""Packet Analysis Agent typed tool wrappers (M5 task #11, ADR-0023 §1).

Two READ_ONLY tools, both operating over the normalized, LLM-safe
:class:`~app.engines.packet.PacketFindings` produced by the sandboxed analysis
engine (T8) — **never** over raw packet bytes. ADR-0023 §1 ("Data minimization
to the LLM") fixes the boundary: payload bytes never leave the sandbox worker,
and the agent receives only the aggregate findings (conversations/top talkers,
protocol hierarchy, TCP anomaly counts). These tools therefore take a
``PacketFindings`` dump as plain JSON-able input and return a JSON object the
model consumes directly — they hold no DB session, do no transport I/O, and
never spawn tshark or a capture (the capture is the ``diagnostic`` tier, T8).

- ``summarize_capture`` — the headline summary: top talkers (by packet volume),
  the protocol breakdown, and the error indicators (TCP resets /
  retransmissions).
- ``query_capture`` — filter-style Q&A over the same analysis result: narrow the
  talkers to a host and/or the protocol breakdown to one protocol, while always
  reporting the capture-wide anomaly totals so the model can answer
  "were there resets/retransmissions?".

This module is the sole crossing point from the ``packet_analysis`` agent
package toward ``app.engines`` (REPO-STRUCTURE §3.2 row 11); the agent module
itself imports only the framework, core, schemas, and this submodule.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool
from app.engines.packet import PacketFindings

__all__ = [
    "PACKET_ANALYSIS_TOOLS",
    "query_capture",
    "summarize_capture",
]


def _coerce_findings(findings: dict[str, Any] | PacketFindings) -> PacketFindings:
    """Validate the inbound analysis result into :class:`PacketFindings`.

    Accepts either a ``PacketFindings`` (the engine's own model) or its JSON
    dump, so callers can pass the persisted analysis row directly. This is the
    LLM-safe boundary: ``PacketFindings`` carries only aggregates — no raw
    payload bytes can be smuggled through it (ADR-0023 §1).
    """
    if isinstance(findings, PacketFindings):
        return findings
    return PacketFindings.model_validate(findings)


@netops_tool(classification=ToolClassification.READ_ONLY)
async def summarize_capture(
    findings: Annotated[
        dict[str, Any],
        Field(
            description=(
                "Normalized packet-analysis findings (a PacketFindings dump) produced by "
                "the sandboxed analysis engine — top talkers, protocol hierarchy, and TCP "
                "anomaly counts. Never raw packet bytes."
            )
        ),
    ],
    top_n: Annotated[
        int,
        Field(default=10, gt=0, description="How many top talkers to report (most active first)."),
    ] = 10,
) -> str:
    """Summarize a finished capture from its normalized analysis findings (read-only).

    Returns a JSON object with ``packet_count``; ``top_talkers`` (the busiest
    ``top_n`` conversations, most active first); ``protocol_breakdown`` (per-
    protocol packet counts); and ``tcp_resets`` / ``tcp_retransmissions`` as the
    error indicators. Operates only over the aggregate findings — no raw packet
    bytes, no capture is launched.
    """
    result = _coerce_findings(findings)
    return json.dumps(
        {
            "packet_count": result.packet_count,
            "top_talkers": [c.model_dump() for c in result.top_talkers[:top_n]],
            "protocol_breakdown": [p.model_dump() for p in result.protocol_hierarchy],
            "tcp_resets": result.tcp_resets,
            "tcp_retransmissions": result.tcp_retransmissions,
        }
    )


@netops_tool(classification=ToolClassification.READ_ONLY)
async def query_capture(
    findings: Annotated[
        dict[str, Any],
        Field(
            description=(
                "Normalized packet-analysis findings (a PacketFindings dump) to query — "
                "the same LLM-safe aggregate produced by the analysis engine. Never raw "
                "packet bytes."
            )
        ),
    ],
    host: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional IP address: keep only conversations where this host is the "
                "source or destination."
            ),
        ),
    ] = None,
    protocol: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "Optional protocol name (e.g. 'tcp', 'dns'): keep only that protocol's count."
            ),
        ),
    ] = None,
) -> str:
    """Answer a filter-style question over a capture's analysis findings (read-only).

    Narrows ``top_talkers`` to conversations involving *host* (matched against
    src or dst) and/or ``protocol_breakdown`` to *protocol* (case-insensitive).
    The capture-wide ``tcp_resets`` / ``tcp_retransmissions`` totals are always
    returned so the model can answer anomaly questions regardless of the filter.
    Read-only over the aggregate findings; no raw bytes, no capture.
    """
    result = _coerce_findings(findings)

    talkers = result.top_talkers
    if host is not None:
        talkers = [c for c in talkers if host in (c.src, c.dst)]

    protocols = result.protocol_hierarchy
    if protocol is not None:
        needle = protocol.strip().lower()
        protocols = [p for p in protocols if p.protocol.lower() == needle]

    return json.dumps(
        {
            "packet_count": result.packet_count,
            "top_talkers": [c.model_dump() for c in talkers],
            "protocol_breakdown": [p.model_dump() for p in protocols],
            "tcp_resets": result.tcp_resets,
            "tcp_retransmissions": result.tcp_retransmissions,
        }
    )


#: The agent's read-only tool set (ADR-0023 §1 — analysis output only).
PACKET_ANALYSIS_TOOLS = (summarize_capture, query_capture)
