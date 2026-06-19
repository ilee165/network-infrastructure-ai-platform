"""Packet Analysis Agent — read-only narration of capture findings (M5 task #11).

CLAUDE.md Core Agent #5 (Packet Analysis) / M5-PLAN row #11, ADR-0023. The
Packet Analysis Agent summarizes a finished capture and answers filter-style
questions over its analysis result, and attaches those findings to a
troubleshooting session (the same session/trace model M3 introduced).

LLM-safe boundary (ADR-0023 §1, ADR-0014 §3, ADR-0009 minimization)
    The agent is **strictly read-only over packet-analysis output**. It operates
    only on the normalized :class:`~app.engines.packet.PacketFindings` produced
    by the sandboxed analysis engine (T8) — top talkers, the protocol hierarchy,
    and TCP anomaly counts. It **never** receives raw packet bytes, and it
    **never invokes a capture itself**: starting a capture is the separate
    ``diagnostic`` tier (T8), gated and audited elsewhere. Every declared tool is
    :attr:`~app.agents.framework.tools.ToolClassification.READ_ONLY`; no
    state-changing or diagnostic tool may ever appear on it (asserted by the
    tests and by :meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`).

Graph: the default ReAct loop from
:meth:`~app.agents.framework.base.BaseSpecialistAgent.build_graph` — the two
read-only tools run directly; no bespoke topology is needed.

Findings attach to a session via :meth:`summarize_findings`: it opens a reasoning
trace on the injected :class:`~app.agents.framework.traces.TraceRecorder`, cites
each headline finding (top talkers, protocol mix, anomaly counts) as an
:class:`~app.agents.framework.traces.EvidenceRef`, and completes the trace. The
M3 :class:`~app.agents.framework.traces.PostgresTraceRecorder` carries the
``agent_sessions`` FK, so recording onto a session-bound recorder *is* attaching
the findings to that troubleshooting session — the same mechanism the
Troubleshooting Agent uses to ground a diagnosis.

Module boundary: this package imports only ``agents.framework``, ``core``,
``schemas``, and its own ``tools`` submodule. The ``tools`` module is the sole
crossing point into ``engines`` (REPO-STRUCTURE §3.2 row 11).
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, Field

from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool
from app.agents.framework.traces import (
    EvidenceRef,
    InMemoryTraceRecorder,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
)
from app.agents.packet_analysis.tools import PACKET_ANALYSIS_TOOLS
from app.engines.packet import Conversation, PacketFindings, ProtocolCount

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
PACKET_ANALYSIS_NAME = "packet_analysis"


class CaptureSummary(BaseModel):
    """The grounded, LLM-safe summary of one capture's analysis findings.

    A thin re-projection of :class:`~app.engines.packet.PacketFindings` returned
    to the caller of :meth:`PacketAnalysisAgent.summarize_findings`. Carries only
    aggregates — top talkers, the protocol breakdown, and the TCP anomaly counts
    — so it never represents an individual packet payload (ADR-0023 §1).
    """

    packet_count: int = 0
    top_talkers: list[Conversation] = Field(default_factory=list)
    protocol_breakdown: list[ProtocolCount] = Field(default_factory=list)
    tcp_resets: int = 0
    tcp_retransmissions: int = 0


class PacketAnalysisAgent(BaseSpecialistAgent):
    """Read-only packet-analysis specialist (CLAUDE.md Core Agent #5).

    Construct with an optional :class:`TraceRecorder` so a troubleshooting
    session can own the findings a run attaches; the default is an
    :class:`InMemoryTraceRecorder`. The recorder is shared across runs of this
    instance, so tests build a fresh agent (or pass a session-bound recorder)
    per run.
    """

    def __init__(self, *, trace_recorder: TraceRecorder | None = None) -> None:
        self._trace_recorder: TraceRecorder = (
            trace_recorder if trace_recorder is not None else InMemoryTraceRecorder()
        )

    # ------------------------------------------------------------------
    # BaseSpecialistAgent contract
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return PACKET_ANALYSIS_NAME

    @property
    def description(self) -> str:
        return (
            "Analyzes finished packet captures: summarizes a capture's top talkers "
            "(busiest conversations), its protocol breakdown, and its error indicators "
            "(TCP resets and retransmissions), and answers filter-style questions over the "
            "capture such as 'which hosts talked to X' or 'how many DNS packets'. Route "
            "here when the user has a capture (pcap) and wants it summarized or queried. It "
            "is strictly read-only over already-produced analysis output: it never starts a "
            "capture and never inspects raw packet payloads. This is NOT generic device "
            "troubleshooting (it does not diagnose routing/BGP/OSPF/ACL faults) and NOT "
            "inventory discovery (it does not crawl devices) — it reasons over packet "
            "capture analysis results."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Packet Analysis Agent for an AI Network Operations Platform.\n\n"
            "You explain finished packet captures: their top talkers, protocol breakdown, "
            "and error indicators (TCP resets and retransmissions), and you answer "
            "filter-style questions over a capture's analysis result.\n\n"
            "You reason ONLY over normalized analysis findings — top talkers, the protocol "
            "hierarchy, and anomaly counts. You never see, ask for, or reconstruct raw "
            "packet bytes or payloads; the sensitive payload never leaves the sandbox. You "
            "also never start a capture yourself — you analyze captures that already exist.\n\n"
            "Ground every statement in the findings you were given: cite the specific "
            "talker, protocol count, or reset/retransmission total you observed. If the "
            "findings do not answer the question, say so plainly rather than guessing.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """The two READ_ONLY analysis tools (summarize + filter-style query)."""
        return PACKET_ANALYSIS_TOOLS

    # ------------------------------------------------------------------
    # Trace access + session attachment
    # ------------------------------------------------------------------

    @property
    def trace_recorder(self) -> TraceRecorder:
        """The recorder a run's findings are attached to (the session/trace seam)."""
        return self._trace_recorder

    async def summarize_findings(self, findings: PacketFindings) -> CaptureSummary:
        """Summarize *findings* and attach them to the current session's trace.

        Opens a reasoning trace on the injected :class:`TraceRecorder`, records a
        PLAN step (what is being summarized), an OBSERVATION step that cites each
        headline finding as an :class:`EvidenceRef` (top talkers, protocol mix,
        TCP anomaly counts), and a CONCLUSION step with a grounded one-line
        narrative; then completes the trace. When the recorder is the M3
        :class:`~app.agents.framework.traces.PostgresTraceRecorder` (session-bound),
        this persists the findings against the active ``agent_sessions`` row — i.e.
        attaches them to that troubleshooting session. Returns the grounded
        :class:`CaptureSummary`.
        """
        recorder = self._trace_recorder
        trace = await recorder.start(self.name)

        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.PLAN,
                summary=(
                    f"summarizing a capture of {findings.packet_count} packet(s): "
                    "top talkers, protocol breakdown, and TCP anomalies"
                ),
            ),
        )

        evidence = _evidence_from_findings(findings)
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.OBSERVATION,
                summary=(
                    f"observed {len(findings.top_talkers)} top talker(s) and "
                    f"{len(findings.protocol_hierarchy)} protocol(s)"
                ),
                evidence=evidence,
            ),
        )

        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.CONCLUSION,
                summary=_compose_summary(findings),
                evidence=evidence,
            ),
        )
        await recorder.complete(trace.trace_id)

        return CaptureSummary(
            packet_count=findings.packet_count,
            top_talkers=list(findings.top_talkers),
            protocol_breakdown=list(findings.protocol_hierarchy),
            tcp_resets=findings.tcp_resets,
            tcp_retransmissions=findings.tcp_retransmissions,
        )


# ---------------------------------------------------------------------------
# Evidence extraction + grounded narrative
# ---------------------------------------------------------------------------


def _evidence_from_findings(findings: PacketFindings) -> list[EvidenceRef]:
    """Cite each headline finding as an :class:`EvidenceRef` for the trace.

    Top talkers, the protocol breakdown, and the TCP anomaly totals each become
    a reference with a human-readable summary for the trace viewer — these are
    the aggregates the LLM is allowed to see (ADR-0023 §1). No raw payload is
    ever referenced.
    """
    refs: list[EvidenceRef] = []
    for talker in findings.top_talkers:
        refs.append(
            EvidenceRef(
                kind="top_talker",
                reference=f"talker:{talker.src}->{talker.dst}",
                description=(
                    f"{talker.src} -> {talker.dst}: {talker.packets} packets, {talker.bytes} bytes"
                ),
            )
        )
    for proto in findings.protocol_hierarchy:
        refs.append(
            EvidenceRef(
                kind="protocol",
                reference=f"protocol:{proto.protocol}",
                description=f"{proto.protocol}: {proto.packets} packets",
            )
        )
    refs.append(
        EvidenceRef(
            kind="tcp_anomaly",
            reference="tcp:anomalies",
            description=(
                f"{findings.tcp_resets} TCP reset(s), "
                f"{findings.tcp_retransmissions} retransmission(s)"
            ),
        )
    )
    return refs


def _compose_summary(findings: PacketFindings) -> str:
    """Compose a grounded one-line narrative from the findings.

    Built *from* the aggregates — the busiest talker, the dominant protocol, and
    the anomaly totals — so the conclusion never asserts anything the findings do
    not show. An empty capture is reported honestly.
    """
    if findings.packet_count == 0:
        return "The capture contained no packets; there is nothing to summarize."
    parts = [f"Capture of {findings.packet_count} packets."]
    if findings.top_talkers:
        top = findings.top_talkers[0]
        parts.append(f"Busiest talker {top.src} -> {top.dst} ({top.packets} packets).")
    if findings.protocol_hierarchy:
        dominant = findings.protocol_hierarchy[0]
        parts.append(f"Dominant protocol {dominant.protocol} ({dominant.packets} packets).")
    parts.append(
        f"{findings.tcp_resets} TCP reset(s), {findings.tcp_retransmissions} retransmission(s)."
    )
    return " ".join(parts)
