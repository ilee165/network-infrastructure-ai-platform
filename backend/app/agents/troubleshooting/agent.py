"""Troubleshooting Agent — the first analytic specialist (M3-13, read-only).

CLAUDE.md Core Agent #4 / MVP.md §5. The Troubleshooting Agent answers
routing / BGP / OSPF / ACL questions over collected normalized data plus
on-demand live reads through the vendor plugin capabilities (M3-07..10). It
is strictly read-only: every declared tool is
:attr:`~app.agents.framework.tools.ToolClassification.READ_ONLY` and no
state-changing tool may ever appear on it (asserted by the tests and by
:meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`).

Bespoke graph (overrides :meth:`BaseSpecialistAgent.build_graph`)
    Instead of the default ReAct loop, this agent runs an explicit
    ``symptom -> hypothesis -> diagnosis`` flow:

    1. **symptom** — classify the user's report into one analysis domain
       (bgp / ospf / acl / routing) and extract the target entity. The router
       is the injected LLM under structured output, so the step is
       deterministic under the scripted fake model used in tests.
    2. **hypothesis** — gather *evidence* by calling the matching READ_ONLY
       tool(s) and turn each collected fact (peer FSM state, route presence,
       deny rule) into an :class:`~app.agents.framework.traces.EvidenceRef`
       recorded on the reasoning trace.
    3. **diagnosis** — compose a grounded, human-readable answer that cites the
       gathered evidence, and complete the trace.

    Grounding is the contract: the final answer is built *from* the evidence
    refs, never from the model's imagination (CLAUDE.md: explain all AI
    decisions). The reasoning trace produced by a run is retrievable from the
    injected :class:`~app.agents.framework.traces.TraceRecorder`, so callers
    (and tests) can inspect exactly which collected facts grounded the answer.

Module boundary: this package imports only ``agents.framework``, ``core``,
``schemas``, and its own ``tools`` submodule. The ``tools`` module is the sole
crossing point into ``models`` / ``plugins`` / ``engines`` — enforced by the
import-linter contract (REPO-STRUCTURE §3.2 row 11).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from enum import StrEnum
from typing import Any, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool
from app.agents.framework.traces import (
    EvidenceRef,
    InMemoryTraceRecorder,
    ReasoningTrace,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
)
from app.agents.troubleshooting.tools import TROUBLESHOOTING_TOOLS

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
TROUBLESHOOTING_NAME = "troubleshooting"


class AnalysisDomain(StrEnum):
    """The analysis domain a symptom is classified into (MVP.md §5)."""

    BGP = "bgp"
    OSPF = "ospf"
    ACL = "acl"
    ROUTING = "routing"


class SymptomClassification(BaseModel):
    """Structured output of the *symptom* node.

    The router maps a free-text user report onto one :class:`AnalysisDomain`
    plus the concrete entities a diagnosis needs: the device under test and,
    where relevant, the specific peer / prefix the user named.
    """

    domain: AnalysisDomain = Field(description="Which analysis the symptom calls for.")
    device_id: str | None = Field(
        default=None,
        description="UUID of the device under test, if the user named one.",
    )
    target: str | None = Field(
        default=None,
        description="The specific peer address, prefix, or ACL the user named, if any.",
    )
    rationale: str = Field(
        default="",
        description="One-sentence explanation of the classification.",
    )


#: Maps each analysis domain to the tool whose output grounds its diagnosis.
_DOMAIN_TOOL: dict[AnalysisDomain, str] = {
    AnalysisDomain.BGP: "read_live_bgp_peers",
    AnalysisDomain.OSPF: "read_live_ospf_neighbors",
    AnalysisDomain.ACL: "read_live_acls",
    AnalysisDomain.ROUTING: "get_device_routes",
}

#: Where each tool puts its records and the EvidenceRef kind to cite them as.
_TOOL_RECORD_KEY: dict[str, tuple[str, str]] = {
    "read_live_bgp_peers": ("peers", "bgp_peer"),
    "read_live_ospf_neighbors": ("neighbors", "ospf_neighbor"),
    "read_live_acls": ("acls", "acl_entry"),
    "get_device_routes": ("routes", "route"),
}


class TroubleshootingState(MessagesState):
    """Graph state: the conversation plus the symptom/evidence/trace channels."""

    #: The symptom classification produced by the ``symptom`` node.
    classification: SymptomClassification
    #: Evidence refs gathered by the ``hypothesis`` node.
    evidence: list[EvidenceRef]
    #: This run's reasoning trace.
    trace: ReasoningTrace | None


def _summarize_bgp_peer(record: dict[str, Any]) -> str:
    return (
        f"BGP peer {record.get('peer_address')} (AS {record.get('remote_as')}) "
        f"state={record.get('state')}"
    )


def _summarize_ospf_neighbor(record: dict[str, Any]) -> str:
    return (
        f"OSPF neighbor {record.get('neighbor_id')} on {record.get('interface')} "
        f"state={record.get('state')}"
    )


def _summarize_acl_entry(record: dict[str, Any]) -> str:
    return (
        f"ACL {record.get('acl_name')} seq {record.get('sequence')} "
        f"{record.get('action')} {record.get('protocol')}"
    )


def _summarize_route(record: dict[str, Any]) -> str:
    return (
        f"route {record.get('prefix')} via {record.get('next_hop') or record.get('interface')} "
        f"({record.get('protocol')})"
    )


#: Per-evidence-kind one-line summarizers for the trace viewer.
_RECORD_SUMMARY = {
    "bgp_peer": _summarize_bgp_peer,
    "ospf_neighbor": _summarize_ospf_neighbor,
    "acl_entry": _summarize_acl_entry,
    "route": _summarize_route,
}


class TroubleshootingAgent(BaseSpecialistAgent):
    """Read-only routing/BGP/OSPF/ACL analysis specialist (CLAUDE.md Core Agent #4).

    Construct with an optional :class:`TraceRecorder` so callers can inspect
    the evidence-grounded reasoning trace a run produces; the default is an
    :class:`InMemoryTraceRecorder`. The recorder is shared across runs of this
    instance, so tests build a fresh agent per run.
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
        return TROUBLESHOOTING_NAME

    @property
    def description(self) -> str:
        return (
            "Diagnoses network control-plane and data-plane problems: routing "
            "analysis, BGP peer/session analysis, OSPF adjacency analysis, and ACL "
            "analysis. Route here when the user reports a symptom such as a down BGP "
            "peer, a stuck OSPF adjacency, a missing route, or traffic being dropped, "
            "and wants to know why. All operations are read-only — no device "
            "configuration is modified."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Troubleshooting Agent for an AI Network Operations Platform.\n\n"
            "You diagnose routing, BGP, OSPF, and ACL problems over collected "
            "normalized data and on-demand live device reads. You are strictly "
            "read-only: you never change device configuration.\n\n"
            "Method:\n"
            "1. Classify the reported symptom into one domain (bgp, ospf, acl, routing) "
            "and identify the device under test and the specific peer/prefix/ACL named.\n"
            "2. Gather evidence by reading the relevant collected or live state "
            "(peer FSM state, neighbor state, route presence, ACL rules).\n"
            "3. Ground every conclusion in that evidence: cite the specific peer state, "
            "interface status, or route you observed. Never guess — if the evidence is "
            "missing, say so and name what you could not collect.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """The four READ_ONLY analysis tools (routing / BGP / OSPF / ACL)."""
        return TROUBLESHOOTING_TOOLS

    # ------------------------------------------------------------------
    # Trace access
    # ------------------------------------------------------------------

    @property
    def trace_recorder(self) -> TraceRecorder:
        """The recorder a run's evidence-grounded reasoning trace is written to."""
        return self._trace_recorder

    # ------------------------------------------------------------------
    # Bespoke symptom -> hypothesis -> diagnosis graph
    # ------------------------------------------------------------------

    def build_graph(
        self, llm: BaseChatModel
    ) -> CompiledStateGraph[MessagesState, None, MessagesState, MessagesState]:
        """Compile the bespoke ``symptom -> hypothesis -> diagnosis`` subgraph.

        Overrides the default ReAct loop. The chosen tool is resolved by name
        from :attr:`tools` at run time so a test can substitute a fixture-backed
        fake of the same name (the established offline-execution pattern). Every
        gathered fact becomes an :class:`EvidenceRef` on the run's trace, and
        the final answer is composed from those refs so it is grounded.
        """
        self.validate_definition()
        recorder = self._trace_recorder
        classifier = llm.with_structured_output(SymptomClassification)
        system_message = SystemMessage(content=self.system_prompt)

        def _resolve_tool(tool_name: str) -> NetOpsTool | None:
            """Resolve a declared tool by name at run time.

            Read from :attr:`tools` on each call (not a build-time snapshot) so a
            fixture-backed fake swapped into the tool list is honored even when
            the graph was compiled earlier — the offline-execution test pattern.
            """
            for tool in self.tools:
                if tool.name == tool_name:
                    return tool
            return None

        async def symptom(state: TroubleshootingState) -> dict[str, Any]:
            """Classify the reported symptom and open the reasoning trace."""
            trace = await recorder.start(self.name)
            classification = cast(
                SymptomClassification,
                await classifier.ainvoke([system_message, *state["messages"]]),
            )
            await recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.PLAN,
                    summary=(
                        f"classified symptom as '{classification.domain.value}' analysis"
                        + (
                            f" for device {classification.device_id}"
                            if classification.device_id
                            else ""
                        )
                    ),
                    detail=classification.rationale or None,
                ),
            )
            return {"classification": classification, "trace": trace, "evidence": []}

        async def hypothesis(state: TroubleshootingState) -> dict[str, Any]:
            """Gather evidence with the domain's READ_ONLY tool; record refs."""
            classification = state["classification"]
            trace = state["trace"]
            assert trace is not None  # noqa: S101 - symptom always sets the trace
            tool_name = _DOMAIN_TOOL[classification.domain]
            tool = _resolve_tool(tool_name)
            evidence: list[EvidenceRef] = []
            if tool is None or classification.device_id is None:
                missing = (
                    f"no '{tool_name}' tool is available"
                    if tool is None
                    else "the symptom did not name a device to inspect"
                )
                await recorder.record_step(
                    trace.trace_id,
                    TraceStep(
                        kind=TraceStepKind.OBSERVATION,
                        summary=f"could not gather evidence: {missing}",
                    ),
                )
                return {"evidence": evidence}

            raw = await tool.ainvoke({"device_id": classification.device_id})
            await recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.TOOL_CALL,
                    summary=f"read {classification.domain.value} state via '{tool_name}'",
                    tool_name=tool_name,
                ),
            )
            evidence = _evidence_from_tool_output(
                tool_name=tool_name,
                device_id=classification.device_id,
                target=classification.target,
                raw=raw,
            )
            await recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.OBSERVATION,
                    summary=(
                        f"collected {len(evidence)} evidence item(s) from '{tool_name}'"
                        if evidence
                        else f"'{tool_name}' returned no matching state"
                    ),
                    evidence=evidence,
                ),
            )
            return {"evidence": evidence}

        async def diagnosis(state: TroubleshootingState) -> dict[str, Any]:
            """Compose a grounded answer from the evidence and complete the trace."""
            classification = state["classification"]
            trace = state["trace"]
            assert trace is not None  # noqa: S101 - symptom always sets the trace
            # Guard: hypothesis may not have written 'evidence' if it raised
            # before returning (e.g. an unexpected exception); default to []
            # so the trace is always completed and no KeyError escapes.
            evidence: list[EvidenceRef] = state.get("evidence", [])
            completed = trace
            try:
                answer = _compose_answer(classification, evidence)
                await recorder.record_step(
                    trace.trace_id,
                    TraceStep(
                        kind=TraceStepKind.CONCLUSION,
                        summary=answer,
                        evidence=evidence,
                    ),
                )
            finally:
                # Always complete the trace so it is never left permanently open.
                completed = await recorder.complete(trace.trace_id)
            return {"messages": [AIMessage(content=answer)], "trace": completed}

        graph: StateGraph[
            TroubleshootingState, None, TroubleshootingState, TroubleshootingState
        ] = StateGraph(TroubleshootingState)
        graph.add_node("symptom", symptom)
        graph.add_node("hypothesis", hypothesis)
        graph.add_node("diagnosis", diagnosis)
        graph.add_edge(START, "symptom")
        graph.add_edge("symptom", "hypothesis")
        graph.add_edge("hypothesis", "diagnosis")
        graph.add_edge("diagnosis", END)
        return cast(
            "CompiledStateGraph[MessagesState, None, MessagesState, MessagesState]",
            graph.compile(name=self.name),
        )


# ---------------------------------------------------------------------------
# Evidence extraction + grounded answer synthesis
# ---------------------------------------------------------------------------


def _evidence_from_tool_output(
    *, tool_name: str, device_id: str, target: str | None, raw: object
) -> list[EvidenceRef]:
    """Turn a tool's JSON output into cited :class:`EvidenceRef` entries.

    Each normalized record becomes one evidence ref pointing at the device and
    record, with a human-readable summary for the trace viewer. When the user
    named a ``target`` (a peer address / prefix), records matching it are
    surfaced; otherwise every returned record is cited.
    """
    record_key, evidence_kind = _TOOL_RECORD_KEY[tool_name]
    payload = _load_json(raw)
    if payload is None or "error" in payload:
        detail = payload.get("error") if payload else "tool returned non-JSON output"
        return [
            EvidenceRef(
                kind=f"{evidence_kind}_unavailable",
                reference=f"device:{device_id}:{record_key}",
                description=str(detail),
            )
        ]
    records = payload.get(record_key) or []
    summarize = _RECORD_SUMMARY[evidence_kind]
    refs: list[EvidenceRef] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if target is not None and not _record_matches(record, target):
            continue
        refs.append(
            EvidenceRef(
                kind=evidence_kind,
                reference=f"device:{device_id}:{record_key}:{_record_id(record)}",
                description=summarize(record),
            )
        )
    return refs


def _record_matches(record: dict[str, Any], target: str) -> bool:
    """Whether *record* concerns the user-named *target* (peer/prefix/acl/id).

    Exact equality is used for IP addresses and prefixes to avoid false
    positives: '10.0.0.2' must not match '10.0.0.20' or '10.0.0.200'.
    For prefix matching a bare host address like '10.0.0.0' is allowed to
    match '10.0.0.0/24' (the needle matches the network part before '/').
    All other string fields (e.g. ACL name) also use exact equality.
    """
    needle = target.strip().lower()
    return any(
        isinstance(value, str)
        and (needle == value.lower() or value.lower().startswith(needle + "/"))
        for value in record.values()
    )


def _record_id(record: dict[str, Any]) -> str:
    """Pick a stable identifier from a normalized record for the evidence ref."""
    for key in ("peer_address", "neighbor_id", "prefix", "acl_name", "sequence"):
        value = record.get(key)
        if value is not None:
            return str(value)
    return "0"


def _compose_answer(classification: SymptomClassification, evidence: list[EvidenceRef]) -> str:
    """Compose a grounded answer that cites the gathered evidence.

    The answer is built *from* the evidence refs — it never asserts a cause the
    evidence does not show. When no evidence was gathered, it says so and names
    the gap, rather than guessing.
    """
    domain = classification.domain.value
    if not evidence:
        return f"I could not ground a {domain} diagnosis: no matching state was collected" + (
            f" for the named target {classification.target!r}." if classification.target else "."
        )
    cited = "; ".join(ref.description or ref.reference for ref in evidence)
    return f"Based on the collected {domain} evidence — {cited} — here is the diagnosis."


def _load_json(raw: object) -> dict[str, Any] | None:
    """Parse a tool's string output into a dict, or ``None`` if it is not JSON."""
    if isinstance(raw, dict):
        return cast("dict[str, Any]", raw)
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None
