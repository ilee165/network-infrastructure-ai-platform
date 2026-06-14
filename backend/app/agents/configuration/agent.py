"""Configuration Agent — read-only drift / compliance explanation (M4 task 9).

CLAUDE.md Core Agent #6 / MVP.md §6. The Configuration Agent *narrates* what a
device's configuration drift or compliance assessment means. It is strictly
read-only: every declared tool is
:attr:`~app.agents.framework.tools.ToolClassification.READ_ONLY`, and no
state-changing tool may ever appear on it (asserted by the tests and by
:meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`).
State-changing config push lands behind the M5 ChangeRequest workflow.

Secret boundary (A9 — ADR-0017 §3). Drift diffs and compliance findings are
computed **server-side over the raw, unredacted config** by
``engines/config_mgmt`` so a security-relevant change to a secret line is still
detected (fidelity over secrecy at the storage boundary). This agent sits at the
**LLM boundary**: it narrates only redacted results. The narration tools
(``configuration.tools``) run every config-derived fragment through
:func:`~app.llm.redaction.redact_prompt` before returning it, so no secret value
ever enters a model prompt — the redacting model wrapper would also strip it as
defence in depth.

Bespoke graph (overrides :meth:`BaseSpecialistAgent.build_graph`)
    Instead of a free ReAct loop, the agent runs an explicit
    ``classify -> narrate`` flow:

    1. **classify** — map the user's request onto one
       :class:`ConfigIntent` (explain_drift / assess_policy /
       summarize_compliance) and extract the target device / policy. The router
       is the injected LLM under structured output, deterministic under the
       scripted fake model used in tests.
    2. **narrate** — call the matching READ_ONLY tool with the server-computed
       drift/compliance result, record each redacted result as an
       :class:`~app.agents.framework.traces.EvidenceRef`, and compose a grounded
       answer *from* those refs (never from raw config) so the explanation is
       both grounded and secret-free.

The server-computed inputs (the drift diff, the compliance findings) are injected
into the agent instance — in production by the API/worker layer that already ran
the audited raw-content read; in tests directly. The agent never opens a DB
session or a transport itself, mirroring the engine/agent separation the rest of
the platform keeps (REPO-STRUCTURE §3.2).
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

from app.agents.configuration.tools import CONFIGURATION_TOOLS
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

#: String id of this agent — equals its package name (REPO-STRUCTURE §4.1).
CONFIGURATION_NAME = "configuration"


class ConfigIntent(StrEnum):
    """The configuration-narration task a request is classified into (MVP.md §6)."""

    EXPLAIN_DRIFT = "explain_drift"
    ASSESS_POLICY = "assess_policy"
    SUMMARIZE_COMPLIANCE = "summarize_compliance"


class ConfigRequest(BaseModel):
    """Structured output of the *classify* node.

    Maps a free-text request onto one :class:`ConfigIntent` plus the concrete
    entities a narration needs: the device under review and, for the compliance
    intents, the policy it was evaluated against.
    """

    intent: ConfigIntent = Field(description="Which configuration narration the request calls for.")
    device_id: str | None = Field(
        default=None,
        description="UUID of the device under review, if the user named one.",
    )
    policy_id: str | None = Field(
        default=None,
        description="Identifier of the compliance policy involved, if any.",
    )
    rationale: str = Field(
        default="",
        description="One-sentence explanation of the classification.",
    )


class ConfigurationState(MessagesState):
    """Graph state: the conversation plus the request/evidence/trace channels."""

    #: The request classification produced by the ``classify`` node; ``None``
    #: when the model failed to produce a parseable classification.
    request: ConfigRequest | None
    #: Evidence refs gathered (from the redacted tool output) by ``narrate``.
    evidence: list[EvidenceRef]
    #: This run's reasoning trace.
    trace: ReasoningTrace | None


#: Maps each intent to the narration tool that grounds its answer.
_INTENT_TOOL: dict[ConfigIntent, str] = {
    ConfigIntent.EXPLAIN_DRIFT: "explain_drift_diff",
    ConfigIntent.ASSESS_POLICY: "assess_device_vs_policy",
    ConfigIntent.SUMMARIZE_COMPLIANCE: "summarize_compliance_posture",
}


class ConfigurationAgent(BaseSpecialistAgent):
    """Read-only drift/compliance explanation specialist (CLAUDE.md Core Agent #6).

    Construct with the server-computed inputs to narrate (``drift_diff`` /
    ``has_drift`` for drift; ``findings`` for compliance) plus an optional
    :class:`TraceRecorder` so callers can inspect the redacted, evidence-grounded
    reasoning trace a run produces. The recorder is shared across runs of this
    instance, so tests build a fresh agent per run.
    """

    def __init__(
        self,
        *,
        trace_recorder: TraceRecorder | None = None,
        drift_diff: str = "",
        has_drift: bool = False,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        self._trace_recorder: TraceRecorder = (
            trace_recorder if trace_recorder is not None else InMemoryTraceRecorder()
        )
        self._drift_diff = drift_diff
        self._has_drift = has_drift
        self._findings: list[dict[str, Any]] = findings if findings is not None else []

    # ------------------------------------------------------------------
    # BaseSpecialistAgent contract
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return CONFIGURATION_NAME

    @property
    def description(self) -> str:
        return (
            "Explains configuration drift and compliance for managed devices: why a "
            "device's running config differs from its approved baseline (drift), and "
            "whether a device passes or violates a compliance policy and why. Route "
            "here when the user asks what changed in a device's configuration, why it "
            "drifted, or how it stands against a hardening/compliance policy "
            "(pass/violation, severity, which rule). This is NOT troubleshooting — it "
            "does not diagnose routing/BGP/OSPF/ACL faults or live control-plane "
            "problems; and it is NOT documentation — it does not generate inventories, "
            "diagrams, or runbooks. It narrates configuration state and compliance "
            "results only. All operations are read-only — no device configuration is "
            "changed (config push is gated behind change approval)."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Configuration Agent for an AI Network Operations Platform.\n\n"
            "You explain configuration drift (how a device's running config differs "
            "from its approved baseline) and compliance posture (whether a device "
            "passes or violates a policy, and why). You are strictly read-only: you "
            "never change device configuration.\n\n"
            "The drift diff and compliance findings you receive were computed "
            "server-side and are already redacted at the secret boundary — secret "
            "values appear only as <<REDACTED:...>> tokens. Never ask for, infer, or "
            "reconstruct a redacted secret value.\n\n"
            "Method:\n"
            "1. Classify the request into one task (explain_drift, assess_policy, "
            "summarize_compliance) and identify the device and any named policy.\n"
            "2. Narrate the server-computed result: cite the specific changed lines or "
            "the specific failing rules and their severity.\n"
            "3. Ground every statement in that result. Never guess — if the input is "
            "missing (no device named, no drift/findings available), say so plainly.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """The three READ_ONLY narration tools (drift / assess / posture)."""
        return CONFIGURATION_TOOLS

    # ------------------------------------------------------------------
    # Trace access
    # ------------------------------------------------------------------

    @property
    def trace_recorder(self) -> TraceRecorder:
        """The recorder a run's redacted, evidence-grounded trace is written to."""
        return self._trace_recorder

    # ------------------------------------------------------------------
    # Bespoke classify -> narrate graph
    # ------------------------------------------------------------------

    def build_graph(
        self, llm: BaseChatModel
    ) -> CompiledStateGraph[MessagesState, None, MessagesState, MessagesState]:
        """Compile the bespoke ``classify -> narrate`` subgraph.

        Overrides the default ReAct loop. The narration tool is resolved by name
        from :attr:`tools` at run time so a test can substitute a fake of the same
        name (the established offline-execution pattern). Every redacted result
        becomes an :class:`EvidenceRef`, and the final answer is composed from
        those refs so it is grounded and secret-free.
        """
        self.validate_definition()
        recorder = self._trace_recorder
        classifier = llm.with_structured_output(ConfigRequest)
        system_message = SystemMessage(content=self.system_prompt)

        def _resolve_tool(tool_name: str) -> NetOpsTool | None:
            for tool in self.tools:
                if tool.name == tool_name:
                    return tool
            return None

        async def classify(state: ConfigurationState) -> dict[str, Any]:
            """Classify the request and open the reasoning trace."""
            trace = await recorder.start(self.name)
            raw = await classifier.ainvoke([system_message, *state["messages"]])
            request = raw if isinstance(raw, ConfigRequest) else None
            if request is None:
                await recorder.record_step(
                    trace.trace_id,
                    TraceStep(
                        kind=TraceStepKind.PLAN,
                        summary=(
                            "could not classify the request into a configuration task "
                            "(explain_drift, assess_policy, or summarize_compliance)"
                        ),
                    ),
                )
                return {"request": None, "trace": trace, "evidence": []}
            await recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.PLAN,
                    summary=(
                        f"classified request as '{request.intent.value}'"
                        + (f" for device {request.device_id}" if request.device_id else "")
                    ),
                    detail=request.rationale or None,
                ),
            )
            return {"request": request, "trace": trace, "evidence": []}

        async def narrate(state: ConfigurationState) -> dict[str, Any]:
            """Call the matching tool and compose a grounded, redacted answer."""
            request = state["request"]
            trace = state["trace"]
            assert trace is not None  # noqa: S101 - classify always sets the trace
            evidence: list[EvidenceRef] = []
            completed = trace
            try:
                if request is None:
                    answer = (
                        "I could not classify your request into a configuration task "
                        "(explain drift, assess a policy, or summarize compliance "
                        "posture). Please name the device and what you want to know."
                    )
                elif request.device_id is None:
                    answer = (
                        "I need the device to review. Please name the device "
                        f"(by UUID) for the {request.intent.value} request."
                    )
                    await recorder.record_step(
                        trace.trace_id,
                        TraceStep(
                            kind=TraceStepKind.OBSERVATION,
                            summary="no device named; cannot ground a configuration narration",
                        ),
                    )
                else:
                    evidence, answer = await self._narrate_intent(
                        recorder=recorder,
                        trace=trace,
                        request=request,
                        resolve_tool=_resolve_tool,
                    )
                await recorder.record_step(
                    trace.trace_id,
                    TraceStep(
                        kind=TraceStepKind.CONCLUSION,
                        summary=answer,
                        evidence=evidence,
                    ),
                )
            finally:
                completed = await recorder.complete(trace.trace_id)
            return {"messages": [AIMessage(content=answer)], "trace": completed}

        graph: StateGraph[ConfigurationState, None, ConfigurationState, ConfigurationState] = (
            StateGraph(ConfigurationState)
        )
        graph.add_node("classify", classify)
        graph.add_node("narrate", narrate)
        graph.add_edge(START, "classify")
        graph.add_edge("classify", "narrate")
        graph.add_edge("narrate", END)
        return cast(
            "CompiledStateGraph[MessagesState, None, MessagesState, MessagesState]",
            graph.compile(name=self.name),
        )

    async def _narrate_intent(
        self,
        *,
        recorder: TraceRecorder,
        trace: ReasoningTrace,
        request: ConfigRequest,
        resolve_tool: Any,
    ) -> tuple[list[EvidenceRef], str]:
        """Run the intent's narration tool over redacted server output, grounded.

        Returns the evidence refs (built from the *redacted* tool output) and a
        grounded answer composed from them. No raw config text is ever read here:
        the tool already redacted every config-derived fragment (A9, ADR-0017 §3).
        """
        tool_name = _INTENT_TOOL[request.intent]
        tool = resolve_tool(tool_name)
        device_id = request.device_id
        assert device_id is not None  # noqa: S101 - caller guards device_id

        if tool is None:  # pragma: no cover - tools are always declared
            await recorder.record_step(
                trace.trace_id,
                TraceStep(
                    kind=TraceStepKind.OBSERVATION,
                    summary=f"no '{tool_name}' tool is available to narrate the result",
                ),
            )
            return [], f"I could not narrate: the '{tool_name}' tool is unavailable."

        if request.intent is ConfigIntent.EXPLAIN_DRIFT:
            args: dict[str, Any] = {
                "device_id": device_id,
                "has_drift": self._has_drift,
                "diff": self._drift_diff,
            }
        elif request.intent is ConfigIntent.ASSESS_POLICY:
            args = {
                "device_id": device_id,
                "policy_id": request.policy_id or "",
                "findings": self._findings,
            }
        else:  # SUMMARIZE_COMPLIANCE
            args = {"device_id": device_id, "findings": self._findings}

        raw = await tool.ainvoke(args)
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.TOOL_CALL,
                summary=f"narrated {request.intent.value} via '{tool_name}' (redacted)",
                tool_name=tool_name,
            ),
        )
        payload = json.loads(raw) if isinstance(raw, str) else raw
        evidence = _evidence_from_payload(request.intent, device_id, payload)
        await recorder.record_step(
            trace.trace_id,
            TraceStep(
                kind=TraceStepKind.OBSERVATION,
                summary=f"collected {len(evidence)} redacted evidence item(s) from '{tool_name}'",
                evidence=evidence,
            ),
        )
        return evidence, _compose_answer(request.intent, payload, evidence)


# ---------------------------------------------------------------------------
# Evidence extraction + grounded answer synthesis (over REDACTED tool output)
# ---------------------------------------------------------------------------


def _evidence_from_payload(
    intent: ConfigIntent, device_id: str, payload: dict[str, Any]
) -> list[EvidenceRef]:
    """Build evidence refs from a tool's already-redacted JSON payload.

    The payload was emitted by a narration tool that redacted every
    config-derived fragment, so every description here is secret-free by
    construction (ADR-0017 §3).
    """
    refs: list[EvidenceRef] = []
    if intent is ConfigIntent.EXPLAIN_DRIFT:
        if not payload.get("has_drift"):
            return [
                EvidenceRef(
                    kind="config_drift",
                    reference=f"device:{device_id}:drift",
                    description="no drift: current config matches the approved baseline",
                )
            ]
        for i, line in enumerate(payload.get("added", [])):
            refs.append(
                EvidenceRef(
                    kind="config_drift_added",
                    reference=f"device:{device_id}:drift:added:{i}",
                    description=f"added: {line}",
                )
            )
        for i, line in enumerate(payload.get("removed", [])):
            refs.append(
                EvidenceRef(
                    kind="config_drift_removed",
                    reference=f"device:{device_id}:drift:removed:{i}",
                    description=f"removed: {line}",
                )
            )
        return refs

    # Compliance intents: cite each finding (assess) or each offender (posture).
    findings = payload.get("findings") or payload.get("offenders") or []
    for finding in findings:
        rule_id = finding.get("rule_id", "?")
        refs.append(
            EvidenceRef(
                kind="compliance_finding",
                reference=f"device:{device_id}:rule:{rule_id}",
                description=(
                    f"{finding.get('status', '?')} [{finding.get('severity', '?')}] "
                    f"{rule_id}: {finding.get('evidence', '')}"
                ),
            )
        )
    return refs


def _compose_answer(
    intent: ConfigIntent, payload: dict[str, Any], evidence: list[EvidenceRef]
) -> str:
    """Compose a grounded answer from the redacted payload + evidence refs."""
    device_id = payload.get("device_id", "?")
    if intent is ConfigIntent.EXPLAIN_DRIFT:
        if not payload.get("has_drift"):
            return f"Device {device_id} shows no configuration drift from its approved baseline."
        cited = "; ".join(ref.description or ref.reference for ref in evidence)
        return (
            f"Device {device_id} has drifted from its approved baseline. "
            f"Changed lines (secrets redacted): {cited}."
        )
    if intent is ConfigIntent.SUMMARIZE_COMPLIANCE:
        posture = payload.get("posture", "unknown")
        counts = payload.get("counts", {})
        if posture == "compliant":
            return f"Device {device_id} is compliant: {counts}."
        cited = "; ".join(ref.description or ref.reference for ref in evidence)
        return (
            f"Device {device_id} compliance posture is '{posture}' ({counts}). "
            f"Offending rules (secrets redacted): {cited}."
        )
    # ASSESS_POLICY
    policy_id = payload.get("policy_id", "?")
    if not evidence:
        return f"No findings to report for device {device_id} against policy {policy_id}."
    cited = "; ".join(ref.description or ref.reference for ref in evidence)
    return (
        f"Assessment of device {device_id} against policy {policy_id} (secrets redacted): {cited}."
    )
