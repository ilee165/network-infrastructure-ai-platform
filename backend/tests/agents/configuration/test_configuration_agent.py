"""Tests for the Configuration Agent (M4 task 9, read-only, ADR-0017 §3).

Mandatory behaviours (task T9):

1. Read-only contract — every tool is READ_ONLY; no STATE_CHANGING (or
   DIAGNOSTIC) tool is ever declared on this agent (hard-reject gate).
2. Secret boundary (A9) — config content is secret-bearing. Every tool that
   narrates a drift diff or compliance evidence MUST redact the text through
   ``llm/redaction.py`` before returning it, so secrets never reach the model
   prompt. The leak test drives the whole graph against a recording mock model
   and asserts no secret pattern reaches it.
3. Offline determinism — the bespoke graph runs fully offline under
   ``ScriptedChatModel`` with no network and no DB.
4. Routing — the description sharply disambiguates from troubleshooting and
   documentation.
5. Registration — the package singleton registers cleanly.
"""

from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from app.agents.configuration import (
    ConfigurationAgent,
    configuration_agent,
    registry,
)
from app.agents.configuration.agent import (
    ConfigIntent,
    ConfigRequest,
)
from app.agents.configuration.agent import (
    ConfigurationAgent as _AgentImpl,
)
from app.agents.configuration.tools import (
    CONFIGURATION_TOOLS,
    assess_device_vs_policy,
    explain_drift_diff,
    summarize_compliance_posture,
)
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import NetOpsTool, ToolClassification
from app.agents.framework.traces import InMemoryTraceRecorder, TraceStepKind
from app.llm.redaction import REDACTION_TOKENS
from tests.agents.conftest import scripted_model

DEVICE_Y = "11111111-1111-1111-1111-111111111111"

# A unified diff that adds a security-relevant, secret-bearing line. The diff is
# computed server-side over the RAW config; the agent only narrates it (redacted).
_DRIFT_DIFF = "\n".join(
    [
        "--- baseline:0011aa22bb33",
        "+++ current:0044cc55dd66",
        "@@ -1,4 +1,5 @@",
        " hostname edge-1",
        " interface Gig0/0",
        "-snmp-server community OldRoComm RO",
        "+snmp-server community S3cr3tNewComm RO",
        "+enable secret 9 $9$nhEmQVczB7dqsO$X.NN.5KTHc.PmGwiL.S6/mQ.GW21Ek1dNXLm6F",
    ]
)

# Secret literals that must NEVER appear in any message handed to the model.
_SECRET_LITERALS = (
    "S3cr3tNewComm",
    "OldRoComm",
    "$9$nhEmQVczB7dqsO$X.NN.5KTHc.PmGwiL.S6/mQ.GW21Ek1dNXLm6F",
    "BgpPeerSecret",
    "MyEnablePass",
)

# Compliance findings whose evidence carries secret-bearing matched config lines.
_FINDINGS = [
    {
        "rule_id": "no-default-snmp",
        "severity": "violation",
        "status": "violation",
        "evidence": "snmp-server community S3cr3tNewComm RO",
    },
    {
        "rule_id": "bgp-auth-required",
        "severity": "warn",
        "status": "violation",
        "evidence": "neighbor 10.0.0.1 password BgpPeerSecret",
    },
    {
        "rule_id": "ntp-configured",
        "severity": "info",
        "status": "pass",
        "evidence": "ntp server 10.0.0.53",
    },
]


class RecordingModel:
    """A scripted chat model wrapper that retains every message it is asked to
    generate over, so the leak test can inspect exactly what reached the model.

    Implemented over :func:`scripted_model` so it tolerates tool binding and
    structured output the same way the rest of the agent tests do.
    """

    def __init__(self, replies: list[AIMessage]) -> None:
        self._inner = scripted_model(replies)
        self.seen: list[BaseMessage] = []

    def __getattr__(self, item: str):  # pragma: no cover - delegation glue
        return getattr(self._inner, item)

    def with_structured_output(self, schema, **kwargs):
        inner = self._inner.with_structured_output(schema, **kwargs)
        seen = self.seen

        class _Recording:
            async def ainvoke(self, messages, *a, **k):
                seen.extend(messages)
                return await inner.ainvoke(messages, *a, **k)

        return _Recording()

    def bind_tools(self, tools, **kwargs):  # pragma: no cover - not used here
        return self

    async def ainvoke(self, messages, *a, **k):
        self.seen.extend(messages)
        return await self._inner.ainvoke(messages, *a, **k)


def _request_reply(
    *, intent: str, device_id: str | None, policy_id: str | None = None
) -> AIMessage:
    """A scripted structured ``ConfigRequest`` (emitted as a tool call)."""
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "ConfigRequest",
                "args": {
                    "intent": intent,
                    "device_id": device_id,
                    "policy_id": policy_id,
                    "rationale": "scripted classification",
                },
                "id": "req-1",
            }
        ],
    )


def _make_agent(**kwargs) -> ConfigurationAgent:
    return ConfigurationAgent(**kwargs)


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestConfigurationIdentity:
    def test_name_is_configuration(self) -> None:
        assert _make_agent().name == "configuration"

    def test_description_non_empty_and_on_topic(self) -> None:
        desc = _make_agent().description.lower()
        assert desc.strip()
        assert "drift" in desc
        assert "complian" in desc

    def test_description_disambiguates_from_siblings(self) -> None:
        """The description must steer the router away from troubleshooting and
        documentation: it explains config drift/compliance, it does not diagnose
        control-plane faults nor generate documents."""
        desc = _make_agent().description.lower()
        assert "troubleshoot" in desc
        assert "document" in desc

    def test_system_prompt_non_empty(self) -> None:
        assert _make_agent().system_prompt.strip()

    def test_validate_definition_passes(self) -> None:
        _make_agent().validate_definition()


# ---------------------------------------------------------------------------
# Read-only contract — hard-reject of state-changing tools
# ---------------------------------------------------------------------------


class TestConfigurationToolClassification:
    def test_has_three_tools(self) -> None:
        names = {t.name for t in _make_agent().tools}
        assert names == {
            "explain_drift_diff",
            "assess_device_vs_policy",
            "summarize_compliance_posture",
        }

    def test_all_tools_read_only(self) -> None:
        for tool in _make_agent().tools:
            assert tool.classification is ToolClassification.READ_ONLY, (
                f"tool '{tool.name}' is {tool.classification}; all tools must be READ_ONLY"
            )

    def test_no_state_changing_tool_declared(self) -> None:
        offenders = [
            t.name
            for t in _make_agent().tools
            if t.classification is ToolClassification.STATE_CHANGING
        ]
        assert not offenders, f"STATE_CHANGING tools found: {offenders}"

    def test_no_diagnostic_tool_declared(self) -> None:
        offenders = [
            t.name for t in _make_agent().tools if t.classification is ToolClassification.DIAGNOSTIC
        ]
        assert not offenders, f"DIAGNOSTIC tools found: {offenders}"

    def test_all_tools_are_netops_tool(self) -> None:
        for tool in _make_agent().tools:
            assert isinstance(tool, NetOpsTool)


# ---------------------------------------------------------------------------
# Tool-level redaction — secrets never survive into the tool output
# ---------------------------------------------------------------------------


class TestToolRedaction:
    async def test_explain_drift_diff_redacts_secrets(self) -> None:
        raw = await explain_drift_diff.ainvoke(
            {"device_id": DEVICE_Y, "has_drift": True, "diff": _DRIFT_DIFF}
        )
        payload = json.loads(raw)
        blob = json.dumps(payload)
        for literal in _SECRET_LITERALS:
            assert literal not in blob, f"secret {literal!r} leaked into tool output"
        # The redaction tokens are present, so the model still sees a secret changed.
        assert REDACTION_TOKENS["snmp_community"] in blob
        assert REDACTION_TOKENS["cisco_type89"] in blob
        # Non-secret structure survives so the narration stays useful.
        assert "snmp-server community" in blob
        assert payload["has_drift"] is True

    async def test_explain_drift_diff_no_drift(self) -> None:
        raw = await explain_drift_diff.ainvoke(
            {"device_id": DEVICE_Y, "has_drift": False, "diff": ""}
        )
        payload = json.loads(raw)
        assert payload["has_drift"] is False

    async def test_assess_device_vs_policy_redacts_evidence(self) -> None:
        raw = await assess_device_vs_policy.ainvoke(
            {"device_id": DEVICE_Y, "policy_id": "baseline", "findings": _FINDINGS}
        )
        payload = json.loads(raw)
        blob = json.dumps(payload)
        for literal in _SECRET_LITERALS:
            assert literal not in blob, f"secret {literal!r} leaked into tool output"
        # Structure preserved: every finding keeps its rule/severity/status.
        rule_ids = {f["rule_id"] for f in payload["findings"]}
        assert {"no-default-snmp", "bgp-auth-required", "ntp-configured"} <= rule_ids

    async def test_summarize_compliance_posture_redacts_and_aggregates(self) -> None:
        raw = await summarize_compliance_posture.ainvoke(
            {"device_id": DEVICE_Y, "findings": _FINDINGS}
        )
        payload = json.loads(raw)
        blob = json.dumps(payload)
        for literal in _SECRET_LITERALS:
            assert literal not in blob, f"secret {literal!r} leaked into tool output"
        # Worst severity present is the device posture (ADR-0018 §3).
        assert payload["posture"] == "violation"
        assert payload["counts"]["violation"] == 2
        assert payload["counts"]["pass"] == 1


# ---------------------------------------------------------------------------
# Bespoke graph — grounded, redacted narration
# ---------------------------------------------------------------------------


class TestDriftNarration:
    async def test_graph_name_matches_agent(self) -> None:
        agent = _make_agent()
        graph = agent.build_graph(
            scripted_model([_request_reply(intent="explain_drift", device_id=None)])
        )
        assert graph.name == "configuration"

    async def test_explain_drift_produces_grounded_redacted_answer(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder, drift_diff=_DRIFT_DIFF, has_drift=True)
        llm = scripted_model([_request_reply(intent="explain_drift", device_id=DEVICE_Y)])
        result = await agent.build_graph(llm).ainvoke(
            {"messages": [HumanMessage(content=f"Explain config drift on {DEVICE_Y}")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        text = str(final.content)
        # The answer references the drift but never the raw secret.
        for literal in _SECRET_LITERALS:
            assert literal not in text, f"secret {literal!r} leaked into the answer"
        traces = recorder.list_traces()
        assert len(traces) == 1
        assert traces[0].is_complete
        kinds = [s.kind for s in traces[0].steps]
        assert TraceStepKind.PLAN in kinds
        assert TraceStepKind.TOOL_CALL in kinds
        assert TraceStepKind.CONCLUSION in kinds
        all_evidence = [ref for step in traces[0].steps for ref in step.evidence]
        assert all_evidence, "drift narration must be grounded in evidence refs"
        blob = " ".join(f"{r.kind} {r.reference} {r.description or ''}" for r in all_evidence)
        for literal in _SECRET_LITERALS:
            assert literal not in blob, f"secret {literal!r} leaked into evidence"


class TestComplianceNarration:
    async def test_compliance_posture_grounded_and_redacted(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder, findings=_FINDINGS)
        llm = scripted_model(
            [
                _request_reply(
                    intent="summarize_compliance", device_id=DEVICE_Y, policy_id="baseline"
                )
            ]
        )
        result = await agent.build_graph(llm).ainvoke(
            {"messages": [HumanMessage(content=f"Compliance posture for {DEVICE_Y}?")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        text = str(final.content)
        assert "violation" in text.lower()
        for literal in _SECRET_LITERALS:
            assert literal not in text

    async def test_assess_policy_grounded_and_redacted(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder, findings=_FINDINGS)
        llm = scripted_model(
            [_request_reply(intent="assess_policy", device_id=DEVICE_Y, policy_id="baseline")]
        )
        result = await agent.build_graph(llm).ainvoke(
            {"messages": [HumanMessage(content=f"Assess {DEVICE_Y} against baseline")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        for literal in _SECRET_LITERALS:
            assert literal not in str(final.content)


class TestDegradedPaths:
    async def test_unclassifiable_request_degrades_without_crashing(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder)
        llm = scripted_model([AIMessage(content="I am not sure what you want.")])
        result = await agent.build_graph(llm).ainvoke(
            {"messages": [HumanMessage(content="do the thing")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        assert "could not" in str(final.content).lower()
        assert recorder.list_traces()[0].is_complete

    async def test_no_device_named_yields_honest_answer(self) -> None:
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(trace_recorder=recorder, drift_diff=_DRIFT_DIFF, has_drift=True)
        llm = scripted_model([_request_reply(intent="explain_drift", device_id=None)])
        result = await agent.build_graph(llm).ainvoke(
            {"messages": [HumanMessage(content="explain drift")]}
        )
        final = result["messages"][-1]
        assert isinstance(final, AIMessage)
        assert "device" in str(final.content).lower()


# ---------------------------------------------------------------------------
# Leak test — the whole graph against a recording mock model (SECURITY-CRITICAL)
# ---------------------------------------------------------------------------


class TestNoSecretReachesProvider:
    async def test_no_secret_pattern_reaches_the_model(self) -> None:
        """Drive the full graph; assert no secret literal reaches the mock model.

        The recording model captures every message the agent hands the provider
        (classifier + any narration call). With the A9 redaction applied at the
        tool boundary, the model only ever sees redacted text.
        """
        recorder = InMemoryTraceRecorder()
        agent = _make_agent(
            trace_recorder=recorder,
            drift_diff=_DRIFT_DIFF,
            has_drift=True,
            findings=_FINDINGS,
        )
        model = RecordingModel([_request_reply(intent="explain_drift", device_id=DEVICE_Y)])
        await agent.build_graph(model).ainvoke(
            {"messages": [HumanMessage(content=f"why did {DEVICE_Y} drift")]}
        )
        seen_blob = "\n".join(str(m.content) for m in model.seen)
        for literal in _SECRET_LITERALS:
            assert literal not in seen_blob, f"SECRET LEAK: {literal!r} reached the model prompt"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestConfigurationRegistration:
    def test_package_singleton_type(self) -> None:
        assert isinstance(configuration_agent, _AgentImpl)

    def test_package_registry_contains_agent(self) -> None:
        assert "configuration" in registry

    def test_register_fresh_instance(self) -> None:
        fresh = AgentRegistry()
        fresh.register(_make_agent())
        assert "configuration" in fresh

    def test_double_register_conflicts(self) -> None:
        from app.core.errors import ConflictError

        fresh = AgentRegistry()
        fresh.register(_make_agent())
        with pytest.raises(ConflictError):
            fresh.register(_make_agent())

    def test_request_schema_round_trips(self) -> None:
        r = ConfigRequest(intent=ConfigIntent.EXPLAIN_DRIFT, device_id=DEVICE_Y)
        assert r.intent.value == "explain_drift"

    def test_tool_list_exported(self) -> None:
        assert {t.name for t in CONFIGURATION_TOOLS} == {
            "explain_drift_diff",
            "assess_device_vs_policy",
            "summarize_compliance_posture",
        }
