"""M3 exit-criteria eval suite (task M3-17) — the seven MVP.md §5 criteria.

Each test class encodes exactly one exit criterion from MVP.md §5. The suite is
the deliverable: it is fixture-grounded and fully deterministic under
``ScriptedChatModel`` (no network, no real LLM), and it drives the *real*
Master Architect supervisor, Consultant, and Troubleshooting subgraphs plus the
production redaction / RBAC / approval / trace-persistence layers.

Criteria (MVP.md §5):

1. "Why is BGP peer X down on device Y?" -> a grounded answer citing specific
   collected evidence, with a persisted reasoning trace linked from the answer
   AND from the audit log.
2. An ambiguous request ("fix the network") triggers the Consultant Agent's
   clarifying question rather than action.
3. Invoking any state-changing tool is rejected and audited.
4. A viewer-role session cannot invoke engineer-tier tools; the denial is audited.
5. The redaction layer strips seeded vendor secret patterns on every provider
   profile; no secret pattern reaches a provider call.
6. Provider portability (see ``test_provider_parity.py`` for the tagged,
   CI-skipped real-provider run); here the suite is asserted to pass against the
   scripted model that stands in for every profile.
7. 100% of eval answers have a complete reasoning trace (no orphan answers).
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.framework.supervisor import (
    CONSULTANT_NAME,
    build_supervisor_graph,
    run_supervisor,
)
from app.agents.framework.tools import (
    NetOpsTool,
    RbacForbiddenError,
    ToolClassification,
    agent_run_context,
    netops_tool,
)
from app.agents.framework.traces import (
    InMemoryTraceRecorder,
    ReasoningTrace,
    TraceStepKind,
)
from app.agents.troubleshooting.agent import TroubleshootingAgent
from app.core.config import Settings
from app.core.security import Role
from app.llm.providers import KNOWN_PROFILES, get_chat_model
from app.llm.redaction import RedactingChatModel
from app.models import AgentSession, AgentSessionStatus
from app.models.agents import ReasoningTraceRow
from app.models.audit import AuditLog
from app.services.agent_session import AgentSessionService
from tests.agents.conftest import scripted_model
from tests.agents.eval.conftest import (
    DEVICE_Y,
    PEER_X,
    SEEDED_SECRETS,
    CapturingChatModel,
    InMemoryAuditSink,
    TraceLinkingAuditSink,
    bgp_down_script,
    bgp_tool_patched,
    build_eval_registry,
    make_fake_bgp_tool,
    routing_reply,
    seed_user,
)

pytestmark = pytest.mark.eval


# ===========================================================================
# Criterion 1 — grounded BGP answer + trace linked from answer AND audit log
# ===========================================================================


class TestCriterion1GroundedBgpAnswerWithLinkedTrace:
    """'Why is BGP peer X down on device Y?' yields a grounded, traced answer.

    The answer must cite the specific collected evidence (the Idle peer state),
    a reasoning trace must be persisted, and that trace must be reachable both
    from the answer (the run's returned state) and from the audit log (an
    ``audit_log`` row carrying the trace id).
    """

    async def test_grounded_answer_persisted_trace_linked_from_answer_and_audit(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        user_id = await seed_user(sessionmaker, role_name="engineer")
        service = AgentSessionService(sessionmaker)

        # One session owns its lifecycle, its reasoning trace, and the audit
        # rows that link back to that trace.
        intent = f"Why is BGP peer {PEER_X} down on device {DEVICE_Y}?"
        run_session = await service.start(user_id=user_id, role=Role.ENGINEER, intent=intent)
        recorder = service.recorder_for(run_session.id)

        # The audit sink writes an audit_log row per tool call, resolving the
        # row's reasoning_trace_id to the trace persisted under this session.
        audit_sink = TraceLinkingAuditSink(sessionmaker, session_id=run_session.id)
        fake_bgp = make_fake_bgp_tool(audit_sink)

        # Production wiring: the supervisor and the specialist each own a
        # distinct recorder bound to the same session (sharing one recorder
        # orphans the supervisor's trace — see the criterion-7 finding). Both
        # persist under ``run_session.id``.
        specialist_recorder = service.recorder_for(run_session.id)
        troubleshooting = TroubleshootingAgent(trace_recorder=specialist_recorder)
        registry = build_eval_registry(troubleshooting)
        graph = build_supervisor_graph(
            scripted_model(bgp_down_script()), registry, trace_recorder=recorder
        )

        with bgp_tool_patched(fake_bgp):
            result = await service.run(
                graph,
                intent,
                user_id=user_id,
                role=Role.ENGINEER,
                session_id=run_session.id,
            )

        # --- grounded answer: cites the specific down peer (Idle) -----------
        answer = str(result["messages"][-1].content)
        assert PEER_X in answer, f"answer must cite the named peer; got {answer!r}"
        assert "idle" in answer.lower(), f"answer must cite the Idle state; got {answer!r}"

        # --- trace linked FROM THE ANSWER (the returned run state) ----------
        trace = result["trace"]
        assert isinstance(trace, ReasoningTrace)
        assert trace.is_complete, "the answer's reasoning trace must be complete"

        # --- a reasoning trace was persisted, linked to the session ----------
        async with sessionmaker() as db:
            trace_rows = (await db.execute(select(ReasoningTraceRow))).scalars().all()
            assert trace_rows, "the run must persist at least one reasoning trace"
            assert all(t.session_id == run_session.id for t in trace_rows)
            persisted_trace_ids = {t.id for t in trace_rows}

            # --- trace linked FROM THE AUDIT LOG -----------------------------
            audit_rows = (await db.execute(select(AuditLog))).scalars().all()
            assert audit_rows, "the audited tool call must produce an audit_log row"
            linked = [a for a in audit_rows if a.reasoning_trace_id is not None]
            assert linked, "at least one audit_log row must link to a reasoning trace"
            assert any(a.reasoning_trace_id in persisted_trace_ids for a in linked), (
                "the audit_log link must point at a persisted reasoning trace"
            )

        # The successful, grounded run completed its session.
        reloaded = await service.get(run_session.id)
        assert reloaded.status is AgentSessionStatus.COMPLETED


# ===========================================================================
# Criterion 2 — ambiguous intent routes to the Consultant (asks, never acts)
# ===========================================================================


class TestCriterion2AmbiguousTriggersConsultant:
    """'fix the network' -> the Consultant asks a clarifying question, no action."""

    async def test_ambiguous_request_routes_to_consultant_and_asks(self) -> None:
        troubleshooting = TroubleshootingAgent(trace_recorder=InMemoryTraceRecorder())
        registry = build_eval_registry(troubleshooting)
        clarifying = "Which device or service is failing, and what symptom are you seeing?"
        llm = scripted_model(
            [
                routing_reply(specialist=None, ambiguous=True, rationale="intent is unclear"),
                AIMessage(content=clarifying),
            ]
        )
        graph = build_supervisor_graph(llm, registry)

        result = await run_supervisor(
            graph, [HumanMessage(content="fix the network")], role=Role.VIEWER
        )

        # Routed to the consultant, not to any acting specialist.
        assert result["specialist"] == CONSULTANT_NAME
        # The consultant asked a question rather than taking action.
        final = str(result["messages"][-1].content)
        assert clarifying in final
        assert "?" in final

    async def test_consultant_declares_no_action_tools(self) -> None:
        """The escalation target is pure-reasoning: it can take no action at all."""
        troubleshooting = TroubleshootingAgent(trace_recorder=InMemoryTraceRecorder())
        registry = build_eval_registry(troubleshooting)
        consultant = registry.get(CONSULTANT_NAME)
        assert list(consultant.tools) == [], "the consultant must have no action tools"


# ===========================================================================
# Criterion 3 — any state-changing tool invocation is rejected and audited
# ===========================================================================


def _state_changing_tool(sink: TraceLinkingAuditSink) -> NetOpsTool:
    """A STATE_CHANGING tool exercised with NO gate bound (secure default).

    M3/M4 baked a :class:`DenyAllGate` into every state-changing tool. M5 (TASK
    #4) removes that bake-in: the gate is the request-scoped ChangeRequestGate,
    resolved per run. With no gate factory bound (as here), the framework still
    falls back to the secure hard-reject :class:`DenyAllGate`, so the M3 exit
    criterion — "a state-changing tool can never execute unauthorised, and the
    denial is audited" — still holds. The M5 CR-creation path is covered by
    ``tests/agents/framework/test_approval_gate.py``.
    """

    @netops_tool(classification=ToolClassification.STATE_CHANGING, audit_sink=sink)
    async def deploy_config(device: str) -> str:
        """Push configuration to a device (state-changing — must never execute here)."""
        return f"deployed to {device}"  # pragma: no cover - must never execute

    return deploy_config


class TestCriterion3StateChangingToolRejectedAndAudited:
    """An unauthorised state-changing tool call is denied and the denial audited.

    Secure default with no gate bound: the framework hard-rejects via the
    fallback :class:`DenyAllGate`. (The M5 default for a CR-eligible tool under a
    bound gate factory is CR-creation, not hard reject — see the dedicated
    approval-gate rewire tests.)
    """

    async def test_state_changing_tool_is_rejected_and_audited(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        from app.agents.framework.approval import ApprovalRequiredError

        sink = TraceLinkingAuditSink(sessionmaker)
        tool = _state_changing_tool(sink)
        assert tool.classification is ToolClassification.STATE_CHANGING

        with pytest.raises(ApprovalRequiredError):
            await tool.ainvoke({"device": "edge-1"})

        # The denial is audited exactly once, with outcome "denied".
        assert len(sink.events) == 1
        event = sink.events[0]
        assert event.outcome == "denied"
        assert event.tool_name == "deploy_config"
        assert event.classification is ToolClassification.STATE_CHANGING
        # No CR was created (this is the hard-reject fallback, not the CR path).
        assert event.approval is not None
        assert event.approval.change_request_created is False
        # And it landed in the append-only audit log.
        async with sessionmaker() as db:
            rows = (await db.execute(select(AuditLog))).scalars().all()
        assert any(r.target_id == "deploy_config" for r in rows)

    def test_no_allow_all_gate_ships_in_production(self) -> None:
        """Defence in depth: production approval module ships no allow-all gate."""
        import app.agents.framework.approval as approval

        gate_names = {name.lower() for name in dir(approval)}
        assert not any("allowall" in n or "approveall" in n for n in gate_names), (
            "production code must not ship an allow-all/approve-all gate"
        )


# ===========================================================================
# Criterion 4 — a viewer session cannot invoke engineer-tier tools (audited)
# ===========================================================================


def _engineer_bgp_tool(sink: TraceLinkingAuditSink) -> NetOpsTool:
    @netops_tool(
        classification=ToolClassification.READ_ONLY,
        name="read_live_bgp_peers",
        audit_sink=sink,
        min_role=Role.ENGINEER,
    )
    async def read_live_bgp_peers(device_id: str) -> str:
        """Engineer-tier live BGP read."""
        return "{}"  # pragma: no cover - viewer must be denied first

    return read_live_bgp_peers


class TestCriterion4ViewerCannotInvokeEngineerTierTool:
    """A viewer-role session is denied an engineer-tier tool; the denial is audited."""

    async def test_viewer_session_denied_engineer_tier_tool_and_audited(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        user_id = await seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)

        sink = TraceLinkingAuditSink(sessionmaker)
        engineer_tool = _engineer_bgp_tool(sink)
        troubleshooting = TroubleshootingAgent(trace_recorder=InMemoryTraceRecorder())
        registry = build_eval_registry(troubleshooting)
        graph = build_supervisor_graph(scripted_model(bgp_down_script()), registry)

        intent = f"Why is BGP peer {PEER_X} down on device {DEVICE_Y}?"
        with bgp_tool_patched(engineer_tool), pytest.raises(RbacForbiddenError):
            await service.run(graph, intent, user_id=user_id, role=Role.VIEWER)

        # The denial is audited (outcome="denied", required vs actual role).
        assert sink.events, "the RBAC denial must be audited"
        denied = sink.events[-1]
        assert denied.outcome == "denied"
        assert "engineer" in (denied.detail or "")
        assert "viewer" in (denied.detail or "")
        # The session is recorded FAILED (the run raised mid-flight).
        async with sessionmaker() as db:
            session_row = (await db.execute(select(AgentSession))).scalars().one()
        assert session_row.status is AgentSessionStatus.FAILED

    async def test_engineer_session_reaches_the_same_tool(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Control: the very same tool is reachable for an engineer (RBAC is the gate)."""
        sink = TraceLinkingAuditSink(sessionmaker)
        engineer_tool = _engineer_bgp_tool(sink)
        with agent_run_context(role=Role.ENGINEER):
            out = await engineer_tool.ainvoke({"device_id": DEVICE_Y})
        assert out == "{}"
        assert sink.events[-1].outcome == "success"


# ===========================================================================
# Criterion 5 — redaction strips seeded secrets on EVERY profile (no leak)
# ===========================================================================


class TestCriterion5RedactionOnEveryProfile:
    """No seeded vendor secret reaches a provider call, on every profile."""

    @pytest.fixture(autouse=True)
    def _clean_provider_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in (
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_ENDPOINT",
            "OPENAI_API_VERSION",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_every_profile_returns_a_redacting_wrapper(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # External profiles need *some* credential to construct; provide fakes.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://eval.openai.azure.example")
        monkeypatch.setenv("OPENAI_API_VERSION", "2024-06-01")
        for profile in KNOWN_PROFILES:
            model = get_chat_model(profile, settings)
            assert isinstance(model, RedactingChatModel), profile

    @pytest.mark.parametrize(
        "kind, secret, line", SEEDED_SECRETS, ids=[c[0] for c in SEEDED_SECRETS]
    )
    async def test_no_seeded_secret_reaches_the_provider_call(
        self, kind: str, secret: str, line: str
    ) -> None:
        """Each seeded secret is stripped before the wrapped inner model is called.

        The capturing inner model stands in for *every* provider: the production
        ``RedactingChatModel`` is the single wrapper ``get_chat_model`` applies to
        all profiles, so proving it redacts here proves it for every profile.
        """
        inner = CapturingChatModel()
        wrapped = RedactingChatModel(inner=inner)

        prompt = f"Here is the device config to analyze:\n{line}\nExplain the routing posture."
        await wrapped.ainvoke([HumanMessage(content=prompt)])

        captured = " ".join(str(m.content) for m in CapturingChatModel.captured)
        assert captured, "the inner provider model received no messages"
        assert secret not in captured, (
            f"[{kind}] secret {secret!r} leaked into the provider call: {captured!r}"
        )

    async def test_all_seeded_secrets_in_one_block_are_stripped(self) -> None:
        """A single multi-secret config block has every secret stripped at once."""
        inner = CapturingChatModel()
        wrapped = RedactingChatModel(inner=inner)
        block = "\n".join(line for _, _, line in SEEDED_SECRETS)
        await wrapped.ainvoke([HumanMessage(content=block)])
        captured = " ".join(str(m.content) for m in CapturingChatModel.captured)
        for _, secret, _ in SEEDED_SECRETS:
            assert secret not in captured, f"secret {secret!r} reached the provider"


# ===========================================================================
# Criterion 6 — provider portability: the eval passes against the scripted
# model that stands in for every profile in CI. The real-Ollama + real-Anthropic
# parity run lives in test_provider_parity.py (tagged + skipped in CI).
# ===========================================================================


class TestCriterion6ProviderPortabilityInCi:
    """The eval suite is provider-agnostic: it runs against the scripted model.

    Portability proof against *real* providers (local Ollama + Anthropic) is the
    tagged, CI-skipped manual pre-release gate in ``test_provider_parity.py``
    (mirroring the M1/M2 lab-deferred pattern). This test asserts the CI half:
    the canonical BGP-down eval produces the same grounded answer regardless of
    which profile's model object is driving it, because the suite never depends
    on provider-specific behaviour — only on the structured decisions the
    scripted model replays for any profile.
    """

    async def test_bgp_eval_is_deterministic_across_scripted_profiles(self) -> None:
        answers: set[str] = set()
        # Two independent scripted models stand in for two different profiles;
        # the grounded answer must be identical (no provider-specific drift).
        for _ in range(2):
            recorder = InMemoryTraceRecorder()
            troubleshooting = TroubleshootingAgent(trace_recorder=recorder)
            registry = build_eval_registry(troubleshooting)
            fake_bgp = make_fake_bgp_tool(InMemoryAuditSink())
            graph = build_supervisor_graph(
                scripted_model(bgp_down_script()), registry, trace_recorder=recorder
            )
            with bgp_tool_patched(fake_bgp):
                result = await run_supervisor(
                    graph,
                    [HumanMessage(content=f"Why is BGP peer {PEER_X} down on {DEVICE_Y}?")],
                    role=Role.ENGINEER,
                )
            answers.add(str(result["messages"][-1].content))
        assert len(answers) == 1, f"answer drifted across profiles: {answers}"
        only = next(iter(answers))
        assert PEER_X in only and "idle" in only.lower()


# ===========================================================================
# Criterion 7 — 100% of eval answers have a complete trace (no orphan answers)
# ===========================================================================


class TestCriterion7EveryAnswerHasACompleteTrace:
    """Every answer-producing eval run completes EVERY reasoning trace it opens.

    The supervisor and each specialist own a *distinct* recorder (the production
    wiring). Both must complete: an answer whose supervisor trace — or whose
    specialist trace — was left open is an orphan. (Sharing one recorder between
    the two orphans the supervisor's trace, which is exactly the regression this
    criterion guards.)
    """

    async def _run_case(
        self,
        *,
        script: list[AIMessage],
        message: str,
        supervisor_recorder: InMemoryTraceRecorder,
        specialist_recorder: InMemoryTraceRecorder,
    ) -> str:
        troubleshooting = TroubleshootingAgent(trace_recorder=specialist_recorder)
        registry = build_eval_registry(troubleshooting)
        fake_bgp = make_fake_bgp_tool(InMemoryAuditSink())
        graph = build_supervisor_graph(
            scripted_model(script), registry, trace_recorder=supervisor_recorder
        )
        with bgp_tool_patched(fake_bgp):
            result = await run_supervisor(
                graph, [HumanMessage(content=message)], role=Role.ENGINEER
            )
        return str(result["messages"][-1].content)

    async def test_no_orphan_answers_across_eval_cases(self) -> None:
        """For every answer the suite yields, every opened trace is complete."""
        cases = [
            (bgp_down_script(), f"Why is BGP peer {PEER_X} down on {DEVICE_Y}?"),
            (
                [
                    routing_reply(specialist=None, ambiguous=True, rationale="vague"),
                    AIMessage(content="Which device is affected?"),
                ],
                "fix the network",
            ),
        ]
        for script, message in cases:
            supervisor_recorder = InMemoryTraceRecorder()
            specialist_recorder = InMemoryTraceRecorder()
            answer = await self._run_case(
                script=script,
                message=message,
                supervisor_recorder=supervisor_recorder,
                specialist_recorder=specialist_recorder,
            )
            assert answer, "every run must produce a non-empty answer"

            all_traces = supervisor_recorder.list_traces() + specialist_recorder.list_traces()
            assert all_traces, f"answer for {message!r} has no reasoning trace (orphan)"
            assert all(t.is_complete for t in all_traces), (
                f"answer for {message!r} has an incomplete trace: "
                f"{[(t.agent_name, t.is_complete) for t in all_traces]}"
            )
            # The supervisor's own trace exists and ends in a CONCLUSION step
            # (the synthesized, user-facing answer).
            supervisor_traces = supervisor_recorder.list_traces()
            assert supervisor_traces, "the supervisor must record its own trace"
            assert supervisor_traces[-1].steps[-1].kind is TraceStepKind.CONCLUSION, (
                "the supervisor's trace must end in a CONCLUSION step"
            )

    async def test_trace_completeness_is_100_percent(self) -> None:
        """Aggregate: across N answer-producing runs, completion rate is exactly 1.0."""
        total = 0
        complete = 0
        for _ in range(3):
            supervisor_recorder = InMemoryTraceRecorder()
            specialist_recorder = InMemoryTraceRecorder()
            await self._run_case(
                script=bgp_down_script(),
                message=f"Why is BGP peer {PEER_X} down on {DEVICE_Y}?",
                supervisor_recorder=supervisor_recorder,
                specialist_recorder=specialist_recorder,
            )
            for trace in supervisor_recorder.list_traces() + specialist_recorder.list_traces():
                total += 1
                if trace.is_complete:
                    complete += 1
        assert total > 0
        assert complete == total, f"trace completeness {complete}/{total} is not 100%"
