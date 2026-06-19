"""Automation Agent: sole executor of approved ChangeRequests (M5 task #9).

The Automation Agent is the single, most security-critical executor in the
project (M5-PLAN risk #1). These tests pin the mandated behaviour:

1. **Refusal of every non-``approved`` state.** The executor runs ONLY a CR in
   ``approved``; for every other lifecycle state (draft, pending_approval,
   rejected/back-to-draft, executing, completed, failed, rolled_back) it
   refuses, performs no device/DDI write, leaves the CR state untouched, and
   audits the refusal.
2. **Happy path:** ``approved -> executing -> completed`` with the config
   capability's ``ChangeResult`` recorded as ``after_state`` and every step
   audited with a reasoning-trace link.
3. **Failure path:** an apply that fails drives ``approved -> executing ->
   failed`` and, when the structured rollback succeeds, ``failed ->
   rolled_back`` — never silently closed.
4. **Four-eyes cannot be bypassed by the executor.** The agent never calls
   ``approve``; a self-approved-looking CR can only reach ``approved`` through
   the server-side four-eyes guard, and the executor refuses to fabricate the
   ``approved`` state. The post-approval ``mark_*`` handoffs additionally require
   the verified :data:`AUTOMATION_PRINCIPAL`, so a foreign principal cannot drive
   execution.

Offline-first: an in-memory aiosqlite engine with the full model schema, scripted
config/DDI executors (no transport, no real device), and the in-memory trace
recorder. No Postgres/Docker/network.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.automation import AutomationAgent, automation_agent, registry
from app.agents.automation.agent import AUTOMATION_NAME, ChangeExecutionRefused
from app.agents.automation.executors import (
    ConfigChangeExecutor,
    DdiChangeExecutor,
    DdiChangeResult,
)
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import ToolClassification
from app.agents.framework.traces import InMemoryTraceRecorder, TraceStepKind
from app.core.security import Role
from app.models import (
    AuditLog,
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    User,
)
from app.models import Role as RoleRow
from app.plugins.base import ChangeOutcome, ChangePlan, ChangeRequestDraft, ChangeResult, WapiVerb
from app.services.audit import service as audit_service
from app.services.change_requests import ChangeRequestService

DEVICE_ID = "22222222-2222-2222-2222-222222222222"

# A config fragment that carries a secret-bearing line (the kind the executor must
# never surface to an LLM un-redacted).
_SECRET_FRAGMENT = "snmp-server community S3cr3tComm RO\nntp server 10.0.0.1"
_SECRET_LITERAL = "S3cr3tComm"


# ---------------------------------------------------------------------------
# Fixtures: in-memory DB, sessionmaker, CR service, seeded users
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full model schema + FK enforcement."""
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
def service(sessionmaker: async_sessionmaker[AsyncSession]) -> ChangeRequestService:
    return ChangeRequestService(sessionmaker)


async def _seed_user(maker: async_sessionmaker[AsyncSession], *, role_name: str) -> uuid.UUID:
    async with maker() as session:
        role = RoleRow(name=f"{role_name}-{uuid.uuid4().hex[:8]}")
        session.add(role)
        await session.flush()
        user = User(
            username=f"user-{uuid.uuid4().hex[:8]}",
            password_hash="x",
            role_id=role.id,
        )
        session.add(user)
        await session.commit()
        return user.id


async def _audit_rows(maker: async_sessionmaker[AsyncSession], cr_id: uuid.UUID) -> list[AuditLog]:
    async with maker() as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.target_id == str(cr_id))
                    .order_by(AuditLog.created_at)
                )
            )
            .scalars()
            .all()
        )
        return list(rows)


# ---------------------------------------------------------------------------
# Scripted executor ports (stand in for the plugin write paths, no transport)
# ---------------------------------------------------------------------------


class _ScriptedConfigExecutor:
    """A ``ConfigChangeExecutor`` that returns a pre-scripted ``ChangeResult``.

    Records the plan it was handed so a test can assert the executor passed an
    ``executing`` ChangePlan (never self-authorizing) and that the secret config
    fragment reached the device path verbatim while never reaching the LLM.
    """

    def __init__(self, result_factory: Any) -> None:
        self._result_factory = result_factory
        self.calls: list[tuple[ChangeRequest, ChangePlan]] = []

    async def apply(self, cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
        self.calls.append((cr, plan))
        return self._result_factory(cr, plan)


class _ScriptedDdiExecutor:
    """A ``DdiChangeExecutor`` that returns a pre-scripted ``DdiChangeResult``."""

    def __init__(self, result_factory: Any) -> None:
        self._result_factory = result_factory
        self.calls: list[tuple[ChangeRequest, ChangeRequestDraft]] = []

    async def apply(self, cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
        self.calls.append((cr, draft))
        return self._result_factory(cr, draft)


def _applied_result(cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
    return ChangeResult(
        change_request_id=cr.id,
        outcome=ChangeOutcome.APPLIED,
        verified=True,
        applied_diff=("+2 lines", "-0 lines"),
        rollback=None,
    )


def _rolled_back_result(cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
    from app.plugins.base import RollbackResult

    return ChangeResult(
        change_request_id=cr.id,
        outcome=ChangeOutcome.ROLLED_BACK,
        verified=False,
        applied_diff=(),
        rollback=RollbackResult(
            attempted=True, succeeded=True, verified=True, detail="restored baseline"
        ),
    )


def _config_agent(
    service: ChangeRequestService,
    *,
    config_executor: ConfigChangeExecutor | None = None,
    ddi_executor: DdiChangeExecutor | None = None,
    recorder: InMemoryTraceRecorder | None = None,
) -> AutomationAgent:
    return AutomationAgent(
        change_request_service=service,
        config_executor=config_executor,
        ddi_executor=ddi_executor,
        trace_recorder=recorder if recorder is not None else InMemoryTraceRecorder(),
    )


async def _approved_config_cr(
    service: ChangeRequestService,
    maker: async_sessionmaker[AsyncSession],
    *,
    fragment: str = _SECRET_FRAGMENT,
) -> ChangeRequest:
    """Author -> submit -> approve (by a *different* engineer) a config CR."""
    requester = await _seed_user(maker, role_name="engineer")
    approver = await _seed_user(maker, role_name="engineer")
    cr = await service.create_draft(
        requester_id=requester,
        actor_role=Role.ENGINEER,
        kind=ChangeRequestKind.CONFIG,
        payload={"capability": "config_deploy", "fragment": fragment},
        target_refs={"device_id": DEVICE_ID},
        rollback_plan={"baseline_content_hash": "abc123"},
        before_state={"config_hash": "old"},
        reasoning_trace_id=uuid.uuid4(),
    )
    await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
    await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)
    return await service.get(cr.id)


async def _approved_ddi_cr(
    service: ChangeRequestService,
    maker: async_sessionmaker[AsyncSession],
    *,
    payload: dict[str, Any] | None = None,
) -> ChangeRequest:
    """Author -> submit -> approve (by a *different* engineer) a DDI_RECORD CR.

    Defaults to a well-formed ``record:a`` create draft (with the ``inverse`` the
    structured rollback needs); pass *payload* to author a malformed draft.
    """
    requester = await _seed_user(maker, role_name="engineer")
    approver = await _seed_user(maker, role_name="engineer")
    if payload is None:
        payload = {
            "verb": "create",
            "wapi_object": "record:a",
            "body": [["name", "host.example.com"], ["ipv4addr", "10.0.0.5"]],
            "summary": "add A record host.example.com",
            "inverse": {
                "verb": "delete",
                "wapi_object": "record:a",
                "object_ref": "record:a/ZG5z:host",
                "summary": "delete A record host.example.com",
            },
        }
    cr = await service.create_draft(
        requester_id=requester,
        actor_role=Role.ENGINEER,
        kind=ChangeRequestKind.DDI_RECORD,
        payload=payload,
        target_refs={"object_ref": "record:a/ZG5z:host"},
    )
    await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
    await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)
    return await service.get(cr.id)


# ---------------------------------------------------------------------------
# 1. Definition / registration / read-only tool contract
# ---------------------------------------------------------------------------


class TestDefinition:
    def test_name_and_validate(self) -> None:
        agent = AutomationAgent(change_request_service=None)  # type: ignore[arg-type]
        assert agent.name == AUTOMATION_NAME == "automation"
        agent.validate_definition()  # must not raise

    def test_tools_are_read_only(self) -> None:
        """No STATE_CHANGING tool may ever appear on the agent surface — the
        write path is the deterministic executor, gated server-side, never a
        model-invocable tool (M5-PLAN risk #4: a 'change X' must never route to
        direct execution)."""
        agent = AutomationAgent(change_request_service=None)  # type: ignore[arg-type]
        for tool in agent.tools:
            assert tool.classification is ToolClassification.READ_ONLY

    def test_registration(self) -> None:
        assert isinstance(registry, AgentRegistry)
        assert registry.get(AUTOMATION_NAME) is automation_agent

    def test_description_disambiguates(self) -> None:
        desc = automation_agent.description.lower()
        assert "approved" in desc
        assert "change request" in desc or "changerequest" in desc


# ---------------------------------------------------------------------------
# 2. Refusal of every non-approved state
# ---------------------------------------------------------------------------


class TestRefusesNonApproved:
    @pytest.mark.parametrize(
        "state",
        [
            ChangeRequestState.DRAFT,
            ChangeRequestState.PENDING_APPROVAL,
            ChangeRequestState.EXECUTING,
            ChangeRequestState.COMPLETED,
            ChangeRequestState.FAILED,
            ChangeRequestState.ROLLED_BACK,
        ],
    )
    async def test_refuses_and_does_not_write(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        state: ChangeRequestState,
    ) -> None:
        """For every non-approved state: refuse, no write, state unchanged, audited."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        # Author a CR then force it into the target state directly in the DB so we
        # can exercise the executor against each lifecycle state in isolation.
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"capability": "config_deploy", "fragment": _SECRET_FRAGMENT},
            target_refs={"device_id": DEVICE_ID},
        )
        async with sessionmaker() as session:
            row = await session.get(ChangeRequest, cr.id)
            assert row is not None
            row.state = state
            await session.commit()

        config_exec = _ScriptedConfigExecutor(_applied_result)
        agent = _config_agent(service, config_executor=config_exec)

        with pytest.raises(ChangeExecutionRefused):
            await agent.execute(cr.id)

        # No device write happened.
        assert config_exec.calls == []
        # State is untouched.
        after = await service.get(cr.id)
        assert after.state is state
        # The refusal is audited.
        actions = {row.action for row in await _audit_rows(sessionmaker, cr.id)}
        assert audit_service.AUTOMATION_EXECUTION_REFUSED in actions

    async def test_rejected_back_to_draft_is_refused(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A CR that was rejected (pending_approval -> draft) is in ``draft`` and
        must be refused — the executor never runs a withdrawn change."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"capability": "config_deploy", "fragment": _SECRET_FRAGMENT},
            target_refs={"device_id": DEVICE_ID},
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.reject(cr.id, actor_id=approver, actor_role=Role.ENGINEER)
        assert (await service.get(cr.id)).state is ChangeRequestState.DRAFT

        config_exec = _ScriptedConfigExecutor(_applied_result)
        agent = _config_agent(service, config_executor=config_exec)
        with pytest.raises(ChangeExecutionRefused):
            await agent.execute(cr.id)
        assert config_exec.calls == []


# ---------------------------------------------------------------------------
# 3. Happy path: approved -> executing -> completed
# ---------------------------------------------------------------------------


class TestHappyPath:
    async def test_config_execute_to_completed(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        cr = await _approved_config_cr(service, sessionmaker)
        recorder = InMemoryTraceRecorder()
        config_exec = _ScriptedConfigExecutor(_applied_result)
        agent = _config_agent(service, config_executor=config_exec, recorder=recorder)

        result = await agent.execute(cr.id)

        # Terminal state is completed.
        final = await service.get(cr.id)
        assert final.state is ChangeRequestState.COMPLETED
        assert result.state is ChangeRequestState.COMPLETED

        # The executor was handed an *executing* plan (never self-authorizing).
        assert len(config_exec.calls) == 1
        _, plan = config_exec.calls[0]
        assert plan.is_executing
        assert plan.change_request_id == cr.id

        # The audit chain records the start, the apply, and the terminal transition.
        actions = [row.action for row in await _audit_rows(sessionmaker, cr.id)]
        assert audit_service.CHANGE_REQUEST_APPROVED_TO_EXECUTING in actions
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_COMPLETED in actions
        assert audit_service.AUTOMATION_CHANGE_APPLIED in actions

        # The terminal transition carries the reasoning-trace link (every action
        # is tied to a reasoning trace, brief §6 / ADR-0020 §4).
        terminal = next(
            row
            for row in await _audit_rows(sessionmaker, cr.id)
            if row.action == audit_service.CHANGE_REQUEST_EXECUTING_TO_COMPLETED
        )
        assert terminal.reasoning_trace_id is not None

        # The reasoning trace was completed with a conclusion step.
        traces = recorder.list_traces()
        assert len(traces) == 1
        assert traces[0].is_complete
        kinds = {step.kind for step in traces[0].steps}
        assert TraceStepKind.CONCLUSION in kinds

    async def test_ddi_execute_to_completed(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.DDI_RECORD,
            payload={
                "verb": "create",
                "wapi_object": "record:a",
                "body": [["name", "host.example.com"], ["ipv4addr", "10.0.0.5"]],
                "summary": "add A record host.example.com",
                "inverse": {
                    "verb": "delete",
                    "wapi_object": "record:a",
                    "object_ref": "record:a/ZG5z:host",
                    "summary": "delete A record host.example.com",
                },
            },
            target_refs={"object_ref": "record:a/ZG5z:host"},
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        def _ddi_ok(cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
            assert draft.verb is WapiVerb.CREATE
            return DdiChangeResult(verified=True, object_ref="record:a/new", rolled_back=False)

        ddi_exec = _ScriptedDdiExecutor(_ddi_ok)
        agent = _config_agent(service, ddi_executor=ddi_exec)
        await agent.execute(cr.id)

        assert (await service.get(cr.id)).state is ChangeRequestState.COMPLETED
        assert len(ddi_exec.calls) == 1


# ---------------------------------------------------------------------------
# 4. Failure path: approved -> executing -> failed -> rolled_back
# ---------------------------------------------------------------------------


class TestFailurePath:
    async def test_config_failure_rolls_back(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        cr = await _approved_config_cr(service, sessionmaker)
        config_exec = _ScriptedConfigExecutor(_rolled_back_result)
        agent = _config_agent(service, config_executor=config_exec)

        result = await agent.execute(cr.id)

        final = await service.get(cr.id)
        assert final.state is ChangeRequestState.ROLLED_BACK
        assert result.state is ChangeRequestState.ROLLED_BACK

        actions = [row.action for row in await _audit_rows(sessionmaker, cr.id)]
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_FAILED in actions
        assert audit_service.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK in actions
        assert audit_service.AUTOMATION_ROLLBACK in actions
        # Never completed.
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_COMPLETED not in actions

    async def test_rollback_failed_stays_failed(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """ADR-0021 §3: a rollback that cannot reach the baseline leaves the CR
        ``failed`` and raises an operator alert — never reported ``rolled_back``."""
        from app.plugins.base import RollbackResult

        def _rollback_failed(cr: ChangeRequest, plan: ChangePlan) -> ChangeResult:
            return ChangeResult(
                change_request_id=cr.id,
                outcome=ChangeOutcome.ROLLBACK_FAILED,
                verified=False,
                applied_diff=(),
                rollback=RollbackResult(
                    attempted=True, succeeded=False, verified=False, detail="unreachable"
                ),
            )

        cr = await _approved_config_cr(service, sessionmaker)
        config_exec = _ScriptedConfigExecutor(_rollback_failed)
        agent = _config_agent(service, config_executor=config_exec)

        result = await agent.execute(cr.id)

        final = await service.get(cr.id)
        assert final.state is ChangeRequestState.FAILED
        assert result.state is ChangeRequestState.FAILED

        actions = [row.action for row in await _audit_rows(sessionmaker, cr.id)]
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_FAILED in actions
        assert audit_service.AUTOMATION_ROLLBACK_FAILED in actions
        assert audit_service.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK not in actions

    async def test_ddi_failure_rolls_back(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A DDI apply whose post-write re-read fails but whose structured inverse
        restored the prior state maps (``_ddi_outcome``) to ``ROLLED_BACK`` and drives
        ``approved -> executing -> failed -> rolled_back`` — never completed."""

        def _ddi_rolled_back(cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
            # The inverse draft must coerce on the failure branch too (recursive
            # tuple coercion of ``inverse.body`` in _coerce_draft).
            assert draft.inverse is not None
            assert draft.inverse.verb is WapiVerb.DELETE
            return DdiChangeResult(
                verified=False,
                object_ref="record:a/ZG5z:host",
                rolled_back=True,
                rollback_attempted=True,
                rollback_verified=True,
            )

        cr = await _approved_ddi_cr(service, sessionmaker)
        ddi_exec = _ScriptedDdiExecutor(_ddi_rolled_back)
        agent = _config_agent(service, ddi_executor=ddi_exec)

        result = await agent.execute(cr.id)

        final = await service.get(cr.id)
        assert final.state is ChangeRequestState.ROLLED_BACK
        assert result.state is ChangeRequestState.ROLLED_BACK
        assert len(ddi_exec.calls) == 1

        actions = [row.action for row in await _audit_rows(sessionmaker, cr.id)]
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_FAILED in actions
        assert audit_service.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK in actions
        assert audit_service.AUTOMATION_ROLLBACK in actions
        # Never completed.
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_COMPLETED not in actions

    async def test_ddi_rollback_failed_stays_failed(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """ADR-0021 §3 for DDI: a write whose inverse could not restore the baseline
        (``rolled_back`` false or ``rollback_verified`` false) maps to
        ``ROLLBACK_FAILED``, leaves the CR ``failed``, and raises the operator alert —
        never reported ``rolled_back``."""

        def _ddi_rollback_failed(cr: ChangeRequest, draft: ChangeRequestDraft) -> DdiChangeResult:
            return DdiChangeResult(
                verified=False,
                object_ref="record:a/ZG5z:host",
                rolled_back=False,
                rollback_attempted=True,
                rollback_verified=False,
                detail="inverse could not restore prior state",
            )

        cr = await _approved_ddi_cr(service, sessionmaker)
        ddi_exec = _ScriptedDdiExecutor(_ddi_rollback_failed)
        agent = _config_agent(service, ddi_executor=ddi_exec)

        result = await agent.execute(cr.id)

        final = await service.get(cr.id)
        assert final.state is ChangeRequestState.FAILED
        assert result.state is ChangeRequestState.FAILED
        assert len(ddi_exec.calls) == 1

        actions = [row.action for row in await _audit_rows(sessionmaker, cr.id)]
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_FAILED in actions
        assert audit_service.AUTOMATION_ROLLBACK_FAILED in actions
        assert audit_service.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK not in actions

    async def test_malformed_ddi_payload_fails_no_executor(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A DDI CR whose payload is not a well-formed draft (``_draft_from_payload``
        returns ``None``) fails closed via ``_fail_no_executor``: the executor is never
        called, the CR is left ``failed``, and the failure is audited — no half-run."""
        cr = await _approved_ddi_cr(
            service,
            sessionmaker,
            payload={"summary": "missing verb/wapi_object — not a draft"},
        )
        ddi_exec = _ScriptedDdiExecutor(
            lambda cr, draft: DdiChangeResult(verified=True, object_ref="x")
        )
        agent = _config_agent(service, ddi_executor=ddi_exec)

        result = await agent.execute(cr.id)

        final = await service.get(cr.id)
        assert final.state is ChangeRequestState.FAILED
        assert result.state is ChangeRequestState.FAILED
        # The malformed payload never reached the executor (fail closed).
        assert ddi_exec.calls == []

        actions = [row.action for row in await _audit_rows(sessionmaker, cr.id)]
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_FAILED in actions
        assert audit_service.AUTOMATION_ROLLBACK_FAILED in actions
        assert audit_service.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK not in actions
        assert audit_service.CHANGE_REQUEST_EXECUTING_TO_COMPLETED not in actions


# ---------------------------------------------------------------------------
# 5. Four-eyes cannot be bypassed by the executor
# ---------------------------------------------------------------------------


class TestFourEyesNotBypassable:
    async def test_executor_never_calls_approve(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """A four-eyes-required CR still pending_approval (requester == only actor)
        cannot be pushed to execution by the agent: the agent never approves, and
        it refuses any non-approved CR. The only path to ``approved`` is the
        server-side four-eyes guard with a *different* approver."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"capability": "config_deploy", "fragment": _SECRET_FRAGMENT},
            target_refs={"device_id": DEVICE_ID},
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        assert (await service.get(cr.id)).state is ChangeRequestState.PENDING_APPROVAL

        config_exec = _ScriptedConfigExecutor(_applied_result)
        agent = _config_agent(service, config_executor=config_exec)
        with pytest.raises(ChangeExecutionRefused):
            await agent.execute(cr.id)

        # No approval row was ever created by the executor, no write happened, and
        # the CR is still pending_approval.
        assert config_exec.calls == []
        assert (await service.get(cr.id)).state is ChangeRequestState.PENDING_APPROVAL

    async def test_foreign_principal_cannot_drive_lifecycle(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """The post-approval ``mark_*`` handoffs require the verified
        AUTOMATION_PRINCIPAL; an agent wired with a forged principal cannot claim
        the CR (defense-in-depth on the executor identity, ADR-0020 §2)."""
        from app.services.change_requests import AutomationPrincipal

        cr = await _approved_config_cr(service, sessionmaker)
        config_exec = _ScriptedConfigExecutor(_applied_result)
        agent = AutomationAgent(
            change_request_service=service,
            config_executor=config_exec,
            principal=AutomationPrincipal(actor="agent:impostor"),
        )
        with pytest.raises(Exception):  # noqa: B017 - ForbiddenError from the service guard
            await agent.execute(cr.id)
        # The CR never left approved and no write happened.
        assert (await service.get(cr.id)).state is ChangeRequestState.APPROVED
        assert config_exec.calls == []


# ---------------------------------------------------------------------------
# 6. A9 redaction: no secret reaches a narration / audit detail
# ---------------------------------------------------------------------------


class TestRedaction:
    async def test_summary_tool_redacts_config_content(self) -> None:
        from app.agents.automation.tools import summarize_change_request

        raw = await summarize_change_request.ainvoke(
            {
                "change_request_id": "cr-1",
                "kind": "config",
                "summary": "deploy fragment",
                "content": _SECRET_FRAGMENT,
            }
        )
        assert _SECRET_LITERAL not in raw
        assert "<<REDACTED:" in raw

    async def test_audit_detail_carries_no_secret(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        """No audit row for the run may carry the raw secret fragment — the CR
        ``payload`` is never echoed into ``detail`` (ADR-0020 §4)."""
        cr = await _approved_config_cr(service, sessionmaker)
        agent = _config_agent(service, config_executor=_ScriptedConfigExecutor(_applied_result))
        await agent.execute(cr.id)
        for row in await _audit_rows(sessionmaker, cr.id):
            assert _SECRET_LITERAL not in repr(row.detail)
