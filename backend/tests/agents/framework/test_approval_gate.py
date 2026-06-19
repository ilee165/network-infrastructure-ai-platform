"""M5 framework approval-gate rewire (TASK #4, ADR-0020 §ref, M5-PLAN task #4).

The M3/M4 gate hard-rejected every state-changing tool (``DenyAllGate``) with an
audit entry. M5 rewires it: a state-changing tool invocation now CREATES a
``ChangeRequest`` *draft* via the Wave-2 #3 :class:`ChangeRequestService` and the
tool returns that CR (id/state) to the agent/user instead of executing. Execution
remains impossible outside an approved CR — only the Automation Agent (Wave 4)
executes an *approved* CR, never a tool directly.

These tests assert the rewired behaviour end-to-end against a real
``ChangeRequestService`` over in-memory SQLite (offline-first, no Docker):

* a state-changing tool now yields a :class:`ChangeRequestCreated` draft — NOT a
  hard reject — and the call is audited (``denied`` outcome, the change did not
  run; the persistent ``change_request.created`` row is written by the service);
* the tool body never executes (a non-approved CR cannot drive execution);
* the A9 redaction layer scrubs config/DNS secrets out of the captured payload
  before it is stored on the CR;
* RBAC inheritance holds — an agent run bound below ``engineer`` cannot create a
  CR at all (the service rejects the author);
* :class:`DenyAllGate` is retained for never-CR-eligible tools and still hard
  rejects with :class:`ApprovalRequiredError`.
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

from app.agents.framework.approval import (
    ApprovalRequiredError,
    ChangeRequestGate,
    DenyAllGate,
)
from app.agents.framework.tools import (
    AgentRunIdentity,
    ChangeRequestCreated,
    NetOpsTool,
    ToolClassification,
    agent_run_context,
    change_request_gate_context,
    netops_tool,
)
from app.core.security import Role
from app.llm.redaction import REDACTION_TOKENS
from app.models import (
    AuditLog,
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    User,
)
from app.models import Role as RoleRow
from app.services.audit import service as audit_service
from app.services.change_requests import ChangeRequestService
from tests.agents.conftest import ApproveAllGate, RecordingAuditSink

# A secret-bearing config line that the A9 layer must scrub before storage.
_SECRET_LINE = "snmp-server community S3cr3tRO RO"


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


async def _all_change_requests(maker: async_sessionmaker[AsyncSession]) -> list[ChangeRequest]:
    async with maker() as session:
        rows = (await session.execute(select(ChangeRequest))).scalars().all()
        return list(rows)


async def _audit_actions(maker: async_sessionmaker[AsyncSession]) -> list[str]:
    async with maker() as session:
        rows = (
            (await session.execute(select(AuditLog).order_by(AuditLog.created_at))).scalars().all()
        )
        return [row.action for row in rows]


def _deploy_tool(
    sink: RecordingAuditSink, *, approval_gate: Any = None
) -> tuple[NetOpsTool, dict[str, bool]]:
    """A state-changing config-deploy tool + a flag that flips iff the body runs.

    With no ``approval_gate`` the tool relies on the per-run gate factory (the M5
    CR-creation default) or the secure hard-reject fallback. An explicit gate
    (``ApproveAllGate``/``DenyAllGate``) pins the behaviour for the execution and
    never-CR-eligible paths.
    """
    state = {"executed": False}

    @netops_tool(
        classification=ToolClassification.STATE_CHANGING,
        audit_sink=sink,
        approval_gate=approval_gate,
        min_role=Role.ENGINEER,
        change_request_kind=ChangeRequestKind.CONFIG,
        target_refs=lambda args: {"device_ids": [args["device"]]},
    )
    async def deploy_config(device: str, config_blob: str) -> str:
        """Deploy a rendered configuration to a device."""
        state["executed"] = True
        return f"deployed to {device}"

    return deploy_config, state


class TestStateChangingToolCreatesChangeRequest:
    async def test_yields_change_request_draft_not_hard_reject(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        audit_sink: RecordingAuditSink,
    ) -> None:
        engineer_id = await _seed_user(sessionmaker, role_name="engineer")
        tool, state = _deploy_tool(audit_sink)

        def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
            assert identity.user_id is not None
            return ChangeRequestGate(
                service,
                requester_id=identity.user_id,
                actor_role=identity.role,
                generating_session_id=identity.session_id,
                reasoning_trace_id=identity.reasoning_trace_id,
            )

        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(factory),
        ):
            result = await tool.ainvoke({"device": "edge-1", "config_blob": _SECRET_LINE})

        # The tool returns the created CR — NOT the deploy result, and no raise.
        assert isinstance(result, ChangeRequestCreated)
        assert result.change_request_state == ChangeRequestState.DRAFT.value
        assert uuid.UUID(result.change_request_id)  # parses as a real CR id

        # Execution remains impossible: a non-approved CR never runs the body.
        assert state["executed"] is False

        # A real, persisted CR draft exists with the expected attribution.
        crs = await _all_change_requests(sessionmaker)
        assert len(crs) == 1
        cr = crs[0]
        assert cr.state is ChangeRequestState.DRAFT
        assert cr.kind is ChangeRequestKind.CONFIG
        assert cr.requester_id == engineer_id
        assert cr.target_refs == {"device_ids": ["edge-1"]}

    async def test_invocation_is_audited_as_denied_with_cr_id(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        audit_sink: RecordingAuditSink,
    ) -> None:
        engineer_id = await _seed_user(sessionmaker, role_name="engineer")
        tool, _ = _deploy_tool(audit_sink)

        def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
            return ChangeRequestGate(
                service, requester_id=identity.user_id, actor_role=identity.role
            )

        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(factory),
        ):
            result = await tool.ainvoke({"device": "edge-1", "config_blob": _SECRET_LINE})

        # Tool-layer audit: exactly one event, NOT a success, carrying the CR id.
        assert len(audit_sink.events) == 1
        event = audit_sink.events[0]
        assert event.outcome == "denied"  # the change did not execute
        assert event.classification is ToolClassification.STATE_CHANGING
        assert event.approval is not None
        assert event.approval.approved is False
        assert event.approval.change_request_created is True
        assert event.approval.change_request_id == result.change_request_id

        # The persistent CR-creation audit row was written by the service.
        actions = await _audit_actions(sessionmaker)
        assert audit_service.CHANGE_REQUEST_CREATED in actions

    async def test_tool_audit_event_arguments_are_redacted(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        audit_sink: RecordingAuditSink,
    ) -> None:
        # A9: the tool-layer audit event must NOT carry the raw secret — _emit
        # redacts arguments before they reach any sink (e.g. structlog would
        # otherwise log them verbatim). The CR payload stays verbatim (ADR-0020
        # §2); only the audit + LLM-preview surfaces are redacted.
        engineer_id = await _seed_user(sessionmaker, role_name="engineer")
        tool, _ = _deploy_tool(audit_sink)

        def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
            return ChangeRequestGate(
                service, requester_id=identity.user_id, actor_role=identity.role
            )

        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(factory),
        ):
            await tool.ainvoke({"device": "edge-1", "config_blob": _SECRET_LINE})

        assert len(audit_sink.events) == 1
        recorded = audit_sink.events[0].arguments["config_blob"]
        assert "S3cr3tRO" not in recorded
        assert REDACTION_TOKENS["snmp_community"] in recorded
        # Non-secret args are preserved so the event still says what ran.
        assert audit_sink.events[0].arguments["device"] == "edge-1"

    async def test_payload_is_verbatim_and_only_preview_is_redacted(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        audit_sink: RecordingAuditSink,
    ) -> None:
        engineer_id = await _seed_user(sessionmaker, role_name="engineer")
        tool, _ = _deploy_tool(audit_sink)

        def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
            return ChangeRequestGate(
                service, requester_id=identity.user_id, actor_role=identity.role
            )

        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(factory),
        ):
            await tool.ainvoke({"device": "edge-1", "config_blob": _SECRET_LINE})

        cr = (await _all_change_requests(sessionmaker))[0]
        # ADR-0020 §2: the stored payload is VERBATIM — it is exactly what the
        # executor (Wave 4) renders, so the secret survives there unchanged (no
        # approve-then-swap TOCTOU from redacting the apply-time content).
        assert cr.payload is not None
        assert cr.payload["config_blob"] == _SECRET_LINE
        assert "S3cr3tRO" in cr.payload["config_blob"]
        # ADR-0020 §4: redaction is applied only at the LLM-preview boundary —
        # the after_state diff/intent preview the agent surfaces. The raw secret
        # is gone there and the stable token + directive context survive.
        assert cr.after_state is not None
        preview = cr.after_state["proposed"]["config_blob"]
        assert "S3cr3tRO" not in preview
        assert REDACTION_TOKENS["snmp_community"] in preview


class TestRbacInheritancePreserved:
    async def test_operator_run_cannot_mint_a_change_request(
        self,
        service: ChangeRequestService,
        sessionmaker: async_sessionmaker[AsyncSession],
        audit_sink: RecordingAuditSink,
    ) -> None:
        # A tool an operator may *invoke* (min_role operator) reaches the gate but
        # still cannot mint a CR: authoring is engineer+ in the service. "An agent
        # can never do what its user cannot" — the role inherited from the run
        # governs CR authoring, and the service rejects it with ForbiddenError.
        from app.core.errors import ForbiddenError

        operator_id = await _seed_user(sessionmaker, role_name="operator")

        @netops_tool(
            classification=ToolClassification.STATE_CHANGING,
            audit_sink=audit_sink,
            min_role=Role.OPERATOR,
        )
        async def toggle_thing(device: str) -> str:
            """A state-changing action."""
            return "done"

        def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
            return ChangeRequestGate(
                service, requester_id=identity.user_id, actor_role=identity.role
            )

        with (
            agent_run_context(role=Role.OPERATOR, user_id=operator_id),
            change_request_gate_context(factory),
            pytest.raises(ForbiddenError),
        ):
            await toggle_thing.ainvoke({"device": "edge-1"})

        # No CR was created (the author was rejected before any state write).
        assert await _all_change_requests(sessionmaker) == []

    async def test_tool_min_role_still_blocks_under_required_rank(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        # RBAC at the tool layer is unchanged: a viewer-bound run cannot even
        # reach the gate for an engineer-only tool.
        from app.agents.framework.tools import RbacForbiddenError

        tool, state = _deploy_tool(audit_sink)  # min_role engineer
        with (
            agent_run_context(role=Role.VIEWER, user_id=uuid.uuid4()),
            pytest.raises(RbacForbiddenError),
        ):
            await tool.ainvoke({"device": "edge-1", "config_blob": "x"})
        assert state["executed"] is False


class TestNonApprovedCannotExecuteAndHardRejectRetained:
    async def test_approved_gate_executes_body(self, audit_sink: RecordingAuditSink) -> None:
        # The execution path still exists: an explicit approving gate (the Wave-4
        # execution seam / tests) runs the body. The CR gate never produces this.
        tool, state = _deploy_tool(audit_sink, approval_gate=ApproveAllGate())
        with agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()):
            result = await tool.ainvoke({"device": "edge-1", "config_blob": "x"})
        assert result == "deployed to edge-1"
        assert state["executed"] is True
        assert audit_sink.events[-1].outcome == "success"

    async def test_deny_all_gate_still_hard_rejects(self, audit_sink: RecordingAuditSink) -> None:
        # DenyAllGate is retained for never-CR-eligible tools: explicit gate wins,
        # the call hard-rejects with ApprovalRequiredError and never executes.
        tool, state = _deploy_tool(audit_sink, approval_gate=DenyAllGate())
        with (
            agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()),
            pytest.raises(ApprovalRequiredError),
        ):
            await tool.ainvoke({"device": "edge-1", "config_blob": "x"})
        assert state["executed"] is False
        assert audit_sink.events[-1].outcome == "denied"
        assert audit_sink.events[-1].approval is not None
        assert audit_sink.events[-1].approval.change_request_created is False

    async def test_no_gate_factory_falls_back_to_hard_reject(
        self, audit_sink: RecordingAuditSink
    ) -> None:
        # Secure default: with no gate factory bound and no explicit gate, a
        # state-changing tool hard-rejects rather than executing unauthorised.
        tool, state = _deploy_tool(audit_sink)
        with (
            agent_run_context(role=Role.ENGINEER, user_id=uuid.uuid4()),
            pytest.raises(ApprovalRequiredError),
        ):
            await tool.ainvoke({"device": "edge-1", "config_blob": "x"})
        assert state["executed"] is False
