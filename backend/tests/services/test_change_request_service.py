"""ChangeRequest service: lifecycle state machine, four-eyes, audited transitions (M5 task #3).

Offline-first: an in-memory aiosqlite engine with the full model schema, no
Postgres/Docker/network. The PostgreSQL four-eyes *constraint trigger* (migration
0007) is the DB backstop and is exercised by its own ``integration``-marked
migration test; here the four-eyes rule is verified through the **service guard**,
which ADR-0020 §3 makes the *primary* enforcement point (the trigger is
defense-in-depth and does not even fire on the SQLite unit backend).

Coverage:

* Guarded transitions: only the ADR-0020 §1 edges are legal; every illegal edge
  raises and writes no state.
* ``submit`` / ``approve`` / ``reject`` / execution handoffs
  (``mark_executing`` / ``mark_completed`` / ``mark_failed`` / ``mark_rolled_back``).
* Four-eyes (PRIMARY, service-side): a requester approving their own
  four-eyes-required CR is rejected; a *different* engineer may approve; when
  ``four_eyes_required`` is disabled the requester may self-approve (and the
  decision is still recorded as a distinct, audited ``approvals`` row).
* RBAC: author/submit/approve require ``engineer``+; ``operator``/``viewer`` are
  denied; ``admin`` inherits ``engineer``.
* Immutability post-submit: ``requester_id`` / ``four_eyes_required`` cannot be
  changed once a CR leaves ``draft`` (service-enforced, ADR-0020 §3).
* Audited transitions: every transition writes one ``audit_log`` row with the
  ``change_request.<from>_to_<to>`` action, before/after state, and the
  reasoning-trace link when the CR carries one (ADR-0020 §4).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.errors import ConflictError, ForbiddenError, NotFoundError
from app.core.security import Role
from app.models import (
    Approval,
    ApprovalDecision,
    AuditLog,
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    User,
)
from app.models import Role as RoleRow
from app.services.audit import service as audit_service
from app.services.change_requests import (
    AUTOMATION_PRINCIPAL,
    AutomationPrincipal,
    ChangeRequestService,
)


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
    """A sessionmaker bound to the in-memory test engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
def service(sessionmaker: async_sessionmaker[AsyncSession]) -> ChangeRequestService:
    return ChangeRequestService(sessionmaker)


async def _seed_user(maker: async_sessionmaker[AsyncSession], *, role_name: str) -> uuid.UUID:
    """Persist a role + user row and return the user id (the requester/actor FK)."""
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
# draft authoring
# ---------------------------------------------------------------------------


class TestCreateDraft:
    async def test_engineer_creates_draft(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"diff": "ip ssh version 2"},
            target_refs={"device_ids": ["edge-1"]},
            rollback_plan={"snapshot_ref": "snap-1"},
            before_state={"ip ssh version": 1},
            after_state={"ip ssh version": 2},
        )

        assert cr.state is ChangeRequestState.DRAFT
        assert cr.requester_id == requester
        assert cr.four_eyes_required is True
        assert cr.payload == {"diff": "ip ssh version 2"}
        # The draft authoring is audited.
        rows = await _audit_rows(sessionmaker, cr.id)
        assert any(r.action == "change_request.created" for r in rows)

    async def test_operator_cannot_author(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="operator")
        with pytest.raises(ForbiddenError):
            await service.create_draft(
                requester_id=requester,
                actor_role=Role.OPERATOR,
                kind=ChangeRequestKind.CONFIG,
            )

    async def test_viewer_cannot_author(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="viewer")
        with pytest.raises(ForbiddenError):
            await service.create_draft(
                requester_id=requester,
                actor_role=Role.VIEWER,
                kind=ChangeRequestKind.DDI_RECORD,
            )

    async def test_admin_can_disable_four_eyes_and_waiver_is_audited(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Only admin may waive four-eyes, and the waiver is a distinct audit event."""
        requester = await _seed_user(sessionmaker, role_name="admin")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ADMIN,
            kind=ChangeRequestKind.CONFIG,
            four_eyes_required=False,
        )
        assert cr.four_eyes_required is False
        # The disablement is a first-class, separately-audited event (ADR-0020 §3),
        # distinct from change_request.created and attributing the waiver role.
        rows = await _audit_rows(sessionmaker, cr.id)
        waiver = next(r for r in rows if r.action == "change_request.four_eyes_waived")
        assert waiver.detail is not None
        assert waiver.detail["waived_by_role"] == "admin"
        assert waiver.actor == f"user:{requester}"

    async def test_engineer_cannot_disable_four_eyes(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """An engineer may author CRs but may NOT waive four-eyes (ADR-0020 §3)."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        with pytest.raises(ForbiddenError):
            await service.create_draft(
                requester_id=requester,
                actor_role=Role.ENGINEER,
                kind=ChangeRequestKind.CONFIG,
                four_eyes_required=False,
            )

    async def test_four_eyes_default_cr_emits_no_waiver_event(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        rows = await _audit_rows(sessionmaker, cr.id)
        assert not any(r.action == "change_request.four_eyes_waived" for r in rows)


# ---------------------------------------------------------------------------
# submit
# ---------------------------------------------------------------------------


class TestSubmit:
    async def test_submit_moves_draft_to_pending(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        submitted = await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        assert submitted.state is ChangeRequestState.PENDING_APPROVAL
        rows = await _audit_rows(sessionmaker, cr.id)
        assert any(r.action == "change_request.draft_to_pending_approval" for r in rows)

    async def test_submit_requires_engineer(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        with pytest.raises(ForbiddenError):
            await service.submit(cr.id, actor_id=requester, actor_role=Role.OPERATOR)
        # State unchanged after the denied attempt.
        assert (await service.get(cr.id)).state is ChangeRequestState.DRAFT

    async def test_submit_rejects_non_draft(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        # A second submit on a pending CR is an illegal transition.
        with pytest.raises(ConflictError):
            await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)

    async def test_submit_unknown_cr_raises_not_found(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        with pytest.raises(NotFoundError):
            await service.submit(uuid.uuid4(), actor_id=requester, actor_role=Role.ENGINEER)


# ---------------------------------------------------------------------------
# four-eyes + approve / reject
# ---------------------------------------------------------------------------


class TestFourEyesAndApproval:
    async def _pending_cr(
        self,
        service: ChangeRequestService,
        maker: async_sessionmaker[AsyncSession],
        *,
        requester: uuid.UUID,
        four_eyes_required: bool = True,
        author_role: Role = Role.ENGINEER,
    ) -> ChangeRequest:
        # Waiving four-eyes is admin-only (ADR-0020 §3): when the test disables
        # it the author must be an admin, otherwise create_draft rejects.
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=author_role,
            kind=ChangeRequestKind.CONFIG,
            four_eyes_required=four_eyes_required,
        )
        return await service.submit(cr.id, actor_id=requester, actor_role=author_role)

    async def test_requester_cannot_approve_own_four_eyes_cr(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """PRIMARY four-eyes guard: self-approval is rejected at the service."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await self._pending_cr(service, sessionmaker, requester=requester)

        with pytest.raises(ForbiddenError):
            await service.approve(cr.id, actor_id=requester, actor_role=Role.ENGINEER)

        # No state change, and NO approve row was written.
        assert (await service.get(cr.id)).state is ChangeRequestState.PENDING_APPROVAL
        async with sessionmaker() as db:
            count = (
                await db.execute(
                    select(func.count())
                    .select_from(Approval)
                    .where(Approval.change_request_id == cr.id)
                )
            ).scalar_one()
            assert count == 0

    async def test_different_engineer_approves(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await self._pending_cr(service, sessionmaker, requester=requester)

        approved = await service.approve(
            cr.id, actor_id=approver, actor_role=Role.ENGINEER, comment="LGTM"
        )
        assert approved.state is ChangeRequestState.APPROVED
        async with sessionmaker() as db:
            row = (
                await db.execute(select(Approval).where(Approval.change_request_id == cr.id))
            ).scalar_one()
            assert row.decision is ApprovalDecision.APPROVE
            assert row.actor_id == approver
            assert row.comment == "LGTM"

    async def test_admin_inherits_engineer_for_approval(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="admin")
        cr = await self._pending_cr(service, sessionmaker, requester=requester)
        approved = await service.approve(cr.id, actor_id=approver, actor_role=Role.ADMIN)
        assert approved.state is ChangeRequestState.APPROVED

    async def test_operator_cannot_approve(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="operator")
        cr = await self._pending_cr(service, sessionmaker, requester=requester)
        with pytest.raises(ForbiddenError):
            await service.approve(cr.id, actor_id=approver, actor_role=Role.OPERATOR)
        assert (await service.get(cr.id)).state is ChangeRequestState.PENDING_APPROVAL

    async def test_self_approval_allowed_when_four_eyes_disabled(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        # Four-eyes may only be waived by an admin (ADR-0020 §3); a waived CR may
        # then be self-approved by its admin author.
        requester = await _seed_user(sessionmaker, role_name="admin")
        cr = await self._pending_cr(
            service,
            sessionmaker,
            requester=requester,
            four_eyes_required=False,
            author_role=Role.ADMIN,
        )
        approved = await service.approve(
            cr.id, actor_id=requester, actor_role=Role.ADMIN, comment="solo lab change"
        )
        assert approved.state is ChangeRequestState.APPROVED
        # The self-approval is still recorded as a distinct, audited approvals row.
        async with sessionmaker() as db:
            row = (
                await db.execute(select(Approval).where(Approval.change_request_id == cr.id))
            ).scalar_one()
            assert row.actor_id == requester
            assert row.decision is ApprovalDecision.APPROVE

    async def test_reject_returns_to_draft_and_records_decision(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        reviewer = await _seed_user(sessionmaker, role_name="engineer")
        cr = await self._pending_cr(service, sessionmaker, requester=requester)

        rejected = await service.reject(
            cr.id, actor_id=reviewer, actor_role=Role.ENGINEER, comment="tighten ACL scope"
        )
        assert rejected.state is ChangeRequestState.DRAFT
        async with sessionmaker() as db:
            row = (
                await db.execute(select(Approval).where(Approval.change_request_id == cr.id))
            ).scalar_one()
            assert row.decision is ApprovalDecision.REJECT
            assert row.comment == "tighten ACL scope"

    async def test_requester_may_reject_own_cr(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Four-eyes constrains *approve*, not *reject* — a requester may withdraw."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await self._pending_cr(service, sessionmaker, requester=requester)
        rejected = await service.reject(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        assert rejected.state is ChangeRequestState.DRAFT

    async def test_approve_rejects_non_pending(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        # Still in draft — approve is an illegal transition from draft.
        with pytest.raises(ConflictError):
            await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)


# ---------------------------------------------------------------------------
# execution handoffs (no device/DDI writes here — Automation Agent owns those)
# ---------------------------------------------------------------------------


class TestExecutionHandoffs:
    async def _approved_cr(
        self,
        service: ChangeRequestService,
        maker: async_sessionmaker[AsyncSession],
    ) -> ChangeRequest:
        requester = await _seed_user(maker, role_name="engineer")
        approver = await _seed_user(maker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        return await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

    async def test_approved_to_executing_to_completed(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        cr = await self._approved_cr(service, sessionmaker)
        executing = await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)
        assert executing.state is ChangeRequestState.EXECUTING
        completed = await service.mark_completed(
            cr.id, principal=AUTOMATION_PRINCIPAL, after_state={"ip ssh version": 2}
        )
        assert completed.state is ChangeRequestState.COMPLETED
        assert completed.after_state == {"ip ssh version": 2}
        rows = await _audit_rows(sessionmaker, cr.id)
        actions = {r.action for r in rows}
        assert "change_request.approved_to_executing" in actions
        assert "change_request.executing_to_completed" in actions
        # The handoff audit actor is the verified Automation principal, not a user.
        exec_row = next(r for r in rows if r.action == "change_request.approved_to_executing")
        assert exec_row.actor == "agent:automation"

    async def test_executing_to_failed_to_rolled_back(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        cr = await self._approved_cr(service, sessionmaker)
        await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)
        failed = await service.mark_failed(
            cr.id, principal=AUTOMATION_PRINCIPAL, after_state={"error": "apply timeout"}
        )
        assert failed.state is ChangeRequestState.FAILED
        rolled = await service.mark_rolled_back(cr.id, principal=AUTOMATION_PRINCIPAL)
        assert rolled.state is ChangeRequestState.ROLLED_BACK
        rows = await _audit_rows(sessionmaker, cr.id)
        actions = {r.action for r in rows}
        assert "change_request.executing_to_failed" in actions
        assert "change_request.failed_to_rolled_back" in actions

    async def test_non_automation_caller_cannot_drive_execution(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """approved → executing is gated on the verified Automation principal (ADR-0020 §2).

        A forged principal (even one mimicking the actor string) is rejected, and
        no state change or audit row is written.
        """
        cr = await self._approved_cr(service, sessionmaker)
        forged = AutomationPrincipal(actor="agent:automation")
        with pytest.raises(ForbiddenError):
            await service.mark_executing(cr.id, principal=forged)
        # State unchanged and no transition audit row written for the denied call.
        assert (await service.get(cr.id)).state is ChangeRequestState.APPROVED
        rows = await _audit_rows(sessionmaker, cr.id)
        assert not any(r.action == "change_request.approved_to_executing" for r in rows)

    async def test_cannot_execute_unapproved_cr(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        # pending/draft → executing is illegal; only approved → executing is legal.
        with pytest.raises(ConflictError):
            await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)

    async def test_cannot_complete_without_executing(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        cr = await self._approved_cr(service, sessionmaker)
        with pytest.raises(ConflictError):
            await service.mark_completed(cr.id, principal=AUTOMATION_PRINCIPAL)

    async def test_completed_is_terminal(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        cr = await self._approved_cr(service, sessionmaker)
        await service.mark_executing(cr.id, principal=AUTOMATION_PRINCIPAL)
        await service.mark_completed(cr.id, principal=AUTOMATION_PRINCIPAL)
        # No edge leaves completed.
        with pytest.raises(ConflictError):
            await service.mark_rolled_back(cr.id, principal=AUTOMATION_PRINCIPAL)


# ---------------------------------------------------------------------------
# post-submit immutability (service-enforced, ADR-0020 §3)
# ---------------------------------------------------------------------------


class TestImmutability:
    async def test_requester_and_four_eyes_immutable_after_submit(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)

        # A submitted (non-draft) CR may not be edited at all — requester_id and
        # four_eyes_required are frozen, and update_draft refuses the whole row.
        with pytest.raises(ConflictError):
            await service.update_draft(
                cr.id, actor_id=requester, actor_role=Role.ENGINEER, payload={"x": 1}
            )

    async def test_update_draft_allows_payload_edit_before_submit(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        updated = await service.update_draft(
            cr.id, actor_id=requester, actor_role=Role.ENGINEER, payload={"diff": "v2"}
        )
        assert updated.payload == {"diff": "v2"}
        # requester_id / four_eyes_required are never accepted by update_draft.
        assert updated.requester_id == requester


# ---------------------------------------------------------------------------
# audit touchpoints (ADR-0020 §4)
# ---------------------------------------------------------------------------


class TestAuditTrail:
    async def test_every_transition_writes_before_after_and_trace_link(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        trace_id = uuid.uuid4()
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            reasoning_trace_id=trace_id,
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        rows = await _audit_rows(sessionmaker, cr.id)
        transition_rows = [r for r in rows if r.action.startswith("change_request.")]
        assert transition_rows, "transitions must be audited"
        # The transition audit carries the before/after lifecycle states.
        submit_row = next(r for r in rows if r.action == "change_request.draft_to_pending_approval")
        assert submit_row.detail is not None
        assert submit_row.detail["before_state"] == "draft"
        assert submit_row.detail["after_state"] == "pending_approval"
        # The reasoning-trace link rides on every transition audit row for an
        # agent-authored CR (ADR-0020 §4).
        assert all(r.reasoning_trace_id == trace_id for r in transition_rows)

    async def test_approve_transition_actor_is_the_approver(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        rows = await _audit_rows(sessionmaker, cr.id)
        approve_row = next(
            r for r in rows if r.action == "change_request.pending_approval_to_approved"
        )
        assert approve_row.actor == f"user:{approver}"

    async def test_transition_audit_carries_target_refs_not_payload(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """The audited record self-identifies affected targets by id (ADR-0020 §4).

        target_refs (device ids / DDI refs) ride in the audit detail; the
        secret-bearing payload never does.
        """
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        target_refs = {"device_ids": ["edge-1", "edge-2"]}
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"diff": "secret enable password 0 hunter2"},
            target_refs=target_refs,
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)

        rows = await _audit_rows(sessionmaker, cr.id)
        for action in (
            "change_request.created",
            "change_request.draft_to_pending_approval",
            "change_request.pending_approval_to_approved",
        ):
            row = next(r for r in rows if r.action == action)
            assert row.detail is not None
            assert row.detail["target_refs"] == target_refs, action
            # The secret-bearing payload is never serialized into the audit detail.
            assert "hunter2" not in str(row.detail), action

    async def test_request_id_correlation_threaded_into_audit(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """The inbound request/correlation id is persisted on the audit row (ADR-0020 §4)."""
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        create_rid = uuid.uuid4()
        submit_rid = uuid.uuid4()
        approve_rid = uuid.uuid4()
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            request_id=create_rid,
        )
        await service.submit(
            cr.id, actor_id=requester, actor_role=Role.ENGINEER, request_id=submit_rid
        )
        await service.approve(
            cr.id, actor_id=approver, actor_role=Role.ENGINEER, request_id=approve_rid
        )

        rows = await _audit_rows(sessionmaker, cr.id)
        by_action = {r.action: r for r in rows}
        assert by_action["change_request.created"].request_id == create_rid
        assert by_action["change_request.draft_to_pending_approval"].request_id == submit_rid
        assert by_action["change_request.pending_approval_to_approved"].request_id == approve_rid


def test_change_request_action_constants() -> None:
    """The CR transition action vocabulary is fixed and importable from the audit package."""
    assert audit_service.CHANGE_REQUEST_CREATED == "change_request.created"
    assert audit_service.CHANGE_REQUEST_FOUR_EYES_WAIVED == "change_request.four_eyes_waived"
    assert (
        audit_service.CHANGE_REQUEST_DRAFT_TO_PENDING == "change_request.draft_to_pending_approval"
    )
    assert (
        audit_service.CHANGE_REQUEST_PENDING_TO_APPROVED
        == "change_request.pending_approval_to_approved"
    )
    assert (
        audit_service.CHANGE_REQUEST_PENDING_TO_DRAFT == "change_request.pending_approval_to_draft"
    )
    assert (
        audit_service.CHANGE_REQUEST_APPROVED_TO_EXECUTING == "change_request.approved_to_executing"
    )
    assert (
        audit_service.CHANGE_REQUEST_EXECUTING_TO_COMPLETED
        == "change_request.executing_to_completed"
    )
    assert audit_service.CHANGE_REQUEST_EXECUTING_TO_FAILED == "change_request.executing_to_failed"
    assert (
        audit_service.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK == "change_request.failed_to_rolled_back"
    )


# ---------------------------------------------------------------------------
# W3-T0: ChangeRequest workflow-health metric emitted at the transition site
# ---------------------------------------------------------------------------


class TestChangeRequestMetrics:
    """Every lifecycle transition increments ``netops_change_requests_total{state}``."""

    @staticmethod
    def _state_count(state: str) -> float:
        from app.core import metrics

        return metrics.CHANGE_REQUESTS_TOTAL.labels(state=state)._value.get()  # type: ignore[attr-defined]

    @staticmethod
    def _approval_latency_count() -> int:
        """Return the current observation count on the approval-latency histogram."""
        from app.core import metrics

        for metric_family in metrics.CHANGE_REQUEST_APPROVAL_LATENCY_SECONDS.collect():
            for sample in metric_family.samples:
                if sample.name.endswith("_count"):
                    return int(sample.value)
        return 0

    async def test_create_and_submit_count_their_states(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        before_draft = self._state_count("draft")
        before_pending = self._state_count("pending_approval")
        requester = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester,
            actor_role=Role.ENGINEER,
            kind=ChangeRequestKind.CONFIG,
            payload={"diff": "x"},
        )
        # The initial draft entry counted.
        assert self._state_count("draft") == before_draft + 1
        await service.submit(cr.id, actor_role=Role.ENGINEER, actor_id=requester)
        # The submit transition counted the entered state.
        assert self._state_count("pending_approval") == before_pending + 1

    async def test_approve_observes_approval_latency_histogram(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """approve() must observe the approval-wait duration on the latency histogram.

        Verifies the ADR-0046 §1 approval-latency SLI series is populated on
        the approve edge (finding: histogram was registered but never populated).
        """
        requester = await _seed_user(sessionmaker, role_name="engineer")
        approver = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        before_count = self._approval_latency_count()
        await service.approve(cr.id, actor_id=approver, actor_role=Role.ENGINEER)
        # Exactly one new histogram observation must have been recorded.
        assert self._approval_latency_count() == before_count + 1

    async def test_reject_observes_approval_latency_histogram(
        self, service: ChangeRequestService, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """reject() must observe the approval-wait duration on the latency histogram.

        Verifies the ADR-0046 §1 approval-latency SLI series is populated on
        the reject edge (finding: histogram was registered but never populated).
        """
        requester = await _seed_user(sessionmaker, role_name="engineer")
        reviewer = await _seed_user(sessionmaker, role_name="engineer")
        cr = await service.create_draft(
            requester_id=requester, actor_role=Role.ENGINEER, kind=ChangeRequestKind.CONFIG
        )
        await service.submit(cr.id, actor_id=requester, actor_role=Role.ENGINEER)
        before_count = self._approval_latency_count()
        await service.reject(cr.id, actor_id=reviewer, actor_role=Role.ENGINEER)
        # Exactly one new histogram observation must have been recorded.
        assert self._approval_latency_count() == before_count + 1
