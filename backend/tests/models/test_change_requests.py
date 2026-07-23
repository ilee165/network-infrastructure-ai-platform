"""ChangeRequest + Approval ORM roundtrips, enums, and FK integrity (M5; ADR-0020).

Mirrors ``tests/models/test_config_mgmt.py`` / ``test_agents.py``: in-memory
aiosqlite, no Postgres/Docker/network. The DB-level four-eyes *constraint
trigger* is PostgreSQL-only DDL exercised by the ``integration``-marked
migration test (``test_0007_*``); here we assert the model shape, the enums,
the JSONB-backed before/after state, and the FK wiring. The conditional
four-eyes predicate itself (approver != requester only when
``four_eyes_required``) is enforced server-side by the M5 ChangeRequest service
(task #3) and at the DB level by the trigger — both paths are covered by their
own suites; this file pins the persistence contract those layers build on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Approval,
    ApprovalDecision,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    Role,
    User,
)


async def _user(session: AsyncSession, username: str | None = None) -> User:
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}")
    session.add(role)
    await session.flush()
    user = User(
        username=username or f"user-{uuid.uuid4().hex[:8]}",
        password_hash="x",
        role_id=role.id,
    )
    session.add(user)
    await session.flush()
    return user


async def _change_request(
    session: AsyncSession,
    requester: User,
    *,
    four_eyes_required: bool = True,
) -> ChangeRequest:
    cr = ChangeRequest(
        state=ChangeRequestState.DRAFT,
        kind=ChangeRequestKind.CONFIG,
        requester_id=requester.id,
        before_state={"hostname": "core-01"},
        after_state={"hostname": "core-01", "ip ssh version": 2},
        four_eyes_required=four_eyes_required,
    )
    session.add(cr)
    await session.flush()
    return cr


async def test_change_request_roundtrip(session: AsyncSession) -> None:
    """A CR persists its state/kind enums, before/after JSON, and four-eyes flag."""
    requester = await _user(session)
    before = {"acl": ["permit ip any any"]}
    after = {"acl": ["deny ip 10.0.0.0/8 any", "permit ip any any"]}
    cr = ChangeRequest(
        state=ChangeRequestState.PENDING_APPROVAL,
        kind=ChangeRequestKind.CONFIG,
        requester_id=requester.id,
        before_state=before,
        after_state=after,
    )
    session.add(cr)
    await session.commit()

    reloaded = (
        await session.execute(
            select(ChangeRequest)
            .where(ChangeRequest.id == cr.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.state is ChangeRequestState.PENDING_APPROVAL
    assert reloaded.kind is ChangeRequestKind.CONFIG
    assert reloaded.requester_id == requester.id
    assert reloaded.before_state == before
    assert reloaded.after_state == after
    # four_eyes_required defaults to True (secure by default, ADR-0020 §3).
    assert reloaded.four_eyes_required is True
    assert reloaded.reasoning_trace_id is None


async def test_change_request_state_machine_terminal_and_failed_states() -> None:
    """The state enum carries the full ADR-0020 §1 lifecycle vocabulary."""
    assert {s.value for s in ChangeRequestState} == {
        "draft",
        "pending_approval",
        "approved",
        "executing",
        "completed",
        "failed",
        "rolled_back",
    }


async def test_change_request_kind_enum_values() -> None:
    """kind distinguishes config / DDI-record / security-remediation writes (ADR-0020 §2).

    ``security_remediation`` (P2 W3-T1, ADR-0037 §4) is a Security-Agent remediation
    draft, gate-routed exactly like the others; it is a code-only addition (the kind
    column is VARCHAR, no CHECK — migration 0007), so no migration is required.
    """
    assert {k.value for k in ChangeRequestKind} == {
        "config",
        "ddi_record",
        "report_generation",
        "security_remediation",
    }


async def test_change_request_requires_requester_fk(session: AsyncSession) -> None:
    """requester_id references users.id — an unknown requester violates the FK."""
    session.add(
        ChangeRequest(
            state=ChangeRequestState.DRAFT,
            kind=ChangeRequestKind.DDI_RECORD,
            requester_id=uuid.uuid4(),
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_change_request_four_eyes_required_defaults_true(session: AsyncSession) -> None:
    """Omitting four_eyes_required yields the secure-by-default value True."""
    requester = await _user(session)
    cr = ChangeRequest(
        state=ChangeRequestState.DRAFT,
        kind=ChangeRequestKind.CONFIG,
        requester_id=requester.id,
    )
    session.add(cr)
    await session.commit()
    assert cr.four_eyes_required is True


async def test_change_request_reasoning_trace_link_is_plain_uuid_no_fk(
    session: AsyncSession,
) -> None:
    """reasoning_trace_id is a nullable plain indexed UUID — no DB-level FK.

    ``reasoning_traces`` is range-partitioned; a PostgreSQL FK to it must include
    the partition key (created_at), so — exactly like ``audit_log`` and
    ``raw_artifact_id`` — the link is a bare indexed UUID and integrity is
    enforced by the service + tests, not a DB constraint.
    """
    from app.models import ChangeRequest as CR

    column = CR.__table__.columns["reasoning_trace_id"]
    assert not column.foreign_keys
    assert column.nullable
    # A free-standing UUID with no matching trace row persists (no FK to enforce).
    requester = await _user(session)
    cr = ChangeRequest(
        state=ChangeRequestState.DRAFT,
        kind=ChangeRequestKind.CONFIG,
        requester_id=requester.id,
        reasoning_trace_id=uuid.uuid4(),
    )
    session.add(cr)
    await session.commit()
    assert cr.reasoning_trace_id is not None


async def test_approval_roundtrip_and_change_request_fk(session: AsyncSession) -> None:
    """An approval row persists its decision enum, comment, actor, and CR link."""
    requester = await _user(session)
    approver = await _user(session)
    cr = await _change_request(session, requester)
    decided = datetime(2026, 6, 18, 3, 0, tzinfo=UTC)
    approval = Approval(
        change_request_id=cr.id,
        actor_id=approver.id,
        decision=ApprovalDecision.APPROVE,
        comment="LGTM — reviewed the ACL diff.",
        created_at=decided,
    )
    session.add(approval)
    await session.commit()

    reloaded = (
        await session.execute(
            select(Approval)
            .where(Approval.id == approval.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.decision is ApprovalDecision.APPROVE
    assert reloaded.actor_id == approver.id
    assert reloaded.change_request_id == cr.id
    assert reloaded.comment == "LGTM — reviewed the ACL diff."
    assert reloaded.created_at == decided


async def test_approval_decision_enum_values() -> None:
    """Each approval row is a single approve/reject decision (ADR-0020 §2)."""
    assert {d.value for d in ApprovalDecision} == {"approve", "reject"}


async def test_approval_requires_change_request_fk(session: AsyncSession) -> None:
    """change_request_id references change_requests.id — orphans are rejected."""
    actor = await _user(session)
    session.add(
        Approval(
            change_request_id=uuid.uuid4(),
            actor_id=actor.id,
            decision=ApprovalDecision.REJECT,
            comment="no",
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_approval_requires_actor_fk(session: AsyncSession) -> None:
    """actor_id references users.id — an unknown actor violates the FK."""
    requester = await _user(session)
    cr = await _change_request(session, requester)
    session.add(
        Approval(
            change_request_id=cr.id,
            actor_id=uuid.uuid4(),
            decision=ApprovalDecision.APPROVE,
            comment="ghost",
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_approvals_are_history_not_a_mutable_column(session: AsyncSession) -> None:
    """Multiple decisions on one CR coexist — approvals is an append-only history.

    ADR-0020 alt #2: a CR may be rejected (returns to draft), re-submitted, and
    later approved; every decision is its own row with its own comment, so the
    full trail (including rejections) survives.
    """
    requester = await _user(session)
    reviewer = await _user(session)
    approver = await _user(session)
    cr = await _change_request(session, requester)
    session.add_all(
        [
            Approval(
                change_request_id=cr.id,
                actor_id=reviewer.id,
                decision=ApprovalDecision.REJECT,
                comment="tighten the ACL scope",
            ),
            Approval(
                change_request_id=cr.id,
                actor_id=approver.id,
                decision=ApprovalDecision.APPROVE,
                comment="fixed, approved",
            ),
        ]
    )
    await session.commit()

    decisions = (
        (
            await session.execute(
                select(Approval)
                .where(Approval.change_request_id == cr.id)
                .order_by(Approval.created_at)
            )
        )
        .scalars()
        .all()
    )
    assert [d.decision for d in decisions] == [
        ApprovalDecision.REJECT,
        ApprovalDecision.APPROVE,
    ]
