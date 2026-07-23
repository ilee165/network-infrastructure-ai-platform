"""Real-PostgreSQL join proofs for P5 W1-T3 reconciliation."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.reconciliation import (
    reconcile_change_request_audit,
    reconcile_reasoning_traces,
)

pytestmark = pytest.mark.integration


async def test_cr_audit_reconcile_counts_executed_terminal_change_without_lifecycle_audit(
    pg_session: AsyncSession,
) -> None:
    cr_id, user_id = uuid4(), uuid4()
    await pg_session.execute(
        text(
            "INSERT INTO users (id, username, email, password_hash, role, is_active,"
            " created_at, updated_at) VALUES (:u, :n, :e, 'x', 'admin', true, now(), now())"
        ),
        {"u": user_id, "n": f"reconcile-{user_id}", "e": f"{user_id}@example.test"},
    )
    await pg_session.execute(
        text(
            "INSERT INTO change_requests (id,state,kind,requester_id,four_eyes_required,"
            "created_at,updated_at) VALUES (:id,'completed','config',:u,true,now(),now())"
        ),
        {"id": cr_id, "u": user_id},
    )
    await pg_session.commit()
    result = await reconcile_change_request_audit(pg_session)
    assert result.inconsistencies == 1


async def test_cr_audit_trace_join_graph_counts_only_missing_or_mismatched_edges(
    pg_session: AsyncSession,
) -> None:
    user_id = uuid4()
    trace_id, wrong_trace_id = uuid4(), uuid4()
    healthy_id, missing_cr_link_id, missing_audit_link_id, mismatch_id = (uuid4() for _ in range(4))
    await pg_session.execute(
        text(
            "INSERT INTO users (id, username, email, password_hash, role, is_active,"
            " created_at, updated_at) VALUES (:u, :n, :e, 'x', 'admin', true, now(), now())"
        ),
        {"u": user_id, "n": f"cr-graph-{user_id}", "e": f"{user_id}@example.test"},
    )
    for cr_id, cr_trace in (
        (healthy_id, trace_id),
        (missing_cr_link_id, None),
        (missing_audit_link_id, trace_id),
        (mismatch_id, trace_id),
    ):
        await pg_session.execute(
            text(
                "INSERT INTO change_requests (id,state,kind,requester_id,four_eyes_required,"
                "reasoning_trace_id,created_at,updated_at) "
                "VALUES (:id,'completed','config',:u,true,:trace,now(),now())"
            ),
            {"id": cr_id, "u": user_id, "trace": cr_trace},
        )
    actions = (
        "change_request.created",
        "change_request.draft_to_pending_approval",
        "change_request.pending_approval_to_approved",
        "change_request.approved_to_executing",
        "change_request.executing_to_completed",
    )
    seq = 1000
    for cr_id, audit_trace in (
        (healthy_id, trace_id),
        (missing_cr_link_id, trace_id),
        (missing_audit_link_id, None),
        (mismatch_id, wrong_trace_id),
    ):
        for action in actions:
            seq += 1
            await pg_session.execute(
                text(
                    "INSERT INTO audit_log "
                    "(id,created_at,seq,actor,action,target_type,target_id,reasoning_trace_id,"
                    "prev_hash,entry_hash) VALUES "
                    "(:id,now(),:seq,'test',:action,'change_request',:target,:trace,"
                    "decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'))"
                ),
                {
                    "id": uuid4(),
                    "seq": seq,
                    "action": action,
                    "target": str(cr_id),
                    "trace": audit_trace,
                },
            )
    await pg_session.commit()
    result = await reconcile_change_request_audit(pg_session)
    assert result.inconsistencies == 3


async def test_trace_reconcile_finds_required_session_without_trace(
    pg_session: AsyncSession,
) -> None:
    user_id, session_id = uuid4(), uuid4()
    settled = datetime.now(UTC) - timedelta(minutes=6)
    await pg_session.execute(
        text(
            "INSERT INTO users (id, username, email, password_hash, role, is_active,"
            " created_at, updated_at) VALUES (:u, :n, :e, 'x', 'admin', true, now(), now())"
        ),
        {"u": user_id, "n": f"trace-{user_id}", "e": f"{user_id}@example.test"},
    )
    await pg_session.execute(
        text(
            "INSERT INTO agent_sessions (id,user_id,invoking_role,intent,status,started_at,"
            "completed_at,created_at,updated_at) VALUES "
            "(:id,:u,'admin','test','completed',:t,:t,:t,:t)"
        ),
        {"id": session_id, "u": user_id, "t": settled},
    )
    await pg_session.commit()
    result = await reconcile_reasoning_traces(pg_session, now=datetime.now(UTC))
    assert result.sessions_without_trace == 1


async def test_trace_reconcile_matched_graph_and_orphan_step_exact_counts(
    pg_session: AsyncSession,
) -> None:
    user_id, session_id, trace_id = uuid4(), uuid4(), uuid4()
    orphan_trace_id = uuid4()
    settled = datetime.now(UTC) - timedelta(minutes=6)
    await pg_session.execute(
        text(
            "INSERT INTO users (id, username, email, password_hash, role, is_active,"
            " created_at, updated_at) VALUES (:u, :n, :e, 'x', 'admin', true, now(), now())"
        ),
        {"u": user_id, "n": f"graph-{user_id}", "e": f"{user_id}@example.test"},
    )
    await pg_session.execute(
        text(
            "INSERT INTO agent_sessions (id,user_id,invoking_role,intent,status,started_at,"
            "completed_at,created_at,updated_at) VALUES "
            "(:id,:u,'admin','test','completed',:t,:t,:t,:t)"
        ),
        {"id": session_id, "u": user_id, "t": settled},
    )
    await pg_session.execute(
        text(
            "INSERT INTO reasoning_traces "
            "(id,created_at,session_id,agent_name,started_at,completed_at) "
            "VALUES (:id,:t,:session,'test',:t,:t)"
        ),
        {"id": trace_id, "session": session_id, "t": settled},
    )
    for ordinal, parent in ((1, trace_id), (2, orphan_trace_id)):
        await pg_session.execute(
            text(
                "INSERT INTO reasoning_trace_steps "
                "(id,created_at,trace_id,ordinal,kind,summary,evidence,occurred_at) "
                "VALUES (:id,:t,:trace,:ordinal,'reasoning','test','[]'::jsonb,:t)"
            ),
            {"id": uuid4(), "t": settled, "trace": parent, "ordinal": ordinal},
        )
    await pg_session.commit()
    result = await reconcile_reasoning_traces(pg_session, now=datetime.now(UTC))
    assert result.sessions_without_trace == 0
    assert result.traces_without_session == 0
    assert result.steps_without_trace == 1
