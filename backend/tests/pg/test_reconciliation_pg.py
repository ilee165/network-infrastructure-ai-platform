"""Real-PostgreSQL join proofs for P5 W1-T3 reconciliation."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.reconciliation import (
    change_request_audit_reconciliation_query,
    reconcile_change_request_audit,
    reconcile_reasoning_traces,
)

pytestmark = pytest.mark.integration


async def _seed_admin_user(
    session: AsyncSession,
    *,
    user_id: object,
    username: str,
) -> None:
    """Insert a user linked to the migration-seeded admin role."""
    role_id = await session.scalar(text("SELECT id FROM roles WHERE name = 'admin'"))
    assert role_id is not None
    await session.execute(
        text(
            "INSERT INTO users (id, username, email, password_hash, role_id, is_active,"
            " created_at, updated_at) VALUES (:u, :n, :e, 'x', :role_id, true, now(), now())"
        ),
        {
            "u": user_id,
            "n": username,
            "e": f"{user_id}@example.test",
            "role_id": role_id,
        },
    )


async def test_cr_audit_reconcile_counts_executed_terminal_change_without_lifecycle_audit(
    pg_session: AsyncSession,
) -> None:
    cr_id, user_id = uuid4(), uuid4()
    await _seed_admin_user(
        pg_session,
        user_id=user_id,
        username=f"reconcile-{user_id}",
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


async def test_cr_audit_reconcile_uses_terminal_specific_action_sets_on_pg(
    pg_session: AsyncSession,
) -> None:
    user_id = uuid4()
    await _seed_admin_user(
        pg_session,
        user_id=user_id,
        username=f"cr-terminal-path-{user_id}",
    )
    completed_id, rolled_back_id, masked_id = uuid4(), uuid4(), uuid4()
    rows = [
        {"id": completed_id, "state": "completed", "trace": uuid4(), "u": user_id},
        {"id": rolled_back_id, "state": "rolled_back", "trace": uuid4(), "u": user_id},
        {"id": masked_id, "state": "completed", "trace": uuid4(), "u": user_id},
    ]
    await pg_session.execute(
        text(
            "INSERT INTO change_requests (id,state,kind,requester_id,four_eyes_required,"
            "reasoning_trace_id,created_at,updated_at) "
            "VALUES (:id,:state,'config',:u,true,:trace,now(),now())"
        ),
        rows,
    )
    common = (
        "change_request.created",
        "change_request.draft_to_pending_approval",
        "change_request.pending_approval_to_approved",
        "change_request.approved_to_executing",
    )
    paths = (
        (rows[0], ("change_request.executing_to_completed",)),
        (
            rows[1],
            (
                "change_request.executing_to_failed",
                "change_request.failed_to_rolled_back",
            ),
        ),
        (
            rows[2],
            (
                "change_request.executing_to_failed",
                "change_request.failed_to_rolled_back",
            ),
        ),
    )
    audit_rows: list[dict[str, object]] = []
    seq = 2_000
    for cr, terminal_actions in paths:
        for action in common + terminal_actions:
            seq += 1
            audit_rows.append(
                {
                    "id": uuid4(),
                    "seq": seq,
                    "action": action,
                    "target": str(cr["id"]),
                    "trace": cr["trace"],
                }
            )
    await pg_session.execute(
        text(
            "INSERT INTO audit_log "
            "(id,created_at,seq,actor,action,target_type,target_id,reasoning_trace_id,"
            "prev_hash,entry_hash) VALUES "
            "(:id,now(),:seq,'test',:action,'change_request',:target,:trace,"
            "decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'))"
        ),
        audit_rows,
    )
    await pg_session.commit()

    assert (await reconcile_change_request_audit(pg_session)).inconsistencies == 1


async def test_cr_audit_trace_join_graph_counts_only_missing_or_mismatched_edges(
    pg_session: AsyncSession,
) -> None:
    user_id = uuid4()
    trace_id, wrong_trace_id = uuid4(), uuid4()
    healthy_id, missing_cr_link_id, missing_audit_link_id, mismatch_id = (uuid4() for _ in range(4))
    await _seed_admin_user(
        pg_session,
        user_id=user_id,
        username=f"cr-graph-{user_id}",
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


async def test_cr_audit_reconcile_plan_is_set_wise_and_uses_composite_lookup(
    pg_session: AsyncSession,
) -> None:
    """A realistic lifecycle fixture gets one aggregate audit pass, never N subplans."""
    user_id = uuid4()
    await _seed_admin_user(
        pg_session,
        user_id=user_id,
        username=f"cr-plan-{user_id}",
    )
    actions = (
        "change_request.created",
        "change_request.draft_to_pending_approval",
        "change_request.pending_approval_to_approved",
        "change_request.approved_to_executing",
        "change_request.executing_to_completed",
    )
    cr_rows: list[dict[str, object]] = []
    audit_rows: list[dict[str, object]] = []
    for ordinal in range(250):
        cr_id, trace_id = uuid4(), uuid4()
        cr_rows.append({"id": cr_id, "u": user_id, "trace": trace_id})
        for action_index, action in enumerate(actions):
            audit_rows.append(
                {
                    "id": uuid4(),
                    "seq": 20_000 + ordinal * len(actions) + action_index,
                    "action": action,
                    "target": str(cr_id),
                    "trace": trace_id,
                }
            )
    await pg_session.execute(
        text(
            "INSERT INTO change_requests (id,state,kind,requester_id,four_eyes_required,"
            "reasoning_trace_id,created_at,updated_at) "
            "VALUES (:id,'completed','config',:u,true,:trace,now(),now())"
        ),
        cr_rows,
    )
    await pg_session.execute(
        text(
            "INSERT INTO audit_log "
            "(id,created_at,seq,actor,action,target_type,target_id,reasoning_trace_id,"
            "prev_hash,entry_hash) VALUES "
            "(:id,now(),:seq,'test',:action,'change_request',:target,:trace,"
            "decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'))"
        ),
        audit_rows,
    )
    await pg_session.commit()

    assert (await reconcile_change_request_audit(pg_session)).inconsistencies == 0
    await pg_session.execute(text("SET LOCAL enable_seqscan = off"))
    statement = change_request_audit_reconciliation_query()
    sql = str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    plan_value = await pg_session.scalar(text(f"EXPLAIN (FORMAT JSON) {sql}"))
    plan_text = str(plan_value)
    assert "SubPlan" not in plan_text
    # PostgreSQL gives each partition-attached index a derived child name.
    assert "target_type_target_id_action_reasoning_tr" in plan_text
    assert plan_text.count("'Relation Name': 'change_requests'") == 1


async def test_trace_reconcile_finds_required_session_without_trace(
    pg_session: AsyncSession,
) -> None:
    user_id, session_id = uuid4(), uuid4()
    settled = datetime.now(UTC) - timedelta(minutes=6)
    await _seed_admin_user(
        pg_session,
        user_id=user_id,
        username=f"trace-{user_id}",
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
    orphan_session_id, orphan_trace_id, missing_trace_id = uuid4(), uuid4(), uuid4()
    settled = datetime.now(UTC) - timedelta(minutes=6)
    await _seed_admin_user(
        pg_session,
        user_id=user_id,
        username=f"graph-{user_id}",
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
    # Production declares the session FK, so deliberately bypass it in this
    # throwaway PostgreSQL transaction to prove the reconciliation query detects
    # corruption that normal writes cannot create. SET LOCAL resets on commit.
    await pg_session.execute(text("SET LOCAL session_replication_role = replica"))
    await pg_session.execute(
        text(
            "INSERT INTO reasoning_traces "
            "(id,created_at,session_id,agent_name,started_at,completed_at) "
            "VALUES (:id,:t,:session,'orphan',:t,:t)"
        ),
        {"id": orphan_trace_id, "session": orphan_session_id, "t": settled},
    )
    for ordinal, parent in ((1, trace_id), (2, missing_trace_id)):
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
    assert result.traces_without_session == 1
    assert result.steps_without_trace == 1
