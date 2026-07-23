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
