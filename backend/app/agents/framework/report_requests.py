"""Durable audit and enqueue for agent-triggered report generation.

The HTTP and agent paths persist the ``report.generation_requested`` audit
entry, report run, and durable dispatch envelope in one transaction.  This
framework helper owns those writes so specialist agents keep reaching
``app.services`` only through ``app.agents.framework`` (REPO-STRUCTURE §3.3
contract 2 / §3.2 row 10 — the ``credential_access`` / ``discovery_jobs``
precedent).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

#: Must match ``app.api.v1.reports._GENERATION_REQUESTED`` — the agent and
#: HTTP triggers write ONE event stream for generation requests.
GENERATION_REQUESTED_ACTION = "report.generation_requested"


async def record_generation_requested(
    *,
    actor: str,
    run_id: UUID,
    kind: str,
    period_start: str,
    period_end: str,
    requested_by: UUID | None,
) -> None:
    """Commit audit, report run, and dispatch envelope in one transaction."""
    import app.db as db
    from app.models.reports import ReportKind
    from app.services import audit
    from app.services.report_outbox import enqueue_report

    async with db.get_sessionmaker()() as session:
        await audit.record(
            session,
            actor=actor,
            action=GENERATION_REQUESTED_ACTION,
            target_type="report_run",
            target_id=str(run_id),
            detail={
                "kind": kind,
                "period_start": period_start,
                "period_end": period_end,
            },
        )
        await enqueue_report(
            session,
            run_id=run_id,
            kind=ReportKind(kind),
            period_start=datetime.fromisoformat(period_start),
            period_end=datetime.fromisoformat(period_end),
            trigger="on_demand",
            requested_by=requested_by,
        )
        await session.commit()
