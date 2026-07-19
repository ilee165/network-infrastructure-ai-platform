"""Durable audit for agent-triggered report generation (PR #166 F3).

The HTTP path (``POST /api/v1/reports``) commits a
``report.generation_requested`` audit entry BEFORE dispatching the Celery
task; the agent path must leave the same durable evidence. This framework
helper owns that write so specialist agents keep reaching ``app.services``
only through ``app.agents.framework`` (REPO-STRUCTURE §3.3 contract 2 /
§3.2 row 10 — the ``credential_access`` / ``discovery_jobs`` precedent).
"""

from __future__ import annotations

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
) -> None:
    """Commit one ``report.generation_requested`` audit entry.

    Committed on its own session so the evidence is durable BEFORE the caller
    enqueues the generation task — a broker failure after this returns can
    never lose the record that *actor* requested the run (PR #166 F3).
    """
    import app.db as db
    from app.services import audit

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
        await session.commit()
