"""Report engine Celery tasks on the ``docs`` queue (P4 W3-T1; ADR-0053 §2/§4).

``reports.generate`` / ``reports.generate_scheduled`` drive the single
payload→artifact path in :mod:`app.engines.reports`; ``reports.purge_expired``
is the daily retention sweep (ADR-0053 §4); ``reports.compliance_sweep``
populates the §7.2 trend history (status/severity only — secret-free by
construction).

Idempotency under redelivery AND beat/on-demand collision (ADR-0053 §2, the
``_claim_backup_run`` precedent): a run's PK is the DETERMINISTIC UUID of its
``(kind, period)``; :func:`_claim_report_run` INSERTs it inside a SAVEPOINT
(PR #166 F1: PostgreSQL only suppresses conflicts on the ``(id)`` ARBITER —
under true concurrency the sibling ``uq_report_runs_kind_period`` unique index
can trip FIRST and raise, so ANY :class:`IntegrityError` is caught and
classified) and classifies a conflict as

* ``skipped``  — the run already SUCCEEDED (a genuine duplicate: no second
  artifact, no second audit pair);
* ``in_progress`` — the row is non-terminal and its ``updated_at`` claim
  heartbeat is YOUNGER than ``report_claim_timeout_seconds`` (PR #166 F2):
  another worker actively owns the generation, so the loser returns WITHOUT
  generating (no duplicate ``report.generated`` audit entry, no interleaved
  artifact delete+insert);
* ``resumed``  — the row is stuck non-terminal AND stale (its heartbeat aged
  past the timeout — the prior claim died with the worker); the generation is
  recovered, not lost;
* ``reclaimed`` — the run previously FAILED (e.g. ``redaction_violation``); a
  fresh request re-attempts it, so a fixed payload can regenerate the period —
  fail-closed redaction blocks a report until fixed, never forever.

Fail-closed redaction (ADR-0053 §6): a
:class:`~app.engines.reports.redaction.RedactionViolationError` marks the run
``failed`` with the TYPED ``redaction_violation`` class, increments
``netops_report_failures_total``, writes an audit entry naming the FIELD PATH
only (never the value), and persists no partial artifact.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from uuid import UUID, uuid4

import structlog
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import aliased

from app import db
from app.core.config import Settings, get_settings
from app.core.metrics import (
    observe_report_generation,
    record_report_failure,
    record_report_outbox_event,
    set_report_last_success,
)
from app.engines.config_mgmt.compliance.engine import DeviceContext, evaluate_policy
from app.engines.config_mgmt.compliance.loader import load_default_pack
from app.engines.reports import (
    ENGINE_VERSION,
    RedactionViolationError,
    RenderEgressBlockedError,
    build_payload,
    deterministic_run_id,
    render_artifacts,
    scheduled_period,
)
from app.engines.reports.builders import REGIME_TAG_DEFAULTS
from app.engines.reports.compliance_posture import OUT_OF_SCOPE_VENDORS
from app.models import Device
from app.models.compliance_history import (
    ComplianceRun,
    ComplianceRunFinding,
    ComplianceSweepTrigger,
)
from app.models.config_mgmt import ConfigSnapshot
from app.models.dispatch_outbox import DispatchConsumerState
from app.models.reports import (
    ReportArtifact,
    ReportKind,
    ReportRun,
    ReportRunStatus,
    ReportTrigger,
)
from app.services import audit
from app.services.report_outbox import (
    ConsumerClaimStatus,
    InvalidDispatchEnvelope,
    claim_consumer,
    lock_owned_consumer,
)
from app.workers.celery_app import celery_app

__all__ = [
    "compliance_sweep",
    "generate",
    "generate_scheduled",
    "purge_expired",
    "seed_last_success_gauges",
]

logger = structlog.get_logger(__name__)

#: Audit actor for worker-side report events (the requesting user, when any,
#: is carried in ``detail.requested_by`` — the API layer separately audits the
#: request under the user's own actor string).
_ACTOR: Final = "worker:reports"

# Audit action vocabulary (worker-local, mirroring the config-queue pattern).
_REPORT_GENERATED: Final = "report.generated"
_REPORT_GENERATION_FAILED: Final = "report.generation_failed"
_REPORT_PURGE_SWEPT: Final = "report.purge_swept"
_COMPLIANCE_SWEEP_COMPLETED: Final = "compliance.sweep_completed"

#: Typed error classes for ``report_runs.error_class`` and the failure counter
#: (ADR-0053 §1/§9). NEVER free-form text.
ERROR_CLASS_REDACTION: Final = "redaction_violation"
ERROR_CLASS_BUILDER: Final = "builder_error"
ERROR_CLASS_RENDER: Final = "render_error"
ERROR_CLASS_PERSISTENCE: Final = "persistence_error"


class ReportConsumerActive(RuntimeError):
    """A young durable consumer lease is owned by another delivery."""


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    """New async engine for one task phase (loop-scoped, disposed after use)."""
    return db.create_engine(get_settings())


@asynccontextmanager
async def _session() -> AsyncIterator[AsyncSession]:
    """One AsyncSession on a fresh engine, disposed when the phase ends."""
    engine = _make_engine()
    try:
        async with db.create_sessionmaker(engine)() as session:
            yield session
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Claim-row guard (ADR-0053 §2 — the ``_claim_backup_run`` precedent)
# ---------------------------------------------------------------------------


async def _claim_report_run(
    *,
    run_id: UUID,
    kind: ReportKind,
    trigger: str,
    requested_by: UUID | None,
    period_start: datetime,
    period_end: datetime,
    dispatch_id: UUID | None = None,
) -> str:
    """INSERT the ``report_runs`` claim row; classify ANY unique conflict.

    Returns ``"claimed"`` (fresh insert), ``"skipped"`` (already succeeded),
    ``"in_progress"`` (another worker actively owns a young claim — the caller
    must NOT generate), ``"resumed"`` (stale non-terminal claim from a dead
    worker, ownership taken over), or ``"reclaimed"`` (previously failed;
    reset to ``running`` for a re-attempt). See the module docstring.

    PR #166 F1: the INSERT runs inside a SAVEPOINT catching
    :class:`IntegrityError` — PostgreSQL only suppresses conflicts on the
    ``(id)`` arbiter index, and under true concurrency the sibling
    ``uq_report_runs_kind_period`` unique index can trip first and raise. The
    deterministic id means id-conflict iff natural-key-conflict, so both
    manifestations classify against the same existing row.

    PR #166 F2: classification re-selects the row ``FOR UPDATE`` (no-op on
    SQLite) so reclaim/stale-takeover is an atomic compare-and-swap — two
    simultaneous resumers serialize, and the second re-reads the refreshed
    ``updated_at`` heartbeat and backs off with ``in_progress``.
    """
    settings = get_settings()
    async with _session() as session:
        dialect = session.bind.dialect.name if session.bind is not None else "sqlite"
        values: dict[str, Any] = {
            "id": run_id,
            "kind": kind.value,
            "trigger": trigger,
            "requested_by": requested_by,
            "period_start": period_start,
            "period_end": period_end,
            "status": ReportRunStatus.RUNNING.value,
            "error_class": None,
            "regime_tags": list(REGIME_TAG_DEFAULTS[kind]),
            "finished_at": None,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        if dialect == "postgresql":
            stmt: Any = (
                pg_insert(ReportRun).values(**values).on_conflict_do_nothing(index_elements=["id"])
            )
        else:
            stmt = sqlite_insert(ReportRun).values(**values).on_conflict_do_nothing()
        inserted = False
        try:
            async with session.begin_nested():
                cursor = await session.execute(stmt)
                inserted = cursor.rowcount == 1  # type: ignore[attr-defined]
        except IntegrityError:
            # The sibling unique index raised before the arbiter could
            # suppress: same natural key, same deterministic id — classify
            # the existing row exactly like an arbiter conflict.
            inserted = False
        if inserted:
            await session.commit()
            return "claimed"
        existing = (
            await session.execute(select(ReportRun).where(ReportRun.id == run_id).with_for_update())
        ).scalar_one_or_none()
        if existing is None:
            # Conflict raised but the row vanished before re-select (e.g. a
            # concurrent delete). Never generate on a guess — report the
            # non-generating outcome; a redelivery re-claims cleanly.
            await session.commit()
            return "in_progress"
        if existing.status == ReportRunStatus.SUCCEEDED.value:
            await session.commit()
            return "skipped"
        if existing.status == ReportRunStatus.QUEUED.value and dispatch_id is not None:
            await session.execute(
                update(ReportRun)
                .where(
                    ReportRun.id == run_id,
                    ReportRun.status == ReportRunStatus.QUEUED.value,
                )
                .values(status=ReportRunStatus.RUNNING.value, updated_at=datetime.now(UTC))
            )
            await session.commit()
            return "claimed"
        if existing.status == ReportRunStatus.FAILED.value:
            # A failed period is re-attemptable (fail-closed redaction must not
            # block a period forever once the payload is fixed): reset the row.
            await session.execute(
                update(ReportRun)
                .where(ReportRun.id == run_id, ReportRun.status == ReportRunStatus.FAILED.value)
                .values(
                    status=ReportRunStatus.RUNNING.value,
                    error_class=None,
                    finished_at=None,
                    trigger=trigger,
                    requested_by=requested_by,
                )
            )
            await session.commit()
            return "reclaimed"
        # Non-terminal (running/queued): resume ONLY a stale claim whose
        # updated_at heartbeat aged past the takeover timeout (PR #166 F2).
        age = datetime.now(UTC) - existing.updated_at
        if age > timedelta(seconds=settings.report_claim_timeout_seconds):
            await session.execute(
                update(ReportRun)
                .where(ReportRun.id == run_id)
                .values(
                    status=ReportRunStatus.RUNNING.value,
                    trigger=trigger,
                    requested_by=requested_by,
                    updated_at=datetime.now(UTC),  # take ownership: fresh heartbeat
                )
            )
            await session.commit()
            return "resumed"
        # Young claim: another worker is actively generating. Back off.
        await session.commit()
        return "in_progress"


async def _fail_run(
    run_id: UUID,
    kind: ReportKind,
    error_class: str,
    detail: dict[str, Any],
    *,
    dispatch_id: UUID,
    owner: str,
) -> bool:
    """Mark the run ``failed`` (typed class) + audit — unless already succeeded.

    *detail* must carry field paths / rule names / class tokens ONLY — never a
    payload value (ADR-0053 §6: a redaction failure must not itself leak).
    """
    async with _session() as session:
        consumer = await lock_owned_consumer(session, dispatch_id=dispatch_id, owner=owner)
        if consumer is None:
            await session.rollback()
            return False
        cursor = await session.execute(
            update(ReportRun)
            .where(ReportRun.id == run_id, ReportRun.status != ReportRunStatus.SUCCEEDED.value)
            .values(
                status=ReportRunStatus.FAILED.value,
                error_class=error_class,
                finished_at=datetime.now(UTC),
            )
        )
        if cursor.rowcount == 1:  # type: ignore[attr-defined]
            consumer.consumer_state = DispatchConsumerState.FAILED.value
            consumer.consumer_owner = None
            consumer.consumer_claimed_at = None
            consumer.consumer_finished_at = datetime.now(UTC)
            consumer.consumer_error_code = error_class
            await audit.record(
                session,
                actor=_ACTOR,
                action=_REPORT_GENERATION_FAILED,
                target_type="report_run",
                target_id=str(run_id),
                detail={"kind": kind.value, "error_class": error_class, **detail},
            )
        await session.commit()
    record_report_failure(report_kind=kind.value, error_class=error_class)
    return True


# ---------------------------------------------------------------------------
# Generation core (single render path — engines/reports owns payload→artifact)
# ---------------------------------------------------------------------------


def _retention_days(settings: Settings, kind: ReportKind) -> int:
    """Per-kind artifact retention (ADR-0053 §4): override or the 7-year default."""
    override: int | None = {
        ReportKind.CHANGE: settings.report_change_retention_days,
        ReportKind.COMPLIANCE_POSTURE: settings.report_compliance_posture_retention_days,
        ReportKind.ACCESS_REVIEW: settings.report_access_review_retention_days,
        ReportKind.AUDIT_INTEGRITY: settings.report_audit_integrity_retention_days,
    }[kind]
    return override if override is not None else settings.report_retention_days


def _parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 task argument into an aware-UTC datetime."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


async def _generate_report_core(
    dispatch_id_value: str,
    run_id_value: str,
) -> dict[str, Any]:
    """Load authoritative row → claim dispatch → render → terminal transition."""
    try:
        dispatch_id = UUID(dispatch_id_value)
        run_id = UUID(run_id_value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidDispatchEnvelope("invalid_consumer_identifier") from exc
    owner = f"{socket.gethostname()}:{uuid4()}"
    async with _session() as session:
        claim = await claim_consumer(
            session,
            dispatch_id=dispatch_id,
            run_id=run_id,
            owner=owner,
            lease_seconds=get_settings().report_claim_timeout_seconds,
            now=datetime.now(UTC),
        )
        await session.commit()
    kind = claim.kind
    trigger = claim.trigger
    requested_by = str(claim.requested_by) if claim.requested_by else None
    period_start = claim.period_start
    period_end = claim.period_end
    ReportTrigger(trigger)
    run_id_str = str(run_id)

    if claim.status in {ConsumerClaimStatus.SUCCEEDED, ConsumerClaimStatus.FAILED}:
        record_report_outbox_event(event="duplicate_consumer")
        logger.info("reports.generate_skipped_duplicate", run_id=run_id_str, kind=kind.value)
        return {"run_id": run_id_str, "status": claim.status.value}
    if claim.status is ConsumerClaimStatus.ACTIVE:
        record_report_outbox_event(event="duplicate_consumer")
        logger.info("reports.generate_claim_active_elsewhere", run_id=run_id_str, kind=kind.value)
        raise ReportConsumerActive("consumer_active")
    if claim.status is ConsumerClaimStatus.RECOVERED:
        record_report_outbox_event(event="consumer_recovered")
    logger.info(
        "reports.generate_started",
        run_id=run_id_str,
        kind=kind.value,
        trigger=trigger,
        claim=claim.status.value,
    )

    started = time.monotonic()
    generated_at = datetime.now(UTC)

    # Phase 1 — payload assembly (allowlisted sources only; typed failure class).
    try:
        async with _session() as session:
            payload = await build_payload(
                session,
                kind=kind,
                period_start=period_start,
                period_end=period_end,
                generated_at=generated_at,
            )
    except Exception as exc:
        logger.error(
            "reports.builder_failed",
            run_id=run_id_str,
            kind=kind.value,
            reason_class=type(exc).__name__,
        )
        await _fail_run(
            run_id,
            kind,
            ERROR_CLASS_BUILDER,
            {"exception": type(exc).__name__},
            dispatch_id=dispatch_id,
            owner=owner,
        )
        return {"run_id": run_id_str, "status": "failed", "error_class": ERROR_CLASS_BUILDER}

    # Phase 2 — THE single render path (redaction choke point runs first inside).
    try:
        artifacts = await asyncio.to_thread(render_artifacts, payload)
    except RedactionViolationError as exc:
        # Field path + rule ONLY — the value is never captured (ADR-0053 §6).
        logger.error(
            "reports.redaction_violation",
            run_id=run_id_str,
            kind=kind.value,
            field_path=exc.field_path,
            rule=exc.rule,
        )
        await _fail_run(
            run_id,
            kind,
            ERROR_CLASS_REDACTION,
            {"field_path": exc.field_path, "rule": exc.rule},
            dispatch_id=dispatch_id,
            owner=owner,
        )
        return {"run_id": run_id_str, "status": "failed", "error_class": ERROR_CLASS_REDACTION}
    except RenderEgressBlockedError:
        logger.error("reports.render_egress_blocked", run_id=run_id_str, kind=kind.value)
        await _fail_run(
            run_id,
            kind,
            ERROR_CLASS_RENDER,
            {"reason": "egress_blocked"},
            dispatch_id=dispatch_id,
            owner=owner,
        )
        return {"run_id": run_id_str, "status": "failed", "error_class": ERROR_CLASS_RENDER}
    except Exception as exc:
        logger.error(
            "reports.render_failed",
            run_id=run_id_str,
            kind=kind.value,
            reason_class=type(exc).__name__,
        )
        await _fail_run(
            run_id,
            kind,
            ERROR_CLASS_RENDER,
            {"exception": type(exc).__name__},
            dispatch_id=dispatch_id,
            owner=owner,
        )
        return {"run_id": run_id_str, "status": "failed", "error_class": ERROR_CLASS_RENDER}

    # Phase 3 — persist artifacts + terminal status + the generation audit entry.
    settings = get_settings()
    expires_at = generated_at + timedelta(days=_retention_days(settings, kind))
    finished_at = datetime.now(UTC)
    try:
        async with _session() as session:
            try:
                consumer = await lock_owned_consumer(session, dispatch_id=dispatch_id, owner=owner)
                if consumer is None:
                    await session.rollback()
                    return {"run_id": run_id_str, "status": "ownership_lost"}
                # A resumed claim may already carry artifacts from the dead
                # attempt: replace them so the run's artifacts always match
                # its final render.
                await session.execute(delete(ReportArtifact).where(ReportArtifact.run_id == run_id))
                for rendered in artifacts:
                    session.add(
                        ReportArtifact(
                            run_id=run_id,
                            format=rendered.format.value,
                            content=rendered.content,
                            sha256=rendered.sha256,
                            size_bytes=rendered.size_bytes,
                            expires_at=expires_at,
                        )
                    )
                await session.execute(
                    update(ReportRun)
                    .where(ReportRun.id == run_id)
                    .values(
                        status=ReportRunStatus.SUCCEEDED.value,
                        finished_at=finished_at,
                        regime_tags=list(REGIME_TAG_DEFAULTS[kind]),
                    )
                )
                consumer.consumer_state = DispatchConsumerState.SUCCEEDED.value
                consumer.consumer_owner = None
                consumer.consumer_claimed_at = None
                consumer.consumer_finished_at = finished_at
                consumer.consumer_error_code = None
                await audit.record(
                    session,
                    actor=_ACTOR,
                    action=_REPORT_GENERATED,
                    target_type="report_run",
                    target_id=run_id_str,
                    detail={
                        "kind": kind.value,
                        "trigger": trigger,
                        "requested_by": requested_by,
                        "artifacts": [
                            {
                                "format": a.format.value,
                                "sha256": a.sha256,
                                "size_bytes": a.size_bytes,
                            }
                            for a in artifacts
                        ],
                    },
                )
                await session.commit()
            except Exception:
                # Roll back the partial delete/insert/update/audit as ONE
                # unit (artifact-consistency preserved: never a half-swapped
                # artifact set) before re-raising to the outer handler below.
                await session.rollback()
                raise
    except Exception as exc:
        # PR #166 F2 (stranded RUNNING): Phases 1-2 already route failures to
        # _fail_run; Phase 3 must too — an ordinary persistence exception here
        # (e.g. a constraint violation, a dropped connection mid-commit) would
        # otherwise propagate out of this task with NO retry configured,
        # leaving the claim ``running`` forever. Routing to _fail_run marks it
        # FAILED, which _claim_report_run's "reclaimed" path makes reclaimable
        # by the next request for this period — never a permanently stuck run.
        logger.error(
            "reports.persist_failed",
            run_id=run_id_str,
            kind=kind.value,
            reason_class=type(exc).__name__,
        )
        await _fail_run(
            run_id,
            kind,
            ERROR_CLASS_PERSISTENCE,
            {"exception": type(exc).__name__},
            dispatch_id=dispatch_id,
            owner=owner,
        )
        return {"run_id": run_id_str, "status": "failed", "error_class": ERROR_CLASS_PERSISTENCE}

    duration = time.monotonic() - started
    observe_report_generation(report_kind=kind.value, duration_seconds=duration)
    set_report_last_success(report_kind=kind.value, timestamp=finished_at.timestamp())
    logger.info(
        "reports.generate_finished",
        run_id=run_id_str,
        kind=kind.value,
        artifacts=len(artifacts),
        duration_seconds=round(duration, 3),
    )
    return {
        "run_id": run_id_str,
        "status": "succeeded",
        "artifacts": [{"format": a.format.value, "sha256": a.sha256} for a in artifacts],
    }


@celery_app.task(name="reports.generate", bind=True, max_retries=None)
def generate(task: Any, dispatch_id: str, run_id: str) -> dict[str, Any]:
    """Consume one identifier-only durable report envelope."""
    try:
        return dict(asyncio.run(_generate_report_core(dispatch_id, run_id)))
    except ReportConsumerActive as exc:
        raise task.retry(
            exc=RuntimeError("consumer_active"), countdown=5, max_retries=None
        ) from exc


@celery_app.task(name="reports.generate_scheduled")
def generate_scheduled(
    kind: str,
    period_start: str | None = None,
    period_end: str | None = None,
) -> dict[str, Any]:
    """Beat entrypoint: generate *kind* for its dispatch-computed cadence period.

    PR #166 F2 (beat-slot identity): *period_start*/*period_end* are the
    cadence period bounds computed by Celery beat AT DISPATCH TIME (via
    ``celery.beat.BeatLazyFunc`` in ``beat_schedule`` — see
    :mod:`app.workers.celery_app`), not recomputed here at EXECUTION time —
    a redelivered task or one delayed past a UTC-midnight boundary would
    otherwise derive a different (wrong) period from ``datetime.now(UTC)``
    at whatever moment it happens to run, permanently ungenerating the
    period beat actually meant. Only a legacy empty message (a pre-fix beat
    process, or a manual/test invocation with no bounds) falls back to
    computing the period from the current wall clock — the prior,
    execution-time-derived behavior.
    """
    if period_start is None or period_end is None:
        settings = get_settings()
        cadence = {
            ReportKind.CHANGE: settings.report_change_cadence,
            ReportKind.COMPLIANCE_POSTURE: settings.report_compliance_posture_cadence,
            ReportKind.ACCESS_REVIEW: settings.report_access_review_cadence,
            ReportKind.AUDIT_INTEGRITY: settings.report_audit_integrity_cadence,
        }[ReportKind(kind)]
        start_dt, end_dt = scheduled_period(cadence, datetime.now(UTC))
        period_start = start_dt.isoformat()
        period_end = end_dt.isoformat()

    async def _enqueue() -> dict[str, Any]:
        from app.services.report_outbox import enqueue_report

        kind_enum = ReportKind(kind)
        start = _parse_utc(period_start)
        end = _parse_utc(period_end)
        async with _session() as session:
            run = await enqueue_report(
                session,
                run_id=deterministic_run_id(kind_enum, start, end),
                kind=kind_enum,
                period_start=start,
                period_end=end,
                trigger=ReportTrigger.SCHEDULED.value,
                requested_by=None,
            )
            await session.commit()
        return {"run_id": str(run.id), "status": "queued"}

    return dict(asyncio.run(_enqueue()))


# ---------------------------------------------------------------------------
# Retention purge (ADR-0053 §4 — the pcap/raw-artifact purge pattern)
# ---------------------------------------------------------------------------


async def _purge_expired_core() -> dict[str, Any]:
    """Hard-delete expired report artifacts and audit the sweep."""
    now = datetime.now(UTC)
    async with _session() as session:
        expired_ids = list(
            (
                await session.execute(
                    select(ReportArtifact.id).where(ReportArtifact.expires_at < now)
                )
            ).scalars()
        )
        if expired_ids:
            await session.execute(delete(ReportArtifact).where(ReportArtifact.id.in_(expired_ids)))
        await audit.record(
            session,
            actor=_ACTOR,
            action=_REPORT_PURGE_SWEPT,
            target_type="report_artifact",
            target_id=None,
            detail={"deleted": len(expired_ids), "cutoff": now.isoformat()},
        )
        await session.commit()
    logger.info("reports.purge_finished", deleted=len(expired_ids))
    return {"deleted": len(expired_ids)}


@celery_app.task(name="reports.purge_expired")
def purge_expired() -> dict[str, Any]:
    """Daily retention purge of expired report artifacts (ADR-0053 §4)."""
    return dict(asyncio.run(_purge_expired_core()))


# ---------------------------------------------------------------------------
# Daily compliance evaluation sweep (ADR-0053 §2 → §7.2 trend history)
# ---------------------------------------------------------------------------


def _sweep_slot_uuid(slot: str) -> UUID:
    """Deterministic ``compliance_runs`` PK per UTC-date slot (redelivery-safe)."""
    digest = hashlib.sha256(f"reports.compliance_sweep:{slot}".encode()).digest()
    return UUID(bytes=digest[:16])


#: Vendors with NO text-config compliance surface at all (ADR-0050 §7.6 /
#: ADR-0051 §3 named deferrals) — reported via the dedicated out-of-scope
#: vendor section (``app.engines.reports.compliance_posture``), never as an
#: "unevaluated" coverage gap (PR #166 F2): the two classes are mutually
#: exclusive so a device is never double-reported.
_OUT_OF_SCOPE_VENDOR_IDS: Final[frozenset[str]] = frozenset(
    vendor for vendor, _ in OUT_OF_SCOPE_VENDORS
)


async def _latest_snapshots_by_device(session: AsyncSession) -> dict[UUID, ConfigSnapshot]:
    """One bounded query for every device's latest ``ConfigSnapshot`` (PR #166 F4).

    The sweep previously issued one ``SELECT ... LIMIT 1`` per device inside
    the fan-out loop — an N+1 that scales linearly with the estate size on
    every daily run. A ``ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY
    captured_at DESC, created_at DESC)`` window, filtered to ``rn = 1``, is the
    dialect-portable equivalent of Postgres ``DISTINCT ON`` (SQLite — the unit
    suite's engine — has supported window functions since 3.25) and returns
    AT MOST one row per device in a single round trip. A device with no
    snapshot simply has no row here — the caller's ``dict.get`` returns
    ``None`` for it, preserving the existing "unevaluated coverage gap"
    behavior (PR #166 F2) exactly.
    """
    row_number = func.row_number().over(
        partition_by=ConfigSnapshot.device_id,
        order_by=(ConfigSnapshot.captured_at.desc(), ConfigSnapshot.created_at.desc()),
    )
    ranked = select(ConfigSnapshot, row_number.label("rn")).subquery()
    latest_snapshot = aliased(ConfigSnapshot, ranked)
    rows = (await session.execute(select(latest_snapshot).where(ranked.c.rn == 1))).scalars().all()
    return {row.device_id: row for row in rows}


async def _compliance_sweep_core(run_id: str | None = None) -> dict[str, Any]:
    """Evaluate the default policy pack across devices; persist secret-free history.

    Reads each device's latest snapshot content ONLY transiently for evaluation
    (exactly like the on-demand engineer+ endpoint) and persists status/severity
    per rule — NEVER an evidence excerpt (ADR-0053 §6 layer 3, §7.2).
    """
    slot = datetime.now(UTC).strftime("%Y-%m-%d")
    run_uuid = UUID(run_id) if run_id is not None else _sweep_slot_uuid(slot)
    executed_at = datetime.now(UTC)
    policy = load_default_pack()

    async with _session() as session:
        dialect = session.bind.dialect.name if session.bind is not None else "sqlite"
        values: dict[str, Any] = {
            "id": run_uuid,
            "executed_at": executed_at,
            "trigger": ComplianceSweepTrigger.SWEEP.value,
            "policy_id": policy.id,
            "policy_version": policy.version,
            "device_scope": [],
            "engine_version": ENGINE_VERSION,
            "created_at": executed_at,
            "updated_at": executed_at,
        }
        if dialect == "postgresql":
            stmt: Any = (
                pg_insert(ComplianceRun)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["id"])
            )
        else:
            stmt = sqlite_insert(ComplianceRun).values(**values).on_conflict_do_nothing()
        cursor = await session.execute(stmt)
        if cursor.rowcount == 0:  # type: ignore[attr-defined]
            await session.commit()
            logger.info("reports.compliance_sweep_skipped_duplicate", run_id=str(run_uuid))
            return {"run_id": str(run_uuid), "status": "skipped"}

        devices = list((await session.execute(select(Device))).scalars())
        # One bulk, bounded query for every device's latest snapshot (PR #166
        # F4) instead of a per-device round trip inside the fan-out below.
        latest_by_device = await _latest_snapshots_by_device(session)
        evaluated_ids: list[str] = []
        unevaluated_ids: list[str] = []
        finding_count = 0
        for device in devices:
            if device.vendor_id in _OUT_OF_SCOPE_VENDOR_IDS:
                # No text-config compliance surface AT ALL (ADR-0050 §7.6 /
                # ADR-0051 §3 named deferrals) — surfaced via the dedicated
                # out-of-scope vendor section, never as a coverage gap here.
                continue
            latest = latest_by_device.get(device.id)
            if latest is None:
                # Supported but UNEVALUATED (PR #166 F2): still recorded in
                # device_scope so the posture report can surface it as an
                # explicit coverage gap — a bare `continue` here would make
                # the device vanish with no finding and no scope trace,
                # letting a mostly-unevaluated estate read as a clean one.
                unevaluated_ids.append(str(device.id))
                continue
            ctx = DeviceContext(
                device_id=device.id,
                vendor=device.vendor_id,
                role=None,
                site=device.site,
                raw_config=latest.content,
            )
            for finding in evaluate_policy(policy, ctx):
                session.add(
                    ComplianceRunFinding(
                        run_id=run_uuid,
                        device_id=finding.device_id,
                        policy_id=finding.policy_id,
                        rule_id=finding.rule_id,
                        status=finding.status.value,
                        severity=finding.severity.value,
                    )
                )
                finding_count += 1
            evaluated_ids.append(str(device.id))

        await session.execute(
            update(ComplianceRun)
            .where(ComplianceRun.id == run_uuid)
            .values(device_scope=evaluated_ids + unevaluated_ids)
        )
        await audit.record(
            session,
            actor=_ACTOR,
            action=_COMPLIANCE_SWEEP_COMPLETED,
            target_type="compliance_run",
            target_id=str(run_uuid),
            detail={
                "devices": len(evaluated_ids),
                "unevaluated_devices": len(unevaluated_ids),
                "findings": finding_count,
                "policy_id": policy.id,
                "policy_version": policy.version,
            },
        )
        await session.commit()

    logger.info(
        "reports.compliance_sweep_finished",
        run_id=str(run_uuid),
        devices=len(evaluated_ids),
        unevaluated_devices=len(unevaluated_ids),
        findings=finding_count,
    )
    return {
        "run_id": str(run_uuid),
        "status": "succeeded",
        "devices": len(evaluated_ids),
        "unevaluated_devices": len(unevaluated_ids),
        "findings": finding_count,
    }


@celery_app.task(name="reports.compliance_sweep")
def compliance_sweep(run_id: str | None = None) -> dict[str, Any]:
    """Daily compliance evaluation sweep feeding the §7.2 trend history."""
    return dict(asyncio.run(_compliance_sweep_core(run_id)))


# ---------------------------------------------------------------------------
# Startup gauge seeding (ADR-0053 §9 — PR #166 F6 "never-succeeded silence")
# ---------------------------------------------------------------------------


async def _seed_last_success_gauges_core(boot_timestamp: float) -> None:
    """Re-hydrate the staleness gauge for all four report kinds at worker boot.

    The staleness alerts (``time() - netops_report_last_success_timestamp >
    cadence + grace``) return NO SERIES for a kind whose gauge was never SET —
    ``set_report_last_success`` is only ever called from the SUCCESS path, so
    a kind that has never once generated successfully (a fresh deployment, or
    one whose every attempt has failed) never gets a sample, and its
    staleness alert stays silently unreachable forever — even though "never
    succeeded" is the worst case the alert exists to catch.

    Seeding at worker boot closes the gap WITHOUT masking a genuine existing
    staleness: this reads the DURABLE last-SUCCEEDED ``ReportRun.finished_at``
    per kind from Postgres (never the ephemeral in-memory gauge, which is
    per-process and reset on restart), so:

    * a kind that HAS succeeded before re-hydrates to its TRUE last success
      timestamp — a real, already-stale condition survives a worker restart
      instead of resetting to "fresh" every time an operator restarts the
      worker for an unrelated reason;
    * a kind that has NEVER succeeded gets *boot_timestamp* — a series now
      exists, so the existing cadence+grace expression starts counting and
      fires on schedule instead of staying silent forever.

    Coordinates with the PR #166 F4 ``mostrecent`` multiprocess gauge mode:
    this write's VALUE is the historical timestamp (never "now"), so even
    though the WRITE itself happens at boot, a later real success — written
    from a different prefork-child process — always carries a later write
    timestamp and correctly wins the ``mostrecent`` aggregation; a boot-time
    reseed can never mask or roll back a real success already on record.
    """
    async with _session() as session:
        for kind in ReportKind:
            latest_finished_at = (
                await session.execute(
                    select(ReportRun.finished_at)
                    .where(
                        ReportRun.kind == kind.value,
                        ReportRun.status == ReportRunStatus.SUCCEEDED.value,
                    )
                    .order_by(ReportRun.finished_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            timestamp = (
                latest_finished_at.timestamp() if latest_finished_at is not None else boot_timestamp
            )
            set_report_last_success(report_kind=kind.value, timestamp=timestamp)


def seed_last_success_gauges() -> None:
    """Sync entrypoint for the ``worker_init`` signal (PR #166 F4/F6).

    Graceful by design (mirrors ``app.workers.celery_app.start_worker_metrics_
    server``): a DB hiccup at worker boot is logged and swallowed, never
    raised — a staleness-gauge seeding failure must not crash the worker or
    block it from draining its queue.
    """
    try:
        asyncio.run(_seed_last_success_gauges_core(datetime.now(UTC).timestamp()))
    except Exception:
        logger.exception("reports.seed_last_success_gauges_failed")
