"""Report engine endpoints on ``/api/v1/reports`` (P4 W3-T1; ADR-0053 §2/§3).

Routes:

    POST /reports                                   per-kind floor  request generation (202)
    GET  /reports                                   viewer+ (rows RBAC-filtered per kind)
    GET  /reports/{run_id}                          visible kinds only  run + artifact metadata
    GET  /reports/{run_id}/artifacts/{artifact_id}  visible kinds only  artifact bytes download

RBAC (ADR-0053 §3): the per-kind role floor (change/compliance-posture →
engineer+; access-review/audit-integrity → admin) is enforced at BOTH the
generation trigger and the artifact download. The floor is evaluated against
the caller's CURRENT role resolved from the database on every request
(``get_current_user``) — a role change between generation and download is
honored at download time; nothing is cached.

403-vs-404 seam (PR #166 F3): run-id-addressed endpoints answer 404 for an
above-floor run, IDENTICAL to a missing one — run ids are deterministic for
``(kind, period)`` and computable offline, so a 403-on-existing response would
disclose which admin-only report runs exist to sub-floor callers (existence is
RBAC-scoped metadata, ADR-0053 §3). The kind-addressed checks (POST body kind,
GET ?kind=) stay 403: report kinds are a static, public enum — a kind-level
denial reveals nothing about any run's existence.

Every generation request and every artifact download writes an audit entry
(actor, report kind, run id, artifact sha256) — evidence about evidence.

No ChangeRequest: report generation mutates only the platform's own report
tables and never touches a device (ADR-0053 §3, the ADR-0052 tagging
classification).
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db, require_role
from app.core.errors import ForbiddenError, NotFoundError
from app.core.security import Role
from app.engines.reports import deterministic_run_id, kinds_visible_to, required_role
from app.models import User
from app.models.reports import ReportArtifact, ReportFormat, ReportKind, ReportRun
from app.schemas.reports_api import (
    ReportGenerationQueued,
    ReportGenerationRequest,
    ReportRunDetail,
    ReportRunListResponse,
    ReportRunRead,
)
from app.services import audit
from app.services.report_outbox import enqueue_report, requeue_dead

router = APIRouter(prefix="/reports", tags=["reports"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
#: Base authentication only — the per-kind floor is enforced per handler
#: (viewer is the platform-wide authenticated baseline; no report kind has a
#: floor below engineer, so the handler check is always the binding one).
AuthedUser = Annotated[User, Depends(require_role("viewer"))]

_GENERATION_REQUESTED = "report.generation_requested"
_ARTIFACT_DOWNLOADED = "report.artifact_downloaded"
_OUTBOX_REQUEUED = "report.outbox_requeued"

_MEDIA_TYPES = {
    ReportFormat.CSV.value: "text/csv; charset=utf-8",
    ReportFormat.PDF.value: "application/pdf",
}


def _enforce_kind_floor(user: User, kind: ReportKind) -> None:
    """403 unless the caller's CURRENT role meets the ADR-0053 §3 kind floor."""
    role = Role.from_name(user.role.name)
    if role is None or not role.can_act_as(required_role(kind)):
        raise ForbiddenError(
            f"the {kind.value!r} report requires the {required_role(kind).value!r} role or higher"
        )


async def _get_visible_run_or_404(
    session: AsyncSession, run_id: uuid.UUID, user: User
) -> ReportRun:
    """The run, IF its kind is visible to the caller's current role — else 404.

    Missing and above-floor resolve to the SAME 404 (PR #166 F3): run ids are
    deterministic for ``(kind, period)`` and computable offline, so a
    distinguishable denial would confirm which admin-only runs exist to a
    sub-floor caller (existence is RBAC-scoped metadata, ADR-0053 §3).
    """
    kinds = sorted(k.value for k in kinds_visible_to(Role.from_name(user.role.name)))
    run: ReportRun | None = None
    if kinds:
        run = (
            await session.execute(
                select(ReportRun)
                .options(selectinload(ReportRun.artifacts))
                .where(ReportRun.id == run_id, ReportRun.kind.in_(kinds))
            )
        ).scalar_one_or_none()
    if run is None:
        raise NotFoundError(f"report run {run_id} does not exist")
    return run


@router.post("", response_model=ReportGenerationQueued, status_code=202)
async def request_generation(
    body: ReportGenerationRequest,
    session: DbSession,
    user: AuthedUser,
) -> ReportGenerationQueued:
    """Enqueue an on-demand generation for ``(kind, period)`` (ADR-0053 §2).

    202: the render happens asynchronously on the ``docs`` queue. The returned
    ``run_id`` is DETERMINISTIC for the period — a beat run or a second request
    for the same ``(kind, period)`` resolves to the same run (claim-row guard;
    no double generation). Audited under the requesting user.
    """
    _enforce_kind_floor(user, body.kind)
    run_id = deterministic_run_id(body.kind, body.period_start, body.period_end)
    await audit.record(
        session,
        actor=f"user:{user.username}",
        action=_GENERATION_REQUESTED,
        target_type="report_run",
        target_id=str(run_id),
        detail={
            "kind": body.kind.value,
            "period_start": body.period_start.isoformat(),
            "period_end": body.period_end.isoformat(),
        },
    )
    await enqueue_report(
        session,
        run_id=run_id,
        kind=body.kind,
        period_start=body.period_start,
        period_end=body.period_end,
        trigger="on_demand",
        requested_by=user.id,
    )
    await session.commit()
    return ReportGenerationQueued(run_id=run_id, status="queued")


@router.post("/outbox/{dispatch_id}/requeue", status_code=204)
async def requeue_dead_dispatch(
    dispatch_id: uuid.UUID,
    session: DbSession,
    admin: Annotated[User, Depends(require_role("admin"))],
) -> Response:
    """Admin-only, audited replay of a validated dead report envelope."""
    row = await requeue_dead(session, dispatch_id)
    if row is None:
        raise NotFoundError(f"dead report dispatch {dispatch_id} does not exist")
    await audit.record(
        session,
        actor=f"user:{admin.username}",
        action=_OUTBOX_REQUEUED,
        target_type="dispatch_outbox",
        target_id=str(dispatch_id),
        detail={"aggregate_type": row.aggregate_type, "aggregate_id": str(row.aggregate_id)},
    )
    await session.commit()
    return Response(status_code=204)


@router.get("", response_model=ReportRunListResponse)
async def list_runs(
    session: DbSession,
    user: AuthedUser,
    kind: Annotated[ReportKind | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ReportRunListResponse:
    """List report runs, newest first — RBAC-scoped to kinds the caller may see.

    A run of a kind above the caller's floor is never listed (an engineer does
    not learn access-review runs exist); explicitly requesting such a kind is a
    403, not an empty page.
    """
    visible = kinds_visible_to(Role.from_name(user.role.name))
    if kind is not None:
        _enforce_kind_floor(user, kind)
        kinds = [kind.value]
    else:
        kinds = sorted(k.value for k in visible)
    if not kinds:
        return ReportRunListResponse(items=[], total=0, limit=limit, offset=offset)
    base = select(ReportRun).where(ReportRun.kind.in_(kinds))
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                base.order_by(ReportRun.created_at.desc(), ReportRun.id).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ReportRunListResponse(
        items=[ReportRunRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{run_id}", response_model=ReportRunDetail)
async def get_run(
    run_id: uuid.UUID,
    session: DbSession,
    user: AuthedUser,
) -> ReportRunDetail:
    """One run's metadata + artifact metadata (visible kinds only; 404 seam)."""
    run = await _get_visible_run_or_404(session, run_id, user)
    return ReportRunDetail.model_validate(run)


@router.get(
    "/{run_id}/artifacts/{artifact_id}",
    responses={
        200: {
            "content": {
                "text/csv": {"schema": {"type": "string", "format": "binary"}},
                "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            },
            "description": "The artifact bytes (CSV or PDF, per its ``format``).",
        },
    },
)
async def download_artifact(
    run_id: uuid.UUID,
    artifact_id: uuid.UUID,
    session: DbSession,
    user: AuthedUser,
) -> Response:
    """Download one artifact's bytes — the RBAC'd, audited evidence exit point.

    The per-kind floor is re-evaluated HERE against the caller's current role
    (ADR-0053 §3): an artifact is never world-readable once generated, and a
    role revoked between generation and download denies the download — as a
    404 identical to a missing run (the PR #166 F3 existence seam). Every
    download writes an audit entry carrying the artifact sha256.
    """
    run = await _get_visible_run_or_404(session, run_id, user)
    artifact = next((a for a in run.artifacts if a.id == artifact_id), None)
    if artifact is None:
        raise NotFoundError(f"report artifact {artifact_id} does not exist on run {run_id}")
    # ``ReportArtifact.content`` is a deferred column (PR #166 F4): the
    # ``_get_visible_run_or_404`` selectinload above never loaded it (a
    # metadata GET, and every OTHER sibling artifact on this run, would
    # otherwise pull every artifact's bytes). Explicitly select the bytes for
    # ONLY the one requested artifact — an ordinary awaited statement, never
    # an implicit lazy-load off a deferred attribute (which would raise
    # ``MissingGreenlet`` on this async session).
    content_stmt = select(ReportArtifact.content).where(ReportArtifact.id == artifact.id)
    content = (await session.execute(content_stmt)).scalar_one()
    await audit.record(
        session,
        actor=f"user:{user.username}",
        action=_ARTIFACT_DOWNLOADED,
        target_type="report_artifact",
        target_id=str(artifact.id),
        detail={
            "run_id": str(run.id),
            "kind": run.kind,
            "format": artifact.format,
            "sha256": artifact.sha256,
        },
    )
    await session.commit()
    filename = f"{run.kind}-{run.period_end.date().isoformat()}.{artifact.format}"
    return Response(
        content=content,
        media_type=_MEDIA_TYPES.get(artifact.format, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
