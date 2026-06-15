"""Config-snapshot sub-resources under ``/devices/{device_id}/`` (M4; T14).

Routes (all read-only in M4 — write paths hard-rejected until M5):

    GET  /devices/{device_id}/config-snapshots            viewer+   list (no content)
    GET  /devices/{device_id}/config-snapshots/{snap_id}  viewer+   metadata (no content)
    GET  /devices/{device_id}/config-snapshots/{snap_id}/content  engineer+  raw content
    GET  /devices/{device_id}/drift                       engineer+  diff vs baseline
    GET  /devices/{device_id}/compliance                  engineer+  policy evaluation

RBAC (ADR-0010, ADR-0017):
* List / metadata: viewer+ (authenticated and active, any rank).
* Raw config content: engineer+ (content may contain credentials/keys).
* Drift / compliance: engineer+ (diff and evidence may expose config excerpts).

The router is NOT a standalone router — it is included into the devices router
(``APIRouter(prefix="/devices")``) via ``app.api.v1.__init__``, so all routes
here carry the ``/devices`` prefix without repeating it.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import NotFoundError
from app.engines.config_mgmt.compliance.engine import (
    DeviceContext,
    FindingStatus,
    evaluate_policy,
)
from app.engines.config_mgmt.compliance.loader import load_default_pack
from app.engines.config_mgmt.compliance.schema import Policy, Severity
from app.engines.config_mgmt.drift import DriftResult, NoBaselineError, detect_drift
from app.models import CompliancePolicy, ConfigSnapshot, Device, User
from app.schemas.config_mgmt import (
    ComplianceRunResponse,
    ConfigSnapshotContent,
    ConfigSnapshotListResponse,
    ConfigSnapshotRead,
    DriftResponse,
    FindingRead,
)
from app.services import audit

router = APIRouter(tags=["config-snapshots"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]
Engineer = Annotated[User, Depends(require_role("engineer"))]

_TARGET_TYPE = "config_snapshot"


async def _get_device_or_404(session: AsyncSession, device_id: uuid.UUID) -> Device:
    device = await session.get(Device, device_id)
    if device is None:
        raise NotFoundError(f"device {device_id} does not exist")
    return device


async def _get_snapshot_or_404(
    session: AsyncSession, device_id: uuid.UUID, snapshot_id: uuid.UUID
) -> ConfigSnapshot:
    snap = await session.get(ConfigSnapshot, snapshot_id)
    if snap is None or snap.device_id != device_id:
        raise NotFoundError(f"config snapshot {snapshot_id} does not exist for device {device_id}")
    return snap


# ---------------------------------------------------------------------------
# List / detail — viewer+
# ---------------------------------------------------------------------------


@router.get("/{device_id}/config-snapshots", response_model=ConfigSnapshotListResponse)
async def list_config_snapshots(
    device_id: uuid.UUID,
    session: DbSession,
    _user: Viewer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConfigSnapshotListResponse:
    """List config snapshots for a device (metadata only, no content).

    Content is intentionally omitted from list responses (ADR-0017) to prevent
    secret material appearing in bulk API responses.  Use the
    ``/content`` sub-resource to fetch the raw text for a specific snapshot.
    """
    await _get_device_or_404(session, device_id)
    base = select(ConfigSnapshot).where(ConfigSnapshot.device_id == device_id)
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                base.order_by(
                    ConfigSnapshot.captured_at.desc(),
                    ConfigSnapshot.created_at.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ConfigSnapshotListResponse(
        items=[ConfigSnapshotRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{device_id}/config-snapshots/{snapshot_id}",
    response_model=ConfigSnapshotRead,
)
async def get_config_snapshot(
    device_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    session: DbSession,
    _user: Viewer,
) -> ConfigSnapshotRead:
    """One config snapshot metadata record (no content — see ``/content``)."""
    snap = await _get_snapshot_or_404(session, device_id, snapshot_id)
    return ConfigSnapshotRead.model_validate(snap)


# ---------------------------------------------------------------------------
# Raw content — engineer+ (ADR-0017 §2: RBAC + audit on every access)
# ---------------------------------------------------------------------------


@router.get(
    "/{device_id}/config-snapshots/{snapshot_id}/content",
    response_model=ConfigSnapshotContent,
)
async def get_config_snapshot_content(
    device_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    session: DbSession,
    user: Engineer,
) -> ConfigSnapshotContent:
    """Return the raw (unredacted) snapshot text — engineer+ only.

    Every access to unredacted snapshot content is treated as a
    read/decrypt-equivalent operation and is appended to the audit trail
    (ADR-0017 §2).  The ``detail`` references the snapshot by id and hash
    only — the content itself never enters the audit record.
    """
    snap = await _get_snapshot_or_404(session, device_id, snapshot_id)
    await audit.record(
        session,
        actor=f"user:{user.username}",
        action=audit.CONFIG_SNAPSHOT_CONTENT_READ,
        target_type=_TARGET_TYPE,
        target_id=str(snap.id),
        detail={
            "device_id": str(device_id),
            "content_hash": snap.content_hash,
        },
    )
    await session.commit()
    return ConfigSnapshotContent.model_validate(snap)


# ---------------------------------------------------------------------------
# Drift — engineer+ (diff may expose config excerpts)
# ---------------------------------------------------------------------------


@router.get("/{device_id}/drift", response_model=DriftResponse)
async def get_drift(
    device_id: uuid.UUID,
    session: DbSession,
    user: Engineer,
) -> DriftResponse:
    """Diff the latest snapshot against the device's approved baseline.

    Returns a unified diff and per-hunk list.  Raises 404 when the device has
    no approved baseline (the engineer must approve one first).
    """
    await _get_device_or_404(session, device_id)
    try:
        result: DriftResult = await detect_drift(
            session,
            device_id=device_id,
            actor=f"user:{user.username}",
        )
    except NoBaselineError as exc:
        raise NotFoundError(
            f"device {device_id} has no approved baseline; approve one before checking drift"
        ) from exc
    return DriftResponse(
        device_id=result.device_id,
        has_drift=result.has_drift,
        diff=result.diff,
        hunks=result.hunks,
        baseline_hash=result.baseline_hash,
        current_hash=result.current_hash,
    )


# ---------------------------------------------------------------------------
# Compliance — engineer+ (findings may contain config excerpts)
# ---------------------------------------------------------------------------


@router.get("/{device_id}/compliance", response_model=ComplianceRunResponse)
async def get_compliance(
    device_id: uuid.UUID,
    session: DbSession,
    _user: Engineer,
    policy_id: Annotated[str | None, Query(max_length=128)] = None,
) -> ComplianceRunResponse:
    """Evaluate the latest config snapshot against compliance policies.

    When ``policy_id`` is supplied the named policy (latest version) is used;
    otherwise the default seeded ``baseline-hardening`` pack applies.

    Returns findings with status ``pass`` | ``violation`` | ``skipped`` per
    rule (ADR-0018 §5).  A 404 is returned when the device has no captured
    snapshot to evaluate against.
    """
    device = await _get_device_or_404(session, device_id)

    # Fetch the latest snapshot for evaluation (must exist)
    latest = (
        await session.execute(
            select(ConfigSnapshot)
            .where(ConfigSnapshot.device_id == device_id)
            .order_by(ConfigSnapshot.captured_at.desc(), ConfigSnapshot.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if latest is None:
        raise NotFoundError(f"device {device_id} has no config snapshots to evaluate")

    # Resolve the policy to evaluate
    if policy_id is not None:
        policy_row = (
            await session.execute(
                select(CompliancePolicy)
                .where(CompliancePolicy.policy_id == policy_id)
                .order_by(CompliancePolicy.version.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if policy_row is None:
            raise NotFoundError(f"compliance policy {policy_id!r} not found")
        policy = Policy.model_validate(
            {
                "id": policy_row.policy_id,
                "version": policy_row.version,
                "scope": policy_row.scope,
                "rules": policy_row.rules,
            }
        )
    else:
        policy = load_default_pack()

    ctx = DeviceContext(
        device_id=device_id,
        vendor=device.vendor_id,
        role=None,
        site=device.site,
        raw_config=latest.content,
    )
    raw_findings = evaluate_policy(policy, ctx)

    findings = [
        FindingRead(
            device_id=f.device_id,
            policy_id=f.policy_id,
            policy_version=f.policy_version,
            rule_id=f.rule_id,
            severity=f.severity,
            status=f.status,
            evidence=f.evidence,
        )
        for f in raw_findings
    ]

    return ComplianceRunResponse(
        device_id=device_id,
        policy_id=policy.id,
        policy_version=policy.version,
        findings=findings,
        violation_count=sum(1 for f in raw_findings if f.status is FindingStatus.VIOLATION),
        warn_count=sum(
            1
            for f in raw_findings
            if f.status is FindingStatus.VIOLATION and f.severity == Severity.WARN
        ),
        pass_count=sum(1 for f in raw_findings if f.status is FindingStatus.PASS),
        skipped_count=sum(1 for f in raw_findings if f.status is FindingStatus.SKIPPED),
    )
