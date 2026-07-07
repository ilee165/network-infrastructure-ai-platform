"""Application-dependency derivation applier (ADR-0052 §3.3/§4, P4 W2-T2).

Persists a :class:`~app.engines.topology.app_derivation.DerivationPlan` —
the pure derivation's desired state — into the ``applications`` /
``application_dependencies`` system of record. All writes happen on the
caller's session inside ONE transaction (the applier flushes, the caller
commits), and every write path enforces the ADR-0052 conflict rules:

- **MERGE on ``origin_ref``** (§4): a planned application that resolved to an
  existing row updates it in place — row UUIDs, and therefore Neo4j node
  keys, are stable across re-runs. Creation stamps the §3.3.3 derived
  watermark so the new row starts derivation-managed.
- **Manual-wins dirty tracking** (§3.3.3): attributes are refreshed only via
  :func:`~app.models.applications.apply_derived_attributes` (which refuses
  operator-edited and ``manual``-origin rows) and only when the desired
  values actually differ — an unchanged row is not re-stamped, so idempotent
  re-derivation causes zero ``updated_at`` churn.
- **Lifecycle deletion keyed on ``origin``+``origin_ref``** (§3.3.5): a
  ``derived`` application whose ``f5:*`` source object stopped existing is
  deleted (with its dependency rows); ``manual`` applications are NEVER
  derivation-deleted — a collision-attached manual row only loses the
  derived edge rows themselves via the per-source diff.
- **Diff-replace per source** (§3.3.1/§4): a pass for source *S* diffs its
  desired ``source=S`` rows against the existing ones by the natural key
  ``(application_id, target_kind, target_ref, source)`` and inserts/updates/
  deletes only actual differences. ``manual`` rows are never queried, never
  written. A skipped dns pass (``plan.dns_pass_ran=False``) leaves every
  ``source='dns'`` row untouched — persisted source-3 results survive DDI
  outages, which is what keeps rebuild independent of DDI reachability
  (§2.3). ``derived_at`` marks the last *content* assertion: it refreshes on
  insert and on provenance change, not on a no-op re-run.

The applier never projects (writes flow one way, ADR-0005 §5); projection
reads these tables in the next pass.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.topology.app_derivation import DerivationPlan, PlannedDependency
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
    apply_derived_attributes,
    derived_attributes_clean,
    stamp_derived_watermark,
)
from app.models.mixins import utcnow

__all__ = ["DerivationApplyStats", "SourceApplyStats", "apply_derivation_plan"]

#: Only ``f5:``-prefixed origin_refs are lifecycle-owned by the automated
#: derivation — sources 2/3 create no applications (ADR-0052 §2).
_F5_REF_PREFIX = "f5:"


class SourceApplyStats(BaseModel):
    """Row-level outcome of one source's diff-replace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    inserted: int = 0
    updated: int = 0
    deleted: int = 0


class DerivationApplyStats(BaseModel):
    """What one applied derivation pass actually wrote (per source)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    applications_created: int = 0
    applications_updated: int = 0
    applications_deleted: int = 0
    f5: SourceApplyStats
    vmware: SourceApplyStats
    #: ``None`` when the dns pass was skipped (``dns_records`` unfetchable).
    dns: SourceApplyStats | None = None


async def _upsert_applications(
    session: AsyncSession, plan: DerivationPlan, instant: datetime
) -> tuple[dict[str, UUID], set[UUID], int, int]:
    """MERGE the planned applications; return (ref->id map, missing ids, created, updated)."""
    created = updated = 0
    id_by_origin_ref: dict[str, UUID] = {}
    missing_app_ids: set[UUID] = set()
    for pa in sorted(plan.applications, key=lambda p: p.origin_ref):
        if pa.application_id is not None:
            row = await session.get(Application, UUID(pa.application_id))
            if row is None:
                # The caller's snapshot raced a concurrent delete; the plan's
                # rows for this application are dropped rather than invented.
                missing_app_ids.add(UUID(pa.application_id))
                continue
            clean = derived_attributes_clean(row)
            wrote_ref = False
            if pa.record_origin_ref and row.origin_ref is None:
                row.origin_ref = pa.origin_ref  # §3.3.4 first-attach records the key
                wrote_ref = True
            applied = False
            if pa.refresh_attributes and clean:
                desired = (pa.name, pa.description, None, list(pa.fqdns))
                current = (row.name, row.description, row.owner, list(row.fqdns or []))
                if current != desired:
                    apply_derived_attributes(
                        row,
                        name=pa.name,
                        description=pa.description,
                        owner=None,
                        fqdns=pa.fqdns,
                        now=instant,
                    )
                    applied = True
            if wrote_ref and clean and not applied:
                # The origin_ref write is a derivation write: re-stamp so the
                # house ``onupdate`` cannot make the row read operator-edited.
                stamp_derived_watermark(row, now=instant)
            if wrote_ref or applied:
                updated += 1
            id_by_origin_ref[pa.origin_ref] = row.id
        else:
            row = Application(
                name=pa.name,
                description=pa.description,
                fqdns=list(pa.fqdns),
                origin=ApplicationOrigin.DERIVED,
                origin_ref=pa.origin_ref,
                owner=None,
                created_by=None,
            )
            stamp_derived_watermark(row, now=instant)
            session.add(row)
            await session.flush()
            created += 1
            id_by_origin_ref[pa.origin_ref] = row.id
    return id_by_origin_ref, missing_app_ids, created, updated


async def _delete_stale_derived_applications(
    session: AsyncSession, plan: DerivationPlan
) -> set[UUID]:
    """§3.3.5: derived apps whose ``f5:*`` source object vanished are deleted."""
    planned_refs = {pa.origin_ref for pa in plan.applications}
    result = await session.execute(
        select(Application).where(
            Application.origin == ApplicationOrigin.DERIVED,
            Application.origin_ref.is_not(None),
            Application.origin_ref.like(_F5_REF_PREFIX + "%"),
        )
    )
    stale = [row for row in result.scalars() if row.origin_ref not in planned_refs]
    if not stale:
        return set()
    deleted_ids = {row.id for row in stale}
    # Explicit dependency-row delete: the DB-level ON DELETE CASCADE also
    # covers this on PostgreSQL, but the applier must not depend on backend
    # pragma state (SQLite unit suite) for a correctness-bearing delete.
    await session.execute(
        delete(ApplicationDependency).where(ApplicationDependency.application_id.in_(deleted_ids))
    )
    for row in stale:
        await session.delete(row)
    await session.flush()
    return deleted_ids


async def _diff_source(
    session: AsyncSession,
    source: DependencySource,
    desired: dict[tuple[str, str, str], PlannedDependency],
    instant: datetime,
) -> SourceApplyStats:
    """Diff-replace exactly the ``source=S`` rows by natural key (§4)."""
    result = await session.execute(
        select(ApplicationDependency).where(ApplicationDependency.source == source)
    )
    existing = {
        (
            str(row.application_id),
            DependencyTargetKind(row.target_kind).value,
            row.target_ref,
        ): row
        for row in result.scalars()
    }
    inserted = updated = deleted = 0
    for key in sorted(set(existing) - set(desired)):
        await session.delete(existing[key])
        deleted += 1
    for key in sorted(desired):
        planned = desired[key]
        provenance = [step.model_dump() for step in planned.provenance]
        row = existing.get(key)
        if row is None:
            session.add(
                ApplicationDependency(
                    application_id=UUID(key[0]),
                    target_kind=DependencyTargetKind(key[1]),
                    target_ref=key[2],
                    source=source,
                    provenance=provenance,
                    derived_at=instant,
                    created_by=None,
                )
            )
            inserted += 1
        elif list(row.provenance or []) != provenance:
            row.provenance = provenance
            row.derived_at = instant
            updated += 1
        # else: unchanged — not rewritten, no ``updated_at``/audit churn (§4).
    await session.flush()
    return SourceApplyStats(inserted=inserted, updated=updated, deleted=deleted)


async def apply_derivation_plan(
    session: AsyncSession, plan: DerivationPlan, *, now: datetime | None = None
) -> DerivationApplyStats:
    """Persist *plan* on *session* (no commit here — one caller transaction).

    Raises :class:`ValueError` if the plan carries a ``manual`` row — the
    derivation must never write user-owned rows (ADR-0052 §3.3.1).
    """
    instant = now if now is not None else utcnow()

    id_by_origin_ref, missing_app_ids, created, updated = await _upsert_applications(
        session, plan, instant
    )
    deleted_ids = await _delete_stale_derived_applications(session, plan)
    dropped_ids = deleted_ids | missing_app_ids

    desired_by_source: dict[DependencySource, dict[tuple[str, str, str], PlannedDependency]] = {
        DependencySource.F5: {},
        DependencySource.VMWARE: {},
    }
    if plan.dns_pass_ran:
        desired_by_source[DependencySource.DNS] = {}
    for planned in plan.dependencies:
        source = DependencySource(planned.source)
        if source is DependencySource.MANUAL:
            raise ValueError("derivation plans must never carry manual rows")
        if source not in desired_by_source:
            continue  # dns rows of a skipped pass: defensive, cannot happen
        if planned.application_id is not None:
            app_id = UUID(planned.application_id)
        else:
            resolved = id_by_origin_ref.get(planned.app_origin_ref or "")
            if resolved is None:
                continue
            app_id = resolved
        if app_id in dropped_ids:
            continue
        desired_by_source[source][(str(app_id), planned.target_kind, planned.target_ref)] = planned

    per_source: dict[str, SourceApplyStats] = {}
    for source in sorted(desired_by_source, key=lambda s: s.value):
        per_source[source.value] = await _diff_source(
            session, source, desired_by_source[source], instant
        )

    return DerivationApplyStats(
        applications_created=created,
        applications_updated=updated,
        applications_deleted=len(deleted_ids),
        f5=per_source[DependencySource.F5.value],
        vmware=per_source[DependencySource.VMWARE.value],
        dns=per_source.get(DependencySource.DNS.value),
    )
