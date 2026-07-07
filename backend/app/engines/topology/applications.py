"""Application-layer graph derivation (ADR-0052 §3.2/§5, P4 W2-T1).

Turns the persisted ``applications`` / ``application_dependencies`` rows into
the typed, frozen records the projector writes: one ``Application`` node per
row (keyed ``pg_id``, exactly like ``Device``/``Interface``/``IPAddress``) and
one **union** ``DEPENDS_ON`` edge per (application, target) pair — Postgres
keeps per-source rows, Neo4j projects one edge carrying ``sources`` (sorted),
``derived_at`` (newest across sources) and a compact provenance summary
(``source:kind:ref`` strings in deterministic order); full per-source JSON
provenance stays authoritative in PG (§3.2).

:func:`derive_applications` is pure and deterministic (identical rows always
produce identical output, independent of input ordering) and — mirroring the
"unreconcilable members emit no edge" rule — drops any dependency row whose
target key is not among the projected ``Device``/``IPAddress`` keys of the
same pass: an endpoint the projector will not ``MATCH`` must not be derived
either, so the snapshot/count contract (`snapshot_lists` vs the live graph,
the rebuild-drill completeness assertion) stays exact.

This layer is a REQUIRED component of every derivation pass
(:func:`app.engines.topology.sync.derive_topology`); it is never an optional
kwarg — the ``dns=`` deletion hazard must not recur (ADR-0052 §5).
"""

from __future__ import annotations

from collections.abc import Sequence
from collections.abc import Set as AbstractSet
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.engines.topology.nodes import GraphNode
from app.knowledge.schema import (
    LABEL_APPLICATION,
    LABEL_DEVICE,
    LABEL_IPADDRESS,
    REL_DEPENDS_ON,
)
from app.models.applications import Application, ApplicationDependency, DependencyTargetKind

__all__ = [
    "ApplicationNode",
    "DependsOnEdge",
    "DerivedApplications",
    "derive_applications",
]


class ApplicationNode(GraphNode):
    """An application (1:1 with an ``applications`` row; ADR-0052 §5).

    Node properties are primitives/arrays only (Neo4j property constraints):
    ``pg_id``, ``name``, ``description``, ``origin``, ``owner``, ``fqdns`` —
    plus the ``last_projected_at`` stamp added at projection time.
    """

    label: ClassVar[str] = LABEL_APPLICATION
    key_property: ClassVar[str] = "pg_id"

    pg_id: UUID
    name: str
    description: str | None
    origin: str
    owner: str | None
    fqdns: tuple[str, ...] = ()


class DependsOnEdge(BaseModel):
    """One projected union ``DEPENDS_ON`` edge per (application, target) (§3.2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rel_type: ClassVar[str] = REL_DEPENDS_ON

    application_pg_id: str
    #: The projected target label (``Device`` or ``IPAddress`` only, §2.3).
    target_label: str
    #: The target node's key property value (its PG row UUID as string).
    target_key: str
    #: Sorted names of every source asserting this pair.
    sources: tuple[str, ...]
    #: Newest ``derived_at`` across the asserting per-source rows.
    derived_at: datetime
    #: Compact provenance summary: ``source:kind:ref`` strings, deterministic
    #: order (rows sorted by source, steps in stored order). Full JSON
    #: provenance stays in PG (§3.2).
    provenance: tuple[str, ...] = ()


class DerivedApplications(BaseModel):
    """The complete application-layer sets of one derivation pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    applications: tuple[ApplicationNode, ...] = ()
    depends_on: tuple[DependsOnEdge, ...] = ()


#: target_kind (lower-snake, ADR-0052 §1) -> projected Neo4j label (§2.3).
TARGET_LABEL_BY_KIND: dict[str, str] = {
    DependencyTargetKind.DEVICE.value: LABEL_DEVICE,
    DependencyTargetKind.IP_ADDRESS.value: LABEL_IPADDRESS,
}


def _compact_provenance(rows: Sequence[ApplicationDependency]) -> tuple[str, ...]:
    """Flatten per-source evidence chains to ``source:kind:ref`` strings (§3.2).

    Rows arrive sorted by source; steps keep their stored (evidence-chain)
    order, so the summary is deterministic for a given row set. Malformed
    steps (non-dict entries) are skipped defensively — provenance is advisory
    display data here; PG remains authoritative.
    """
    summary: list[str] = []
    for row in rows:
        source = str(row.source)
        # JSON columns carry whatever was stored — widen to ``object`` so the
        # malformed-step guard is a real runtime check, not dead typing.
        steps: Sequence[object] = row.provenance or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            summary.append(f"{source}:{step.get('kind')}:{step.get('ref')}")
    return tuple(summary)


def derive_applications(
    applications: Sequence[Application],
    dependencies: Sequence[ApplicationDependency],
    *,
    device_keys: AbstractSet[str],
    ip_address_keys: AbstractSet[str],
) -> DerivedApplications:
    """Derive the application node + union edge sets from PG rows (pure).

    Inputs are plain in-memory ORM rows — no session, no I/O. Output ordering
    and dedup are independent of input order: nodes sort by (case-folded name,
    ``pg_id``); union edges sort by (application key, target label, target
    key).

    *device_keys* / *ip_address_keys* are the key-property values of the
    ``Device`` / ``IPAddress`` nodes derived in the SAME pass: a dependency row
    whose target is not among them emits **no** edge (the projector's
    ``MATCH``-only endpoints could never create it — no phantom endpoints,
    ADR-0052 §5) and a row referencing an application absent from
    *applications* is likewise dropped.
    """
    nodes = tuple(
        sorted(
            (
                ApplicationNode(
                    pg_id=app.id,
                    name=app.name,
                    description=app.description,
                    origin=str(app.origin),
                    owner=app.owner,
                    fqdns=tuple(app.fqdns or []),
                )
                for app in applications
            ),
            key=lambda node: (node.name.casefold(), str(node.pg_id)),
        )
    )
    seen_app_keys: set[str] = set()
    deduped_nodes: list[ApplicationNode] = []
    for node in nodes:
        key = str(node.pg_id)
        if key in seen_app_keys:
            continue
        seen_app_keys.add(key)
        deduped_nodes.append(node)

    valid_target_keys: dict[str, AbstractSet[str]] = {
        DependencyTargetKind.DEVICE.value: device_keys,
        DependencyTargetKind.IP_ADDRESS.value: ip_address_keys,
    }

    # Union per (application, target_kind, target_ref): per-source PG rows
    # collapse to ONE projected edge per pair (§3.2).
    groups: dict[tuple[str, str, str], list[ApplicationDependency]] = {}
    for row in dependencies:
        app_key = str(row.application_id)
        kind = str(row.target_kind)
        if app_key not in seen_app_keys:
            continue
        if kind not in valid_target_keys:
            continue
        if row.target_ref not in valid_target_keys[kind]:
            continue
        groups.setdefault((app_key, kind, row.target_ref), []).append(row)

    edges: list[DependsOnEdge] = []
    for (app_key, kind, target_ref), rows in groups.items():
        rows_sorted = sorted(rows, key=lambda row: str(row.source))
        edges.append(
            DependsOnEdge(
                application_pg_id=app_key,
                target_label=TARGET_LABEL_BY_KIND[kind],
                target_key=target_ref,
                sources=tuple(sorted({str(row.source) for row in rows_sorted})),
                derived_at=max(row.derived_at for row in rows_sorted),
                provenance=_compact_provenance(rows_sorted),
            )
        )
    edges.sort(key=lambda edge: (edge.application_pg_id, edge.target_label, edge.target_key))

    return DerivedApplications(applications=tuple(deduped_nodes), depends_on=tuple(edges))
