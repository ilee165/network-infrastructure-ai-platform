"""Topology API contracts (M2-10): response models for ``/api/v1/topology``.

Pure data (D2): validation/serialization only, no I/O.  The graph endpoint
returns the projected Neo4j subgraph (:class:`GraphResponse`) and the diff
endpoint returns the M2-08 :class:`~app.engines.topology.diff.TopologyDiff`
wire shape wrapped with the two run ids it was computed from
(:class:`TopologyDiffResponse`).

Every graph response surfaces ``projected_at`` (ADR-0005: answers are "as of
run X") — the most recent ``last_projected_at`` stamp across the returned
nodes, or ``None`` when the subgraph is empty.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.engines.topology.diff import TopologyDiff

__all__ = [
    "GraphEdge",
    "GraphNode",
    "GraphResponse",
    "ImpactDependency",
    "ImpactDependent",
    "ImpactResponse",
    "ImpactTarget",
    "TopologyDiffResponse",
]


class GraphNode(BaseModel):
    """One projected node: its label, key value, and flat property map."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(description="Projected node label (e.g. Device, Subnet).")
    key: Any = Field(description="Value of the label's key property (pg_id / natural key).")
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Flat, JSON-safe property map for display."
    )


class GraphEdge(BaseModel):
    """One projected relationship between two node keys."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(description="Relationship type (e.g. CONNECTED_TO, ROUTES_TO).")
    source: Any = Field(description="Key of the start node.")
    target: Any = Field(description="Key of the end node.")
    properties: dict[str, Any] = Field(
        default_factory=dict, description="Flat, JSON-safe relationship property map."
    )


class GraphResponse(BaseModel):
    """The projected topology subgraph for ``GET /topology/graph``.

    ``projected_at`` is the most recent ``last_projected_at`` (ISO-8601 UTC)
    across the returned nodes — the projection pass these answers are "as of".
    It is ``None`` only when the filtered subgraph contains no nodes.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    projected_at: str | None = Field(
        default=None,
        description="Most recent projection timestamp across the returned nodes.",
    )


class ImpactTarget(BaseModel):
    """A node addressed by label + key (the impact endpoint's minimal endpoint form)."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(description="Projected node label (e.g. Device, IPAddress, Application).")
    key: Any = Field(description="Value of the label's key property (pg_id / natural key).")


class ImpactDependent(BaseModel):
    """One application impacted by the target, with the edge's provenance (§8).

    ``application`` is the dependent application node; ``target`` is the endpoint
    it depends on (the target itself for a direct dependent, or a neighborhood
    node for an indirect one). ``sources``/``provenance``/``derived_at`` are the
    compact, refs-only explainability summary carried on the ``DEPENDS_ON`` edge.
    """

    model_config = ConfigDict(extra="forbid")

    application: GraphNode
    target: ImpactTarget
    sources: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    derived_at: str | None = None


class ImpactDependency(BaseModel):
    """One endpoint an Application target depends on, with the edge's provenance."""

    model_config = ConfigDict(extra="forbid")

    target: GraphNode
    sources: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    derived_at: str | None = None


class ImpactResponse(BaseModel):
    """The bounded impact answer for ``GET /topology/impact`` (ADR-0052 §8).

    ``dependents`` answers "what depends on X" (every target kind); for an
    ``Application`` target ``dependencies`` also answers "what does A depend on".
    ``projected_at`` is the watermark these answers are "as of" (``None`` when
    the target is absent from the projection); ``depth_used`` is the hop bound
    the physical-neighborhood expansion ran with.
    """

    model_config = ConfigDict(extra="forbid")

    target: ImpactTarget
    dependents: list[ImpactDependent] = Field(default_factory=list)
    dependencies: list[ImpactDependency] = Field(default_factory=list)
    projected_at: str | None = None
    depth_used: int


class TopologyDiffResponse(BaseModel):
    """The diff between two topology snapshots for ``GET /topology/diff``.

    Wraps the M2-08 :class:`TopologyDiff` (the four added/removed lists) with
    the two run ids the diff was computed from.
    """

    model_config = ConfigDict(extra="forbid")

    from_run: uuid.UUID = Field(description="The earlier run whose snapshot is the baseline.")
    to_run: uuid.UUID = Field(description="The later run whose snapshot is compared.")
    diff: TopologyDiff
