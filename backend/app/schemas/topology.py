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


class TopologyDiffResponse(BaseModel):
    """The diff between two topology snapshots for ``GET /topology/diff``.

    Wraps the M2-08 :class:`TopologyDiff` (the four added/removed lists) with
    the two run ids the diff was computed from.
    """

    model_config = ConfigDict(extra="forbid")

    from_run: uuid.UUID = Field(description="The earlier run whose snapshot is the baseline.")
    to_run: uuid.UUID = Field(description="The later run whose snapshot is compared.")
    diff: TopologyDiff
