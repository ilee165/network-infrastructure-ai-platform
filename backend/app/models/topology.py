"""Topology snapshot model (M2-07, ADR-0005).

:class:`TopologySnapshot` stores the canonical multiset summary of a single
topology projection pass — the *diff foundation*.  One snapshot per discovery
run (``run_id`` is a unique FK to ``discovery_runs``).

Canonical form (shared with the diff engine, M2-08):

- ``nodes`` — sorted list of ``[label, key]`` pairs, deduped.
- ``edges`` — sorted list of ``[rel_type, src_key, dst_key]`` triples, deduped.

Both columns are JSONB on PostgreSQL and plain JSON on SQLite (portable via
``JSON_VARIANT``, same pattern used throughout the inventory models).

See :func:`app.engines.topology.snapshots.build_snapshot` for the pure builder
and :func:`app.engines.topology.snapshots.upsert_snapshot` for persistence.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UuidPkMixin

__all__ = ["TopologySnapshot"]


class TopologySnapshot(UuidPkMixin, TimestampMixin, Base):
    """One canonical snapshot of the topology graph for a discovery run.

    ``nodes`` and ``edges`` hold the sorted, deduped multiset summary:

    - ``nodes``: ``[[label, key], ...]``
    - ``edges``: ``[[rel_type, src_key, dst_key], ...]``

    The unique constraint on ``run_id`` enforces one-snapshot-per-run.
    """

    __tablename__ = "topology_snapshots"

    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("discovery_runs.id"),
        unique=True,
        nullable=False,
        index=True,
    )
    nodes: Mapped[list[Any]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    edges: Mapped[list[Any]] = mapped_column(JSON_VARIANT, nullable=False, default=list)

    def __repr__(self) -> str:
        return (
            f"<TopologySnapshot id={self.id} run_id={self.run_id} "
            f"nodes={len(self.nodes or [])} edges={len(self.edges or [])}>"
        )
