"""M2-07: topology_snapshots table — diff foundation.

Stores the canonical sorted multiset summary (nodes + edges) of one topology
projection pass, keyed by discovery run.  The diff engine (M2-08) compares
successive snapshots entirely within Postgres.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-12
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Portable JSON column: plain JSON everywhere, JSONB on PostgreSQL.
#: Mirrors app.models.mixins.JSON_VARIANT (migrations never import models — D4).
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "topology_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False, default=uuid.uuid4),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("nodes", _JSON, nullable=False, server_default="[]"),
        sa.Column("edges", _JSON, nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["run_id"], ["discovery_runs.id"]),
        sa.UniqueConstraint("run_id", name="uq_topology_snapshots_run_id"),
    )
    op.create_index("ix_topology_snapshots_run_id", "topology_snapshots", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_topology_snapshots_run_id", table_name="topology_snapshots")
    op.drop_table("topology_snapshots")
