"""P5 W1-T1: expand-only durable report dispatch outbox.

Revision ID: 0023
Revises: 0022
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dispatch_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("aggregate_type", sa.String(32), nullable=False),
        sa.Column("aggregate_id", sa.Uuid(), nullable=False),
        sa.Column("task_name", sa.String(128), nullable=False),
        sa.Column("queue", sa.String(32), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_owner", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.Column("consumer_state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("consumer_owner", sa.String(128), nullable=True),
        sa.Column("consumer_claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumer_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumer_error_code", sa.String(64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_dispatch_outbox"),
        sa.UniqueConstraint(
            "aggregate_type",
            "aggregate_id",
            "task_name",
            name="uq_dispatch_outbox_aggregate_task",
        ),
    )
    op.create_index(
        "ix_dispatch_outbox_relay",
        "dispatch_outbox",
        ["state", "available_at", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_dispatch_outbox_relay", table_name="dispatch_outbox")
    op.drop_table("dispatch_outbox")
