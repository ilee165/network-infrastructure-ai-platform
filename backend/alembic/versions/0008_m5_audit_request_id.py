"""M5 task #3 (review fix): audit_log gains a nullable request_id correlation id.

ADR-0020 §4 enumerates ``request id`` as a required dimension of every
ChangeRequest transition audit entry (alongside actor, action, target,
before/after state, and the reasoning-trace link). Migration 0007 shipped the
CR spine but ``audit_log`` had no column to carry that correlation id, so the
mandated field could not be persisted even by a future API caller. This
migration closes the gap.

Like ``reasoning_trace_id`` (added in 0004), ``request_id`` is a **plain indexed
UUID with no FK**: ``audit_log`` is range-partitioned by ``created_at`` (the 0001
baseline), and there is no request table to point at — it is a free-standing
correlation handle captured at the route layer. ADD COLUMN on the partitioned
parent propagates to every partition; CREATE INDEX on the parent creates a
partitioned index. On SQLite (the unit-test backend) ``audit_log`` is
unpartitioned and the same DDL applies unchanged.

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable, plain indexed UUID linking an audited action to the inbound
    # request/correlation id that produced it (ADR-0020 §4). No FK — there is no
    # request table, and audit_log is partitioned (cf. reasoning_trace_id, 0004).
    op.add_column("audit_log", sa.Column("request_id", sa.Uuid(), nullable=True))
    op.create_index(op.f("ix_audit_log_request_id"), "audit_log", ["request_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_log_request_id"), table_name="audit_log")
    op.drop_column("audit_log", "request_id")
