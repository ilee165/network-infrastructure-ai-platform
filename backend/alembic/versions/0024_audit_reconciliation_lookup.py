"""Expand audit lookup support for set-wise CR reconciliation.

Revision ID: 0024
Revises: 0023
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_audit_log_cr_reconciliation_lookup",
        "audit_log",
        ["target_type", "target_id", "action", "reasoning_trace_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_log_cr_reconciliation_lookup", table_name="audit_log")
