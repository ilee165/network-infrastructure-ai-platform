"""P4-W3-T5 (ADR-0053 §7.4, ADR-0038): audit chain verification history.

One **expand-only** revision adding ``audit_chain_verification_runs`` — the
persisted per-run outcome of the daily ADR-0038 chain-verification CronJob
(started/finished, verified range from/to entry id, ``outcome`` clean|break,
checkpoint watermark hash before/after, and the daily append-only
grant-attestation outcome). Today the CronJob emits only a metric + exit code;
metrics retention cannot back a 7-year evidence trail — this table can. The
audit-integrity report reads this history and surfaces a MISSING day as a
finding (a verification that never ran is a finding, not a blank).

Checkpoint hashes are stored as hex SHA-256 digest presentations — tamper
evidence, not secret material (the ADR-0053 §6 redaction contract deliberately
permits digests).

Portable DDL (PostgreSQL + SQLite unit tests). (D4: migrations never import
models.)

Revision ID: 0021
Revises: 0020
Create Date: 2026-07-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_verification_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("entries_checked", sa.BigInteger(), nullable=False),
        sa.Column("range_from_entry_id", sa.Uuid(), nullable=True),
        sa.Column("range_to_entry_id", sa.Uuid(), nullable=True),
        sa.Column("checkpoint_before_hash", sa.String(length=64), nullable=True),
        sa.Column("checkpoint_after_hash", sa.String(length=64), nullable=True),
        sa.Column("grant_check_outcome", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_chain_verification_runs"),
    )
    # The audit-integrity report selects the CLOSED-OPEN period over started_at.
    op.create_index(
        "ix_audit_chain_verification_runs_started_at",
        "audit_chain_verification_runs",
        ["started_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_chain_verification_runs_started_at",
        table_name="audit_chain_verification_runs",
    )
    op.drop_table("audit_chain_verification_runs")
