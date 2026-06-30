"""P3-W3 (ADR-0045 §2): audit→SIEM export durable cursor table.

The audit→SIEM export pipeline (``app.services.audit.export``) streams every
committed ``audit_log`` row to the customer SIEM at-least-once, in ``seq`` order,
driven by a DURABLE cursor over the ADR-0038 ``seq`` append-order key. This
migration creates the single-row ``audit_export_cursor`` watermark table that
makes the export gap-free across restarts (ADR-0045 §2):

  * ``id``                     — UUID primary key; the fixed singleton id (one
    watermark per deployment), mirroring ``audit_chain_checkpoint``.
  * ``exported_seq``           — highest ``audit_log.seq`` CONFIRMED delivered to
    the SIEM. Advanced ONLY on sink ACK (never over an unacknowledged row), so a
    crash re-exports the un-advanced rows on restart (at-least-once, never
    at-most-once). ``0`` = nothing exported yet (``seq > 0`` selects the whole
    chain; the writer assigns ``seq`` from 1).
  * ``last_exported_commit_at`` — nullable timestamptz: the commit/``created_at``
    of the row at ``exported_seq``, the basis of the ``export_lag_seconds`` SLI
    (ADR-0045 §3). NULL until the first export.
  * ``updated_at``             — timestamptz of the last cursor advance.

This is strictly DOWNSTREAM of the audit DB commit (ADR-0045 §3): the cursor is a
separate row advanced in the exporter process, never coupled into the audit write
path — a SIEM outage grows the durable backlog + the lag gauge, never blocks the
write and never drops a row.

Portable DDL: no PostgreSQL-specific types (D4: migrations never import models).
This table is NOT append-only / NOT part of the audit hash chain — it is a mutable
run-tracking watermark, so the 0001 ``REVOKE`` / 0011 chain controls do not apply.

Revision ID: 0014
Revises: 0013
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_export_cursor",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("exported_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_exported_commit_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_export_cursor"),
    )


def downgrade() -> None:
    op.drop_table("audit_export_cursor")
