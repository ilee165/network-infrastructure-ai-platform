"""P3-W2 (ADR-0043 §6 / ADR-0008 §5): config_backup_runs idempotency guard table.

``config.nightly_backup`` is beat-scheduled and runs with ``task_acks_late`` /
``task_reject_on_worker_lost`` (globally enabled, ``celery_app.py``). A worker
killed between task receipt and ack causes the task to be **redelivered** — at
which point the old code generated a fresh ``uuid.uuid4()`` and unconditionally
emitted a second ``config.backup_run_started`` + ``config.backup_run_finished``
audit pair and dispatched a second full device fan-out wave (the "double audit
row" hazard the ADR names explicitly). This migration creates a lightweight
``config_backup_runs`` table whose ``run_uuid`` primary key is used as an
idempotency token: the task INSERTs ``ON CONFLICT DO NOTHING`` and skips the
fan-out + audit emit when the row already existed (the ``run_uuid`` was supplied
by the caller or derived deterministically from the UTC date slot, so a
redelivered task carries the same ``run_uuid``).

Schema:
  * ``run_uuid``      — UUID primary key (the idempotency token).
  * ``scheduled_slot`` — ISO date string of the UTC scheduled date (used to
    derive the deterministic slot UUID and indexed for range queries / reporting).
  * ``status``        — mutable lifecycle VARCHAR (``"running"`` → terminal);
    NOT append-only (this is a run-tracking table, not part of the audit chain).
  * ``started_at``    — timestamptz set at run start.
  * ``finished_at``   — nullable timestamptz set at run completion.

Portable DDL: no PostgreSQL-specific types. (D4: migrations never import models.)

Revision ID: 0013
Revises: 0012
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "config_backup_runs",
        sa.Column("run_uuid", sa.UUID(), nullable=False),
        sa.Column("scheduled_slot", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("run_uuid", name="pk_config_backup_runs"),
    )
    op.create_index(
        "ix_config_backup_runs_scheduled_slot",
        "config_backup_runs",
        ["scheduled_slot"],
    )


def downgrade() -> None:
    op.drop_index("ix_config_backup_runs_scheduled_slot", table_name="config_backup_runs")
    op.drop_table("config_backup_runs")
