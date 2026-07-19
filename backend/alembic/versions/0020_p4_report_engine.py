"""P4-W3-T1 (ADR-0053 §1/§7.2): report engine + compliance trend history.

One **expand-only** revision adding the four ADR-0053 tables:

* ``report_runs`` / ``report_artifacts`` (§1) — the dedicated report model.
  Deliberately NOT the RAG-embedded ``documents`` table: reports are RBAC-scoped
  evidence and are never embedded (structural exclusion). Artifacts are PG
  ``bytea`` with ``sha256`` + ``expires_at`` (7-year PROPOSED retention, purged
  by ``reports.purge_expired``). ``report_runs`` carries a unique
  ``(kind, period_start, period_end)`` so the deterministic claim-row guard is
  DB-enforced (beat + on-demand cannot double-generate, §2).
* ``compliance_runs`` / ``compliance_run_findings`` (§7.2) — the trend history
  the compliance-posture report requires; **secret-free by construction**:
  status/severity only, deliberately NO evidence-excerpt column (§6 layer 3).

Portable DDL (PostgreSQL + SQLite unit tests): ``LargeBinary`` -> ``bytea`` /
``BLOB``; ``sa.JSON`` -> JSONB is applied by the model variant only, plain JSON
here is fine for both backends. (D4: migrations never import models.)

Revision ID: 0020
Revises: 0019
Create Date: 2026-07-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_class", sa.String(length=64), nullable=True),
        sa.Column("regime_tags", sa.JSON(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_report_runs"),
        sa.UniqueConstraint(
            "kind", "period_start", "period_end", name="uq_report_runs_kind_period"
        ),
    )
    op.create_index(
        "ix_report_runs_kind_created", "report_runs", ["kind", "created_at"], unique=False
    )

    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_report_artifacts"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["report_runs.id"],
            name="fk_report_artifacts_run_id",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_report_artifacts_run_id", "report_artifacts", ["run_id"], unique=False)
    op.create_index(
        "ix_report_artifacts_expires_at", "report_artifacts", ["expires_at"], unique=False
    )

    op.create_table(
        "compliance_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("policy_id", sa.String(length=128), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("device_scope", sa.JSON(), nullable=False),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_compliance_runs"),
    )
    op.create_index(
        "ix_compliance_runs_executed_at", "compliance_runs", ["executed_at"], unique=False
    )

    # Secret-free by construction (ADR-0053 §6 layer 3): status/severity only —
    # deliberately NO evidence-excerpt column (excerpts can quote config text).
    op.create_table(
        "compliance_run_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.String(length=128), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_compliance_run_findings"),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["compliance_runs.id"],
            name="fk_compliance_run_findings_run_id",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_compliance_run_findings_run_id", "compliance_run_findings", ["run_id"], unique=False
    )
    op.create_index(
        "ix_compliance_run_findings_device_id",
        "compliance_run_findings",
        ["device_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_compliance_run_findings_device_id", table_name="compliance_run_findings")
    op.drop_index("ix_compliance_run_findings_run_id", table_name="compliance_run_findings")
    op.drop_table("compliance_run_findings")
    op.drop_index("ix_compliance_runs_executed_at", table_name="compliance_runs")
    op.drop_table("compliance_runs")
    op.drop_index("ix_report_artifacts_expires_at", table_name="report_artifacts")
    op.drop_index("ix_report_artifacts_run_id", table_name="report_artifacts")
    op.drop_table("report_artifacts")
    op.drop_index("ix_report_runs_kind_created", table_name="report_runs")
    op.drop_table("report_runs")
