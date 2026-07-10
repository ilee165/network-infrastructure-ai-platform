"""Settings T1.3: soft-disable (retire) device credentials.

Adds nullable ``disabled_at`` on ``device_credentials`` so operators can retire
dead vault names without hard-deleting the row (audit trail + FK safety).

NULL = active (pre-T1.3 default). A non-NULL timestamp means the credential is
retired: list APIs exclude it by default, decrypt/rotate refuse it, and the
operator-facing name is freed by renaming at disable time (unique constraint).

Expand-only, portable DDL (PostgreSQL + SQLite unit tests). No crypto columns
touched. (D4: migrations never import models.)

Revision ID: 0019
Revises: 0018
Create Date: 2026-07-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Additive, nullable: existing rows stay active (NULL = not disabled).
    op.add_column(
        "device_credentials",
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("device_credentials", "disabled_at")
