"""M2-03: add nullable site column to devices.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("site", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "site")
