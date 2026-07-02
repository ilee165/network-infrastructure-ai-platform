"""Audit Wave 2 (PRODUCTION_READINESS #5): refresh-token reuse detection.

Adds ``refresh_sessions.current_jti_hash`` — the SHA-256 hex of the ``jti`` of
the most recently issued refresh token for the session. ``POST /auth/refresh``
compares the presented token's ``jti`` hash against this column: a mismatch
means a rotated-out (superseded) refresh token was replayed — a theft signal —
so the session is revoked and ``auth.refresh_reuse_detected`` is audited.

Additive + nullable, deliberately: sessions created before this migration have
``NULL`` (no reuse baseline yet) and keep working — the column is backfilled on
their next legitimate rotation. A code revert therefore leaves a harmless
unused column; no emergency down-migration is required (Wave 2 rollback plan).

Only the hash is stored — never the token or the raw ``jti`` — so the column
carries no credential material (D4: migrations never import models; portable
DDL, no PostgreSQL-specific types).

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "refresh_sessions",
        sa.Column("current_jti_hash", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("refresh_sessions", "current_jti_hash")
