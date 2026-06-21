"""ADR-0028 OIDC/SSO: federated-identity columns + 1:1 anchor index on users.

``users`` gains two **nullable** columns — ``idp_iss`` and ``idp_subject`` — the
immutable ``(iss, sub)`` pair that anchors a federated account (ADR-0028 §2).
Local accounts leave both NULL. A **partial UNIQUE index** over the pair (where
``idp_subject IS NOT NULL``) is the DB-level backstop that keeps one federated
identity ⇒ exactly one ``users`` row, which is what lets the ADR-0020 four-eyes
``user.id`` comparison stay a faithful 1:1 proxy for the IdP subject (§6). The
partial predicate exempts local users (NULLs) so multiple local rows still
coexist, on both PostgreSQL and SQLite (the unit-test backend honours the same
WHERE-qualified unique index).

This is an expand-only migration (ADR-0002 / PRODUCTION.md §10 expand/contract):
nullable ADD COLUMN backfills existing rows with NULL, no data rewrite.

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("idp_iss", sa.String(length=512), nullable=True))
    op.add_column("users", sa.Column("idp_subject", sa.String(length=255), nullable=True))
    # Partial UNIQUE index: one federated identity ⇒ one row (ADR-0028 §6). The
    # predicate exempts local users (idp_subject NULL) so they are unconstrained.
    op.create_index(
        "uq_users_idp_identity",
        "users",
        ["idp_iss", "idp_subject"],
        unique=True,
        postgresql_where=sa.text("idp_subject IS NOT NULL"),
        sqlite_where=sa.text("idp_subject IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_users_idp_identity", table_name="users")
    op.drop_column("users", "idp_subject")
    op.drop_column("users", "idp_iss")
