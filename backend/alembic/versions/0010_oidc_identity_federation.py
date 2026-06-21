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
    # Pair-nullability invariant: the federated anchor is either FULLY present
    # (both non-NULL) or FULLY absent (both NULL) — never half-set (ADR-0028 §6).
    # This closes the NULL-distinct gap where (NULL, 'x') rows would evade the
    # UNIQUE index (NULLs compare distinct), letting one IdP subject map to two
    # rows and breaking the one-identity ⇒ one-user invariant.
    # Name is the convention *suffix* only; MetaData's "ck_%(table_name)s_..."
    # convention renders the full "ck_users_idp_identity_pair" (REPO §4.2).
    op.create_check_constraint(
        "idp_identity_pair",
        "users",
        "(idp_iss IS NULL AND idp_subject IS NULL) "
        "OR (idp_iss IS NOT NULL AND idp_subject IS NOT NULL)",
    )
    # Partial UNIQUE index: one federated identity ⇒ one row (ADR-0028 §6). The
    # predicate now requires BOTH fields non-NULL so the indexed tuple never
    # contains a NULL (which would otherwise compare distinct and admit dupes);
    # local users (both NULL, enforced by the CHECK above) stay unconstrained.
    op.create_index(
        "uq_users_idp_identity",
        "users",
        ["idp_iss", "idp_subject"],
        unique=True,
        postgresql_where=sa.text("idp_iss IS NOT NULL AND idp_subject IS NOT NULL"),
        sqlite_where=sa.text("idp_iss IS NOT NULL AND idp_subject IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_users_idp_identity", table_name="users")
    op.drop_constraint("idp_identity_pair", "users", type_="check")
    op.drop_column("users", "idp_subject")
    op.drop_column("users", "idp_iss")
