"""P4-W2-T1 (ADR-0052 §1): application-dependency system-of-record tables.

**Expand-only** migration adding the two tables behind the application-
dependency topology layer — NOTHING existing is altered (ADR-0004 / N-2
upgrade discipline):

- ``applications`` — one row per application identity; the Neo4j
  ``Application`` node projects from it (``pg_id`` = ``id``). Case-insensitive
  unique name (expression index on ``lower(name)``); partial-unique
  ``origin_ref`` where not null so re-derivation MERGEs keep row UUIDs — and
  hence graph node keys — stable across re-runs (ADR-0052 §4);
  ``derived_watermark`` backs the §3.3.3 manual-wins dirty tracking.
- ``application_dependencies`` — one row per (application, target, source)
  assertion with its JSON provenance chain; natural-key unique
  ``(application_id, target_kind, target_ref, source)`` for idempotent
  diff-upserts (§4); reverse index on ``(target_kind, target_ref)`` for
  "what depends on X" reads; ``ON DELETE CASCADE`` off ``applications``.

Enum-valued columns are plain VARCHAR with explicit CHECK constraints (never
native PG enums) so SQLite and PostgreSQL agree on semantics (ADR-0052 §1).
Portable DDL: plain ``JSON`` (``JSONB`` on PostgreSQL) mirrored from the
app-side ``JSON_VARIANT`` per the existing ``_JSON`` migration convention
(D4: migrations never import models).

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Portable JSON column: plain JSON everywhere, JSONB on PostgreSQL. Mirrors
#: app.models.mixins.JSON_VARIANT (migrations never import models — D4).
_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")

_TIMESTAMP_COLUMNS: tuple[sa.Column, ...] = (
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def upgrade() -> None:
    op.create_table(
        "applications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("fqdns", _JSON, nullable=False),
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("origin_ref", sa.String(length=512), nullable=True),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("derived_watermark", sa.DateTime(timezone=True), nullable=True),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_applications")),
        sa.CheckConstraint(
            "origin IN ('manual', 'derived')", name=op.f("ck_applications_origin_valid")
        ),
        sa.CheckConstraint("length(name) > 0", name=op.f("ck_applications_name_not_empty")),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_applications_created_by")
        ),
    )
    # Case-insensitive unique name (ADR-0052 §1): expression index, supported
    # by both PostgreSQL and SQLite.
    op.create_index(
        "uq_applications_lower_name", "applications", [sa.text("lower(name)")], unique=True
    )
    # Partial-unique origin_ref where not null (ADR-0052 §1/§4).
    op.create_index(
        "uq_applications_origin_ref",
        "applications",
        ["origin_ref"],
        unique=True,
        postgresql_where=sa.text("origin_ref IS NOT NULL"),
        sqlite_where=sa.text("origin_ref IS NOT NULL"),
    )

    op.create_table(
        "application_dependencies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("target_ref", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("provenance", _JSON, nullable=False),
        sa.Column("derived_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        *_TIMESTAMP_COLUMNS,
        sa.PrimaryKeyConstraint("id", name=op.f("pk_application_dependencies")),
        sa.UniqueConstraint(
            "application_id",
            "target_kind",
            "target_ref",
            "source",
            name="uq_application_dependencies_natural_key",
        ),
        sa.CheckConstraint(
            "target_kind IN ('device', 'ip_address')",
            name=op.f("ck_application_dependencies_target_kind_valid"),
        ),
        sa.CheckConstraint(
            "source IN ('f5', 'vmware', 'dns', 'manual')",
            name=op.f("ck_application_dependencies_source_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["application_id"],
            ["applications.id"],
            ondelete="CASCADE",
            name=op.f("fk_application_dependencies_application_id"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_application_dependencies_created_by")
        ),
    )
    op.create_index(
        op.f("ix_application_dependencies_application_id"),
        "application_dependencies",
        ["application_id"],
    )
    op.create_index(
        "ix_application_dependencies_target",
        "application_dependencies",
        ["target_kind", "target_ref"],
    )


def downgrade() -> None:
    op.drop_index("ix_application_dependencies_target", table_name="application_dependencies")
    op.drop_index(
        op.f("ix_application_dependencies_application_id"),
        table_name="application_dependencies",
    )
    op.drop_table("application_dependencies")

    op.drop_index("uq_applications_origin_ref", table_name="applications")
    op.drop_index("uq_applications_lower_name", table_name="applications")
    op.drop_table("applications")
