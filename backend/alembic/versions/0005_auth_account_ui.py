"""Auth & Account UI: user auth columns + refresh_sessions + system_settings.

Hand-written (mirrors the 0004 style) and schema-only — no data seeding.

``users`` gains ``email`` (nullable, unique), ``display_name`` (nullable) and
``must_change_password`` (NOT NULL, ``server_default false`` so the ADD COLUMN
backfills existing rows). ``refresh_sessions`` records the server-side refresh
sessions whose ids are the refresh-JWT ``sid`` claim (revoke = set
``revoked_at``). ``system_settings`` is the single operator-settings row read by
the LLM registry (provider keys stay in env — never stored here).

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    _add_user_columns()
    _create_refresh_sessions()
    _create_system_settings()


def _add_user_columns() -> None:
    op.add_column("users", sa.Column("email", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("display_name", sa.String(length=255), nullable=True))
    # server_default false backfills existing rows; the column is NOT NULL.
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.create_unique_constraint(op.f("uq_users_email"), "users", ["email"])


def _create_refresh_sessions() -> None:
    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_sessions")),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_refresh_sessions_user_id")
        ),
    )
    op.create_index(op.f("ix_refresh_sessions_user_id"), "refresh_sessions", ["user_id"])


def _create_system_settings() -> None:
    op.create_table(
        "system_settings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("llm_profile", sa.String(length=64), nullable=False),
        sa.Column("llm_role_reasoning", sa.String(length=128), nullable=True),
        sa.Column("llm_role_fast", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_system_settings")),
    )


# ---------------------------------------------------------------------------
# downgrade
# ---------------------------------------------------------------------------


def downgrade() -> None:
    op.drop_table("system_settings")
    op.drop_index(op.f("ix_refresh_sessions_user_id"), table_name="refresh_sessions")
    op.drop_table("refresh_sessions")
    op.drop_constraint(op.f("uq_users_email"), "users", type_="unique")
    op.drop_column("users", "must_change_password")
    op.drop_column("users", "display_name")
    op.drop_column("users", "email")
