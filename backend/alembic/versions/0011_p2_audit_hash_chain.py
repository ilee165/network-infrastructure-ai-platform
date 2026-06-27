"""P2 W4-T1 (ADR-0038): audit_log hash chain + verified-checkpoint watermark.

Makes the append-only ``audit_log`` TAMPER-EVIDENT (ADR-0038, PRODUCTION.md §5):

- ``audit_log`` gains ``prev_hash`` / ``entry_hash`` — both the RAW 32-byte
  SHA-256 digest (``bytea`` on PostgreSQL / ``BLOB`` on SQLite via SQLAlchemy
  ``LargeBinary``); one on-disk format, NO hex variant (ADR-0038 §1). The
  application audit writer sets them on every append
  (``entry_hash = SHA-256(canonical(immutable fields) || prev_hash)``, the first
  entry chaining from a fixed genesis); the daily verification job recomputes them
  (§3/§4). The migration 0009 append-only trigger STAYS, so a chain link can never
  be silently rewritten.

  Both columns are ``NOT NULL``. To stay expand/contract-safe (PRODUCTION.md §10)
  on a non-empty table, they are added with a TRANSIENT genesis server_default
  (32 zero bytes) that backfills any pre-existing rows, then the default is
  DROPPED so the application writer is the sole source of chain values going
  forward (no DB-side default could compute the real per-row hash). Pre-existing
  rows therefore carry genesis placeholders the verifier will flag — by design:
  history written before chaining cannot be retroactively proven untampered.

- ``audit_chain_checkpoint`` — a single-row table holding the
  ``(entry_id, entry_created_at, entry_hash)`` of the last verified-clean entry so
  the daily job recomputes FROM the checkpoint to head rather than the whole
  history every day (ADR-0038 §4). ``entry_created_at`` is stored because
  ``audit_log`` is range-partitioned on ``created_at`` (composite PK
  ``(id, created_at)``), so resuming needs the full key.

Portable DDL: ``LargeBinary`` renders ``BYTEA`` on PostgreSQL and ``BLOB`` on
SQLite (the unit-test backend); ADD COLUMN on the partitioned ``audit_log`` parent
propagates to every partition. (D4: migrations never import models.)

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The fixed genesis seed (ADR-0038 §1) — 32 zero bytes. Mirrors
#: ``app.services.audit.chain.GENESIS_HASH`` but is INLINED here (D4: migrations
#: never import application models/constants); the two are pinned equal by test.
_GENESIS = b"\x00" * 32

#: The singleton checkpoint row id — mirrors
#: ``app.models.audit.AuditChainCheckpoint.SINGLETON_ID`` (inlined per D4).
_CHECKPOINT_SINGLETON_ID = "00000000-0000-0000-0000-0000000a0d38"


def _is_postgresql() -> bool:
    """Dialect guard safe in both online and offline (``--sql``) mode."""
    return op.get_context().dialect.name == "postgresql"


def _genesis_default() -> sa.TextClause:
    """A SQL literal for the 32-byte genesis seed, per dialect.

    ``server_default`` must be a SQL clause (not raw Python ``bytes``). PostgreSQL
    spells a bytea literal ``'\\x00…00'::bytea``; SQLite spells a BLOB literal
    ``x'00…00'``. Both decode to the same 32 zero bytes — the expand-safe backfill
    value for any pre-existing rows (dropped again on PostgreSQL below).
    """
    hexed = _GENESIS.hex()
    if _is_postgresql():
        return sa.text(f"'\\x{hexed}'::bytea")
    return sa.text(f"x'{hexed}'")


def upgrade() -> None:
    # Add the chain columns NOT NULL with a TRANSIENT genesis server_default so any
    # pre-existing rows backfill (expand-safe), then drop the default — the
    # application writer computes the real per-row hash on every append (ADR-0038
    # §3); no DB-side default can do that.
    default = _genesis_default()
    op.add_column(
        "audit_log",
        sa.Column("prev_hash", sa.LargeBinary(length=32), nullable=False, server_default=default),
    )
    op.add_column(
        "audit_log",
        sa.Column("entry_hash", sa.LargeBinary(length=32), nullable=False, server_default=default),
    )
    # Drop the transient backfill default so the writer is the sole source of chain
    # values. SQLite (the unit-test backend) cannot ALTER a column default — it
    # never carries pre-existing prod rows, so leaving the harmless default off the
    # SQLite path is fine; PostgreSQL (the prod backend) drops it.
    if _is_postgresql():
        op.alter_column("audit_log", "prev_hash", server_default=None)
        op.alter_column("audit_log", "entry_hash", server_default=None)

    # The verified-clean watermark (ADR-0038 §4): a single-row table the daily job
    # advances over verified-clean segments and resumes the recompute from.
    op.create_table(
        "audit_chain_checkpoint",
        sa.Column(
            "id",
            sa.Uuid(),
            primary_key=True,
            nullable=False,
            server_default=sa.text(f"'{_CHECKPOINT_SINGLETON_ID}'"),
        ),
        sa.Column("entry_id", sa.Uuid(), nullable=False),
        sa.Column("entry_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entry_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_chain_checkpoint")
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "prev_hash")
