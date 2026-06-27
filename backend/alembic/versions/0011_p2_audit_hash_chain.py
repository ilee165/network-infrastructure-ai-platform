"""P2 W4-T1 (ADR-0038): audit_log hash chain + verified-checkpoint watermark.

Makes the append-only ``audit_log`` TAMPER-EVIDENT (ADR-0038, PRODUCTION.md §5):

- ``audit_log`` gains ``prev_hash`` / ``entry_hash`` — both the RAW 32-byte
  SHA-256 digest (``bytea`` on PostgreSQL / ``BLOB`` on SQLite via SQLAlchemy
  ``LargeBinary``); one on-disk format, NO hex variant (ADR-0038 §1). The
  application audit writer sets them on every append
  (``entry_hash = SHA-256(canonical(immutable fields) || prev_hash)``, the first
  entry chaining from a fixed genesis); the daily verification job recomputes them
  (§3/§4). ``audit_log`` append-only is enforced by the migration 0001
  ``REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC`` (the 0009 trigger guards the
  ``approvals`` table, not this one); a REVOKE cannot bind the table owner /
  superuser, so the hash chain — not a trigger — is what detects a privileged-actor
  rewrite of a chain link.

  Both columns are ``NOT NULL``. To stay expand/contract-safe (PRODUCTION.md §10)
  on a non-empty table AND across N→N+1 rolling deploys, they are added with a
  genesis server_default (32 zero bytes) that backfills any pre-existing rows AND
  catches inserts from OLD (pre-W4) pods still running during the rolling window —
  those pods do not set the chain columns, so without the default their inserts
  would hit NOT NULL and crash (W4-T1 A7). The default is KEPT through this expand
  migration (the application writer always sets the real per-row hash; the default
  only ever fires for old-code inserts) and may be dropped later in a separate
  CONTRACT migration once no pre-W4 pod can write. Pre-existing / old-code rows
  carry genesis placeholders the verifier will flag — by design: history written
  before chaining cannot be retroactively proven untampered.

- ``audit_log`` gains ``seq`` — a ``BIGINT NOT NULL`` monotonic append-order key
  (ADR-0038 §3, W4-T1 A4). The chain is ORDERED by ``seq`` (not ``(created_at,
  id)``, whose random-UUID tiebreak could invert two equal-``created_at`` rows and
  false-alarm the verifier). On PostgreSQL the value is drawn from a single shared
  ``audit_log_seq`` sequence (``server_default = nextval``) on every INSERT into
  ANY range partition, so ``seq`` is globally monotonic across partitions; on
  SQLite (the unit-test backend, no sequences) the application writer assigns
  ``MAX(seq)+1`` under its serialised head read, and the column carries a constant
  ``0`` backfill default for the rare migration-of-a-non-empty-table case.

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

#: Name of the shared sequence backing the monotonic ``seq`` append-order column
#: (W4-T1 A4). INLINED here (D4 — migrations never import models); pinned equal to
#: ``app.models.audit._SEQ_SEQUENCE_NAME`` by test.
_SEQ_SEQUENCE_NAME = "audit_log_seq"


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
    # Add the chain columns NOT NULL with a genesis server_default so any
    # pre-existing rows backfill AND old (pre-W4) pods still running during an
    # N→N+1 rolling deploy can keep inserting audit rows without hitting NOT NULL
    # (W4-T1 A7, PRODUCTION.md §10 expand-safe). The application writer always sets
    # the real per-row hash (ADR-0038 §3); the default only ever catches old-code
    # inserts. It is KEPT here (a separate CONTRACT migration may drop it later once
    # no pre-W4 pod can write); no DB-side default can compute the real hash.
    default = _genesis_default()
    op.add_column(
        "audit_log",
        sa.Column("prev_hash", sa.LargeBinary(length=32), nullable=False, server_default=default),
    )
    op.add_column(
        "audit_log",
        sa.Column("entry_hash", sa.LargeBinary(length=32), nullable=False, server_default=default),
    )

    # The monotonic append-order column ``seq`` (W4-T1 A4). On PostgreSQL a single
    # shared sequence is the server_default (``nextval``), drawn from on every
    # INSERT into ANY range partition so ``seq`` is globally monotonic across
    # partitions; on SQLite (no sequences) the application writer assigns
    # ``MAX(seq)+1`` and the column carries a constant ``0`` backfill default for
    # the rare non-empty-table migration. NOT NULL + expand-safe in both backends.
    if _is_postgresql():
        op.execute(sa.text(f"CREATE SEQUENCE IF NOT EXISTS {_SEQ_SEQUENCE_NAME}"))
        seq_default: sa.TextClause = sa.text(f"nextval('{_SEQ_SEQUENCE_NAME}'::regclass)")
    else:
        seq_default = sa.text("0")
    op.add_column(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), nullable=False, server_default=seq_default),
    )
    op.create_index("ix_audit_log_seq", "audit_log", ["seq"])

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
    op.drop_index("ix_audit_log_seq", table_name="audit_log")
    op.drop_column("audit_log", "seq")
    if _is_postgresql():
        op.execute(sa.text(f"DROP SEQUENCE IF EXISTS {_SEQ_SEQUENCE_NAME}"))
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "prev_hash")
