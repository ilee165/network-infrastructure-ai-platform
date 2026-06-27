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
  false-alarm the verifier). ``seq`` is APP-ASSIGNED: the writer reads
  ``MAX(seq)+1`` under the append advisory lock and sets it BEFORE the insert, so it
  participates in the canonical hash (a tampered ``seq`` then breaks the chain, PR
  #76 round-2 #5) and there is NO volatile DB ``nextval`` default (which would force
  a full table REWRITE + long lock on add, PR #76 round-2 #1). The migration adds
  the column NULLABLE, backfills existing rows deterministically in ``(created_at,
  id)`` append order, then sets NOT NULL — expand/contract-safe, no rewrite. The
  ``seq`` index is built WITHOUT a long blocking lock on the partitioned parent:
  created on ONLY the parent, then each child-partition index is built CONCURRENTLY
  and ATTACHed (PR #76 round-2 #2). A global UNIQUE constraint on the partitioned
  parent would have to fold in the partition key, so ``seq`` uniqueness rests on the
  app-under-lock assignment (PR #76 round-2 #4); on SQLite (the unit-test backend)
  the index is a real UNIQUE index that additionally proves no duplicate is produced.

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

#: Name of the index on the monotonic ``seq`` append-order column (W4-T1 A4; PR #76
#: round-2 #4). INLINED here (D4 — migrations never import models); pinned equal to
#: ``app.models.audit._SEQ_UNIQUE_INDEX_NAME`` by test. On SQLite (the unit-test
#: backend) it is a real UNIQUE index (``Base.metadata`` builds it that way and the
#: round-trip exercises it); on the partitioned PostgreSQL parent a global UNIQUE
#: cannot be enforced without folding the partition key into the constraint, so this
#: is the read-path / ORDER-BY index there and uniqueness of ``seq`` rests on the
#: writer's ``MAX(seq)+1`` assignment under the append advisory lock (#3).
_SEQ_INDEX_NAME = "uq_audit_log_seq"

#: Partition suffixes of the ``audit_log`` range-partitioned parent (mirrors
#: migration 0001 ``_PARTITION_WINDOWS`` + the DEFAULT partition; INLINED per D4).
#: Used ONLY to build the ``seq`` index CONCURRENTLY per child partition so the
#: upgrade never takes a long blocking index lock across the partitions (PR #76
#: round-2 #2). Pinned equal to migration 0001's set by test.
_AUDIT_LOG_PARTITION_SUFFIXES: tuple[str, ...] = ("2026_06", "2026_07", "default")


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

    # The monotonic append-order column ``seq`` (W4-T1 A4). It is APP-ASSIGNED: the
    # audit writer reads ``MAX(seq)+1`` under the append advisory lock and sets
    # ``seq`` BEFORE the insert (so it participates in the canonical hash, PR #76
    # round-2 #5). The migration adds NO volatile DB ``nextval`` default — that would
    # force a full table REWRITE + long lock on a large PostgreSQL audit_log (PR #76
    # round-2 #1).
    if _is_postgresql():
        # Expand/contract-safe add (no rewrite, PR #76 round-2 #1): add the column
        # NULLABLE (metadata-only), backfill existing rows DETERMINISTICALLY in
        # append order (``created_at, id``) via ROW_NUMBER, THEN set NOT NULL. Old
        # (pre-W4) pods writing during an N→N+1 rolling window do not set ``seq``;
        # while NULLABLE their inserts succeed, and NOT NULL is set only after the
        # backfill — a contract a later deploy relies on once no pre-W4 pod can write.
        op.add_column("audit_log", sa.Column("seq", sa.BigInteger(), nullable=True))
        op.execute(
            sa.text(
                "UPDATE audit_log AS a SET seq = s.rn FROM ("
                "SELECT id, created_at, "
                "ROW_NUMBER() OVER (ORDER BY created_at, id) AS rn FROM audit_log"
                ") AS s WHERE a.id = s.id AND a.created_at = s.created_at"
            )
        )
        op.alter_column("audit_log", "seq", existing_type=sa.BigInteger(), nullable=False)

        # The ``seq`` index on the range-partitioned parent, built WITHOUT a long
        # blocking lock (PR #76 round-2 #2): create it on ONLY the parent (brief
        # catalog lock, no scan), then build each child-partition index CONCURRENTLY
        # (no insert-blocking lock) and ATTACH it. CREATE INDEX CONCURRENTLY cannot
        # run inside a transaction, so the per-partition builds run in an
        # ``autocommit_block``. A global UNIQUE on the partitioned parent would have
        # to fold in the partition key, so this is the read/ORDER-BY index and
        # ``seq`` uniqueness rests on the app-under-lock assignment (PR #76 round-2 #4).
        op.execute(sa.text(f"CREATE INDEX {_SEQ_INDEX_NAME} ON ONLY audit_log (seq)"))
        with op.get_context().autocommit_block():
            for suffix in _AUDIT_LOG_PARTITION_SUFFIXES:
                child = f"audit_log_{suffix}"
                child_index = f"{_SEQ_INDEX_NAME}_{suffix}"
                op.execute(sa.text(f"CREATE INDEX CONCURRENTLY {child_index} ON {child} (seq)"))
                op.execute(sa.text(f"ALTER INDEX {_SEQ_INDEX_NAME} ATTACH PARTITION {child_index}"))
    else:
        # SQLite (unit-test backend): no rewrite-lock concern and no partitions, so
        # add the column NOT NULL directly with a constant ``0`` backfill default
        # (SQLite cannot ALTER COLUMN ... SET NOT NULL after the fact). The writer
        # always assigns the real ``seq``; the default only satisfies NOT NULL for
        # any raw insert. A real UNIQUE index additionally proves the writer never
        # produces a duplicate ``seq`` (no CONCURRENTLY — SQLite serialises anyway).
        op.add_column(
            "audit_log",
            sa.Column("seq", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        )
        op.create_index(_SEQ_INDEX_NAME, "audit_log", ["seq"], unique=True)

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
    # Dropping the partitioned-parent index cascades to the attached child indexes;
    # the column drop then removes the ``seq`` column. No sequence to drop — the
    # append-order key is app-assigned, so no DB sequence was ever created (PR #76
    # round-2 #1).
    op.drop_index(_SEQ_INDEX_NAME, table_name="audit_log")
    op.drop_column("audit_log", "seq")
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "prev_hash")
