"""Append-only audit log (brief §7, ADR-0004, ADR-0011).

``audit_log`` is range-partitioned by ``created_at`` on PostgreSQL (the
partition option is ignored on SQLite), so the partition key must be part of
the primary key — hence the composite PK ``(id, created_at)``. Append-only
enforcement (INSERT/SELECT-only grants) is applied by migration, not here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Index, LargeBinary, String, func, select
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, UtcDateTime, utcnow

#: Genesis seed for the hash chain (ADR-0038 §1) — 32 zero bytes. Defined here so
#: the model carries no service-layer import (REPO §3.2); it is pinned equal to
#: ``app.services.audit.chain.GENESIS_HASH`` (the canonical definition the writer /
#: verifier use) and to migration 0011's inlined value by test.
_GENESIS_HASH = b"\x00" * 32

#: Name of the read-path / ORDER-BY index on the monotonic append-order column
#: ``seq`` (ADR-0038 §3, W4-T1 A4; PR #76 round-2 #4, round-3 #03/#04). ``seq`` is
#: the chain's ORDER key and the verifier's keyset boundary, so the index serves the
#: head read (``MAX(seq)``) and the verifier's ``ORDER BY seq``. It is NOT unique:
#: ``audit_log`` is ``postgresql_partition_by: RANGE (created_at)``, and a UNIQUE
#: index on ``seq`` ALONE is INVALID on a PostgreSQL partitioned table (the unique
#: key must contain the partition key) — so ``create_all`` / alembic autogenerate on
#: PostgreSQL would break (round-3 #03/#04). ``seq`` uniqueness is guaranteed instead
#: by the app-under-lock ``MAX(seq)+1`` assignment in the writer (PR #76 round-2 #4),
#: proven by a behavioural append test on BOTH backends. Mirrored (inlined) by
#: migration 0011 (D4 — migrations never import models); the two are pinned equal by
#: test. The name keeps its historical ``uq_`` prefix so the on-disk index name is
#: stable across this change (no needless DROP/CREATE churn on existing schemas).
_SEQ_UNIQUE_INDEX_NAME = "uq_audit_log_seq"


def _next_seq(context: Any) -> int:
    """App-side default for the monotonic ``seq`` column on DIRECT construction (A4).

    The audit writer (:func:`app.services.audit.record`) ALWAYS pre-assigns ``seq``
    explicitly — it must, because ``seq`` now participates in the canonical hash
    (PR #76 round-2 #5), so the value has to be known BEFORE ``entry_hash`` is
    computed, which is before the flush. The writer reads ``MAX(seq)+1`` under the
    transaction-scoped append advisory lock (PostgreSQL) / the single connection
    (SQLite), so the value is monotonic in true append order.

    This default therefore fires ONLY on the rare direct-construct path (a handful
    of schema-semantics tests that build :class:`AuditLog` without the writer). It
    computes ``MAX(seq)+1`` on the SAME connection/transaction as the INSERT, in
    both backends — there is no DB sequence and no DB-side volatile default (PR #76
    round-2 #1: a ``nextval`` default would force a full table REWRITE on add). When
    the writer has already set ``seq``, this default never runs.
    """
    connection = context.connection
    current = connection.scalar(select(func.coalesce(func.max(AuditLog.seq), 0)))
    return int(current) + 1


class AuditLog(Base):
    """One audited action: who (`actor`) did what (`action`) to which target.

    ``reasoning_trace_id`` links an audited action back to the reasoning trace
    that produced it (brief §6). It is a plain indexed UUID with NO DB-level FK:
    ``reasoning_traces`` is range-partitioned, and PostgreSQL FKs to a
    partitioned table must include the partition key — the same design used for
    ``raw_artifact_id`` (see ``app.models.inventory``). Linkage integrity is
    enforced by tests, and the column is nullable for non-agent audit entries.

    ``request_id`` is the inbound request/correlation id of the call that
    produced the audited action (ADR-0020 §4 names ``request id`` as a required
    dimension of every transition audit entry). It is a plain indexed UUID with
    no FK — a free-standing correlation handle, captured at the route layer and
    threaded down to :func:`app.services.audit.record`. It is ``None`` for
    actions raised outside an HTTP request (e.g. background/agent-driven
    handoffs that carry no inbound correlation id).

    ``prev_hash`` / ``entry_hash`` form the tamper-evident hash chain (ADR-0038):
    ``entry_hash = SHA-256(canonical(immutable fields) || prev_hash)`` and
    ``prev_hash`` is the predecessor entry's ``entry_hash`` (the fixed
    :data:`app.services.audit.chain.GENESIS_HASH` for the first entry). Both hold
    the RAW 32-byte SHA-256 digest (``bytea`` / ``BLOB``) — one on-disk format, no
    hex variant. They are written by the single application audit writer at insert
    time (ADR-0038 §3) and recomputed by the daily verification job (§4).
    ``audit_log`` append-only is enforced by the migration 0001
    ``REVOKE UPDATE, DELETE ... FROM PUBLIC`` (the 0009 trigger guards
    ``approvals``, not this table); because a REVOKE does not bind the table
    owner / superuser, the hash chain is the real backstop that detects a
    privileged-actor rewrite.
    """

    __tablename__ = "audit_log"
    # A NON-unique read-path / ORDER-BY index on ``seq`` (PR #76 round-2 #4, round-3
    # #03/#04) — ``seq`` is the chain's ORDER key and the verifier's keyset boundary,
    # so the index serves the head read (``MAX(seq)``) and the verifier's
    # ``ORDER BY seq``. It is deliberately NOT unique: this table is
    # ``postgresql_partition_by: RANGE (created_at)``, and a UNIQUE index on ``seq``
    # ALONE is INVALID on a PG partitioned table (the unique key must contain the
    # partition key), so making it unique would break ``create_all`` / alembic
    # autogenerate on PostgreSQL. ``seq`` uniqueness is guaranteed instead by the
    # writer's app-under-lock ``MAX(seq)+1`` assignment (PR #76 round-2 #4) — proven
    # by a behavioural serial/batched-append test on BOTH backends (the test that
    # replaces the lost DB-level guarantee). The composite ``postgresql_partition_by``
    # table option must be the LAST element.
    __table_args__ = (
        Index(_SEQ_UNIQUE_INDEX_NAME, "seq"),
        {"postgresql_partition_by": "RANGE (created_at)"},
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
    # Monotonic append-order key (ADR-0038 §3, W4-T1 A4). The chain's ORDER is this
    # column — NOT ``(created_at, id)`` — so equal-``created_at`` rows can never be
    # ordered ambiguously by the random-UUID tiebreak (which could invert read order
    # and false-alarm the verifier). The audit writer assigns ``MAX(seq)+1`` under
    # the transaction-scoped append advisory lock (PostgreSQL) / the single
    # connection (SQLite) BEFORE the insert — it must, because ``seq`` participates
    # in the canonical hash (PR #76 round-2 #5), so the value is known before
    # ``entry_hash`` is computed (still a SINGLE INSERT, no nextval default → no
    # full table rewrite on add, PR #76 round-2 #1). The ``default`` below fires only
    # on the rare direct-construct test path; the read index lives in
    # ``__table_args__`` above.
    #
    # ``seq`` is NULLABLE (round-3 #01/#02). The expand migration 0011 adds it
    # NULLABLE and KEEPS it nullable through this expand phase: an OLD (pre-W4) pod
    # still inserting audit rows during an N→N+1 rolling deploy does NOT set ``seq``
    # (it is app-assigned, so unlike prev_hash/entry_hash a server_default cannot
    # supply a correct monotonic value), so a NOT-NULL ``seq`` here would crash those
    # legitimate old-writer inserts. New rows are never NULL — the writer always
    # assigns ``MAX(seq)+1`` under the lock. A NULL-seq row is therefore exactly an
    # old-writer / pre-chain row: it also carries the genesis ``entry_hash`` default,
    # so the verifier already treats it as untrusted pre-chain history (it sorts
    # NULLS LAST and flags genesis-hash rows like any genesis row). A later CONTRACT
    # migration will backfill residual NULL ``seq`` and SET NOT NULL once no pre-W4
    # pod can write (NOT written now — see docs/runbooks/audit-chain-verify-and-reseal.md).
    seq: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        default=_next_seq,
    )
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)
    reasoning_trace_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    request_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    # Tamper-evident hash chain (ADR-0038 §1). Raw 32-byte SHA-256 digests — the
    # writer sets them on every append and the verifier recomputes them; never
    # hex, never nullable (a row without a valid chain link is rejected, §3). The
    # app-side ``default`` is the genesis seed (:data:`_GENESIS_HASH`); the single
    # audit writer ALWAYS overrides both with the real per-row chain values before
    # flush (the default merely keeps the NOT NULL columns satisfiable for the rare
    # direct-construction test path without a service-layer import, REPO §3.2).
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, default=_GENESIS_HASH)
    entry_hash: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, default=_GENESIS_HASH
    )


class AuditChainCheckpoint(Base):
    """Last verified-clean watermark for the audit hash chain (ADR-0038 §4).

    A single-row table holding the ``(entry_id, entry_hash)`` of the most recent
    ``audit_log`` entry the daily verification job confirmed clean. The job
    recomputes the chain FROM this checkpoint to the current head (not the whole
    history every day), advancing the watermark only over a verified-clean segment;
    on any mismatch it alerts and exits non-zero without advancing (ADR-0038 §4).

    The fixed ``id`` (:data:`SINGLETON_ID`) makes this an upsert target — there is
    exactly one watermark per deployment. ``entry_created_at`` is stored alongside
    the id because ``audit_log`` is range-partitioned on ``created_at`` (the
    composite PK is ``(id, created_at)``), so resuming the recompute needs the full
    key, not the id alone.
    """

    __tablename__ = "audit_chain_checkpoint"

    #: The fixed primary key of the singleton watermark row (one per deployment).
    SINGLETON_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-0000000a0d38")

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=lambda: AuditChainCheckpoint.SINGLETON_ID
    )
    entry_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    entry_created_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    entry_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    verified_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)


class AuditExportCursor(Base):
    """Durable last-exported watermark for the audit→SIEM export (ADR-0045 §2).

    A single-row table holding the highest ``seq`` the exporter has confirmed
    delivered to (ACKed by) the SIEM sink, plus the exported row's commit timestamp
    (the basis of the ``export_lag_seconds`` SLI, ADR-0045 §3). The exporter reads
    committed ``audit_log`` rows with ``seq > exported_seq`` ordered by ``seq``,
    delivers them, and advances the watermark **only after the sink ACKs** — so a
    crash between "sink received" and "cursor persisted" re-exports the un-advanced
    rows on restart (**at-least-once, never at-most-once**, ADR-0045 §2): no
    committed row is ever skipped, ordering is the ADR-0038 ``seq`` append order,
    and a restart resumes from the persisted ``seq`` with **no gap** (only bounded
    duplication of the in-flight batch, which the SIEM deduplicates on the per-row
    ``seq`` key).

    This is strictly DOWNSTREAM of the audit DB commit (ADR-0045 §3): advancing the
    cursor is a separate transaction in the exporter process; it never holds open or
    rolls back the action transaction that wrote the audit row, so a SIEM outage
    grows the backlog in the durable ``audit_log`` table and the lag gauge — never in
    lost rows and never as backpressure on the audit write path.

    Mirrors the :class:`AuditChainCheckpoint` singleton/upsert pattern (ADR-0038 §4).
    The fixed ``id`` (:data:`SINGLETON_ID`) makes this the one watermark per
    deployment. ``exported_seq`` is ``0`` before the first export (the genesis
    cursor: ``seq > 0`` selects the whole chain, ``seq`` starts at 1).
    """

    __tablename__ = "audit_export_cursor"

    #: The fixed primary key of the singleton export-cursor row (one per deployment).
    #: Distinct from the chain-checkpoint singleton; the ``e`` tail flags "export".
    SINGLETON_ID: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-0000000a0d4e")

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=lambda: AuditExportCursor.SINGLETON_ID
    )
    #: Highest ``audit_log.seq`` confirmed delivered to the SIEM. ``0`` = nothing
    #: exported yet (``seq > 0`` selects the whole chain; the writer assigns ``seq``
    #: from 1). Advanced only on sink ACK — never over an unacknowledged row.
    exported_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: Commit/``created_at`` timestamp of the audit row at ``exported_seq`` — the
    #: basis for ``export_lag_seconds = now − last_exported_commit_ts`` (ADR-0045 §3).
    #: ``None`` until the first row is exported (lag is then undefined → reported 0).
    last_exported_commit_at: Mapped[datetime | None] = mapped_column(UtcDateTime())
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
