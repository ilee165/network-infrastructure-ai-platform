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

from sqlalchemy import LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, UtcDateTime, utcnow

#: Genesis seed for the hash chain (ADR-0038 §1) — 32 zero bytes. Defined here so
#: the model carries no service-layer import (REPO §3.2); it is pinned equal to
#: ``app.services.audit.chain.GENESIS_HASH`` (the canonical definition the writer /
#: verifier use) and to migration 0011's inlined value by test.
_GENESIS_HASH = b"\x00" * 32


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
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
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
