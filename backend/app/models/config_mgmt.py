"""Config-management + documentation persistence models (M4; ADR-0004 §2/§3,
ADR-0017, ADR-0018, ADR-0019).

Aggregates:

- :class:`ConfigSnapshot` — a device configuration captured verbatim and
  content-addressed (SHA-256 of the normalized text). Per ADR-0017 the content
  is stored **raw at rest** (parity with ``raw_artifacts``: RBAC + audit, never
  redacted at rest); the A9 redaction layer applies only at the LLM boundary.
  ``(device_id, content_hash)`` is unique so an unchanged re-capture dedups to a
  single blob; ``baseline`` marks the current last-approved config per device.
- :class:`CompliancePolicy` — one declarative YAML policy *version* (ADR-0018):
  ``scope`` (vendors/roles/sites) and ``rules`` ride in JSONB; ``(id, version)``
  is unique so a policy may evolve without losing prior versions.
- :class:`Document` — a generated artifact (ADR-0019): inventory / diagram /
  runbook, in md / csv / mermaid, with ``source_refs`` provenance and the
  generating ``agent_sessions`` id.
- :class:`Embedding` — one chunk of a document embedded into pgvector for RAG
  (ADR-0004 §3): a fixed-dimension ``vector`` column indexed HNSW/cosine on
  PostgreSQL. The dimension tracks the configured embedding profile (D9,
  default ``nomic-embed-text`` → 768); changing models is a re-embed migration,
  not a schema redesign.

Portability: the ``vector`` column is ``VECTOR(EMBEDDING_DIM)`` on PostgreSQL and
falls back to ``TEXT`` on the SQLite unit-test backend (``with_variant``), the
same portability posture ``JSON_VARIANT`` uses for JSONB. The HNSW/cosine index
is PostgreSQL-only DDL expressed by the migration (a no-op on SQLite).

Design decision (fixed): ``embeddings.document_id`` is a real FK to the
non-partitioned ``documents`` table (these tables are not partitioned), unlike
the ``raw_artifact_id`` / ``trace_id`` plain-UUID pattern used for partitioned
parents.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import BigInteger, Boolean, ForeignKey, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy import Enum as SaEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin, utcnow

__all__ = [
    "EMBEDDING_DIM",
    "CompliancePolicy",
    "ConfigArchive",
    "ConfigBackupRun",
    "ConfigSnapshot",
    "ConfigSource",
    "Document",
    "DocumentFormat",
    "DocumentKind",
    "Embedding",
]

#: Embedding vector dimension of the default local profile (D9,
#: ``nomic-embed-text`` → 768, ADR-0009 §6). Fixed on the column because an HNSW
#: index requires a known dimension; changing the embedding model is a re-embed
#: migration (ADR-0004 §3), not an ad-hoc schema edit.
EMBEDDING_DIM = 768

#: Portable embedding column: pgvector ``VECTOR(EMBEDDING_DIM)`` on PostgreSQL,
#: ``TEXT`` on SQLite (the unit-test backend cannot create a VECTOR type). Mirrors
#: the ``JSON_VARIANT`` JSONB-vs-JSON portability pattern.
VECTOR_VARIANT = Vector(EMBEDDING_DIM).with_variant(Text(), "sqlite")


class ConfigSource(StrEnum):
    """How a configuration snapshot was captured."""

    SCHEDULED = "scheduled"
    ON_DEMAND = "on_demand"


class ConfigBackupRun(Base):
    """One nightly-backup run record — the idempotency guard for ``config.nightly_backup``.

    ``run_uuid`` is both the primary key and the idempotency token: the beat caller
    (or a deterministic slot-derived UUID) supplies it before the fan-out, and the
    INSERT uses ``ON CONFLICT DO NOTHING``. A redelivered ``nightly_backup`` task
    that inserts the same ``run_uuid`` gets no row inserted (``rowcount == 0``) and
    skips the audit emit + fan-out, collapsing the double-delivery to exactly one
    started/finished audit pair and one wave of captures (ADR-0008 §5, ADR-0043 §6).

    ``status`` is a short VARCHAR updated once at run completion (``"running"`` →
    terminal value). It is NOT append-only — it is a mutable lifecycle column, not
    part of the audit hash chain.
    """

    __tablename__ = "config_backup_runs"

    run_uuid: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    scheduled_slot: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


class DocumentKind(StrEnum):
    """What a generated document is."""

    INVENTORY = "inventory"
    DIAGRAM = "diagram"
    RUNBOOK = "runbook"
    INCIDENT_REPORT = "incident_report"


class DocumentFormat(StrEnum):
    """Serialization format of a generated document's content."""

    MD = "md"
    CSV = "csv"
    MERMAID = "mermaid"


def _wire_enum(enum_cls: type[StrEnum], *, length: int = 32) -> SaEnum:
    """Portable enum column persisting StrEnum *values* as VARCHAR.

    ``native_enum=False`` keeps SQLite/Postgres DDL identical and avoids Postgres
    ``CREATE TYPE`` churn; values (not member names) go on the wire. Mirrors
    ``app.models.inventory._wire_enum``.
    """
    return SaEnum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda enum_type: [member.value for member in enum_type],
    )


class ConfigSnapshot(UuidPkMixin, TimestampMixin, Base):
    """A verbatim, content-addressed device configuration snapshot (ADR-0017).

    ``content`` is the raw config text stored unredacted at rest (RBAC + audit,
    parity with ``raw_artifacts``); ``content_hash`` is the SHA-256 of the
    normalized text — the ``(device_id, content_hash)`` unique constraint dedups
    an unchanged re-capture to a single row. ``baseline`` flags the current
    last-approved config a drift check diffs against.
    """

    __tablename__ = "config_snapshots"
    __table_args__ = (
        UniqueConstraint("device_id", "content_hash", name="uq_config_snapshots_device_hash"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True
    )
    captured_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[ConfigSource] = mapped_column(_wire_enum(ConfigSource), nullable=False)
    capture_run_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ConfigArchive(UuidPkMixin, TimestampMixin, Base):
    """A secret-bearing full-fidelity binary config archive (UCS) at rest (ADR-0050 §7.3).

    The archive is **double-encrypted**: it arrives already passphrase-encrypted
    on-box (the per-backup passphrase lives in the credential vault, referenced by
    ``passphrase_ref``), and this row stores that ciphertext **envelope-encrypted a
    second time** with the D11/ADR-0032 machinery (per-archive DEK wrapped by the
    KEK, AAD = this row id). Reading the DB alone yields double-encrypted bytes;
    the vault passphrase row AND the KEK are both required to reconstruct a usable
    UCS. Metadata columns (device, format, ``size_bytes``, ``sha256``) are log-safe;
    ``ciphertext`` never appears on any API/log surface (metadata-only, no download
    endpoint in P4). ``sha256`` is the digest of the passphrase-encrypted archive
    (integrity verification at restore). The archive row + its vault passphrase row
    are an atomic pair — deleting one deletes the other (ADR-0050 §7.3).
    """

    __tablename__ = "config_archives"

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True
    )
    captured_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    archive_format: Mapped[str] = mapped_column(String(16), nullable=False, default="ucs")
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    passphrase_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    # Second (platform) envelope over the already-passphrase-encrypted UCS bytes.
    # Mirrors the DeviceCredential envelope columns (ADR-0032 §1).
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kek_version: Mapped[str] = mapped_column(String(64), nullable=False)

    def __repr__(self) -> str:
        # Never render ciphertext / passphrase_ref bytes — metadata-only surface.
        return (
            f"ConfigArchive(id={self.id!r}, device_id={self.device_id!r}, "
            f"format={self.archive_format!r}, size_bytes={self.size_bytes!r}, "
            f"sha256={self.sha256!r})"
        )


class CompliancePolicy(UuidPkMixin, TimestampMixin, Base):
    """One version of a declarative YAML compliance policy (ADR-0018).

    ``policy_id`` is the operator-facing policy identifier (e.g.
    ``baseline-hardening``); ``version`` bumps on every edit. ``(policy_id,
    version)`` is unique so prior versions are retained. ``scope`` (vendors /
    roles / sites) and ``rules`` (the typed assertion list) ride as JSONB exactly
    as authored.
    """

    __tablename__ = "compliance_policies"
    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_compliance_policies_policy_version"),
    )

    policy_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[int] = mapped_column(nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON_VARIANT, nullable=False, default=dict)
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSON_VARIANT, nullable=False, default=list)


class Document(UuidPkMixin, TimestampMixin, Base):
    """A generated documentation artifact (ADR-0019).

    Inventory / diagram / runbook in md / csv / mermaid. ``source_refs`` records
    the device/site/run ids the artifact was generated from (provenance);
    ``generated_by_session_id`` links the producing agent run.
    """

    __tablename__ = "documents"

    kind: Mapped[DocumentKind] = mapped_column(_wire_enum(DocumentKind), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    format: Mapped[DocumentFormat] = mapped_column(_wire_enum(DocumentFormat), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_refs: Mapped[dict[str, Any]] = mapped_column(JSON_VARIANT, nullable=False, default=dict)
    generated_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False, default=utcnow)
    generated_by_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_sessions.id"), index=True
    )


class Embedding(UuidPkMixin, TimestampMixin, Base):
    """One embedded chunk of a :class:`Document` for pgvector RAG (ADR-0004 §3).

    ``embedding`` is a fixed-dimension vector (``EMBEDDING_DIM``) indexed
    HNSW/cosine on PostgreSQL (the index is migration DDL, PostgreSQL-only).
    ``(document_id, chunk_index)`` is unique so re-embedding a document replaces
    chunks deterministically (ADR-0019 §5 — no orphan vectors).
    """

    __tablename__ = "embeddings"
    __table_args__ = (
        UniqueConstraint("document_id", "chunk_index", name="uq_embeddings_document_chunk"),
    )

    document_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("documents.id"), nullable=False, index=True
    )
    chunk_index: Mapped[int] = mapped_column(nullable=False)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[Any] = mapped_column(VECTOR_VARIANT, nullable=False)
