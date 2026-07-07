"""Application-dependency system of record (ADR-0052 §1/§3.3.3, P4 W2-T1).

Two tables behind ONE expand-only migration (0018):

- ``applications`` — one row per application identity. ``id`` is the Neo4j
  projection key (``pg_id`` on the ``Application`` node, ADR-0052 §5). ``name``
  is unique **case-insensitively** (expression index on ``lower(name)``);
  ``origin_ref`` (the deriving object's stable natural key, e.g.
  ``f5:<device_pg_id>:<vs_full_path>``) is partial-unique where not null so
  re-derivation MERGEs on it and the row UUID — hence the graph node key — is
  stable across re-runs (ADR-0052 §4).
- ``application_dependencies`` — one row per (application, target, source)
  assertion; the natural key ``(application_id, target_kind, target_ref,
  source)`` is what idempotent re-derivation diff-upserts against. ``target_ref``
  is the target row's PG UUID as string — by construction the target label's
  Neo4j key property value (``NODE_KEY_PROPERTY`` is ``pg_id`` for both
  ``Device`` and ``IPAddress``). Targets are restricted to the two rebuild-safe
  kinds (ADR-0052 §2.3).

Enum-valued columns are plain ``String`` with app-layer :class:`~enum.StrEnum`
validation **plus CHECK constraints** — never native PG enums — so SQLite (the
unit suite) and PostgreSQL (``tests/pg/``) agree on semantics (P2
recurring-major lesson; ADR-0052 §1).

Manual-wins dirty tracking (ADR-0052 §3.3.3 — the mechanism W2-T1 binds)
------------------------------------------------------------------------
``derived_watermark`` records the instant a derivation pass last wrote the
row's *attributes* (``name``/``description``/``owner``/``fqdns``). A derivation
write sets ``updated_at`` and ``derived_watermark`` to the **same instant**
(:func:`stamp_derived_watermark`); an operator edit refreshes ``updated_at``
via the house ``onupdate`` without touching the watermark. The invariant both
directions:

1. **Never clobber** — ``updated_at != derived_watermark`` means a user has
   touched the row since the last derivation write; :func:`apply_derived_attributes`
   refuses to overwrite (derivation then refreshes *edges only*, §3.3.3).
2. **Never freeze** — while ``updated_at == derived_watermark`` the row is
   still derivation-managed and every re-derivation may refresh its metadata
   (stale VS names do not fossilise).

Both directions are PG-asserted in ``tests/pg/test_applications_pg.py`` (the
``onupdate``-at-flush semantics are exactly what an in-memory check would
mismodel).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.inventory import _wire_enum
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin, utcnow

__all__ = [
    "Application",
    "ApplicationDependency",
    "ApplicationOrigin",
    "DependencySource",
    "DependencyTargetKind",
    "apply_derived_attributes",
    "derived_attributes_clean",
    "stamp_derived_watermark",
]


class ApplicationOrigin(StrEnum):
    """Who owns an application row's lifecycle (ADR-0052 §1/§3.3.5)."""

    MANUAL = "manual"
    DERIVED = "derived"


class DependencySource(StrEnum):
    """The four ADR-0052 §2 derivation sources — a closed set for P4."""

    F5 = "f5"
    VMWARE = "vmware"
    DNS = "dns"
    MANUAL = "manual"


class DependencyTargetKind(StrEnum):
    """Rebuild-safe projected target kinds only (ADR-0052 §2.3)."""

    DEVICE = "device"
    IP_ADDRESS = "ip_address"


class Application(UuidPkMixin, TimestampMixin, Base):
    """One application identity (ADR-0052 §1, field-for-field)."""

    __tablename__ = "applications"
    __table_args__ = (
        CheckConstraint("origin IN ('manual', 'derived')", name="origin_valid"),
        CheckConstraint("length(name) > 0", name="name_not_empty"),
        # Case-insensitive uniqueness: "payroll" and "Payroll" are the same
        # application (ADR-0052 §3.3.4 name-collision rule).
        Index("uq_applications_lower_name", text("lower(name)"), unique=True),
        # Partial-unique: every derived row MERGEs on its origin_ref; manual
        # rows (origin_ref NULL) are exempt (ADR-0052 §1/§4).
        Index(
            "uq_applications_origin_ref",
            "origin_ref",
            unique=True,
            postgresql_where=text("origin_ref IS NOT NULL"),
            sqlite_where=text("origin_ref IS NOT NULL"),
        ),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    #: FQDNs the application answers on; input to the DNS source (§2.3).
    fqdns: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    origin: Mapped[ApplicationOrigin] = mapped_column(_wire_enum(ApplicationOrigin), nullable=False)
    #: Stable natural key of the deriving object for ``derived`` rows.
    origin_ref: Mapped[str | None] = mapped_column(String(512))
    owner: Mapped[str | None] = mapped_column(String(255))
    #: Set for ``manual`` rows; null for ``derived`` (ADR-0052 §1).
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    #: Manual-wins dirty tracking (§3.3.3): the instant derivation last wrote
    #: this row's attributes; equal to ``updated_at`` iff still derivation-managed.
    derived_watermark: Mapped[datetime | None] = mapped_column(UtcDateTime())


class ApplicationDependency(UuidPkMixin, TimestampMixin, Base):
    """One (application, target, source) assertion (ADR-0052 §1)."""

    __tablename__ = "application_dependencies"
    __table_args__ = (
        # The natural key idempotent re-derivation diff-upserts against (§4).
        UniqueConstraint(
            "application_id",
            "target_kind",
            "target_ref",
            "source",
            name="uq_application_dependencies_natural_key",
        ),
        # Reverse ("what depends on X") reads (ADR-0052 §1).
        Index("ix_application_dependencies_target", "target_kind", "target_ref"),
        CheckConstraint("target_kind IN ('device', 'ip_address')", name="target_kind_valid"),
        CheckConstraint("source IN ('f5', 'vmware', 'dns', 'manual')", name="source_valid"),
    )

    application_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_kind: Mapped[DependencyTargetKind] = mapped_column(
        _wire_enum(DependencyTargetKind), nullable=False
    )
    #: The target row's PG UUID as string — the target label's Neo4j key value.
    target_ref: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[DependencySource] = mapped_column(_wire_enum(DependencySource), nullable=False)
    #: Ordered evidence chain: JSON list of ``{"kind": ..., "ref": ...}`` steps
    #: (§3.1). Refs are row ids / stable natural keys — never row content, never
    #: secret material.
    provenance: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_VARIANT, nullable=False, default=list
    )
    #: When this source last asserted the row.
    derived_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    #: Set for ``source='manual'`` rows only.
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))


# ---------------------------------------------------------------------------
# Manual-wins dirty tracking (ADR-0052 §3.3.3) — the W2-T1-bound mechanism
# ---------------------------------------------------------------------------


def stamp_derived_watermark(application: Application, *, now: datetime | None = None) -> datetime:
    """Mark *application*'s attributes as derivation-managed as of one instant.

    Sets ``updated_at`` **and** ``derived_watermark`` to the same tz-aware
    instant. The explicit ``updated_at`` assignment supersedes the house
    ``onupdate`` for this flush, so after commit the two columns compare equal
    — the "still derivation-managed" state :func:`derived_attributes_clean`
    keys on. Every derivation write of a ``derived`` row's attributes MUST end
    with this stamp (creation included), or the row would read as
    operator-edited and its derived metadata would freeze.
    """
    instant = now if now is not None else utcnow()
    application.updated_at = instant
    application.derived_watermark = instant
    return instant


def derived_attributes_clean(application: Application) -> bool:
    """True iff derivation may refresh this row's attributes (ADR-0052 §3.3.3).

    Three conditions, each a hard gate:

    - ``origin == 'derived'`` — a ``manual``-origin row is user-owned; even
      when derivation attaches edges to it under the §3.3.4 name-collision
      rule, it never takes over the attributes.
    - the watermark exists — a derived row that was never stamped is treated
      as NOT refreshable (conservative: never clobber on ambiguity).
    - ``updated_at == derived_watermark`` — any operator edit refreshes
      ``updated_at`` (house ``onupdate``) without moving the watermark, which
      permanently hands attribute ownership to the user (manual wins).
    """
    return (
        ApplicationOrigin(application.origin) is ApplicationOrigin.DERIVED
        and application.derived_watermark is not None
        and application.updated_at == application.derived_watermark
    )


def apply_derived_attributes(
    application: Application,
    *,
    name: str,
    description: str | None,
    owner: str | None,
    fqdns: Sequence[str],
    now: datetime | None = None,
) -> bool:
    """Refresh derivation-managed attributes under manual-wins (§3.3.3).

    Returns ``True`` when the row was clean and the attributes were applied
    (and re-stamped, so the next derivation pass may refresh again — no
    freeze); ``False`` when the row is operator-edited or ``manual``-origin,
    in which case NOTHING is touched — the caller (a W2-T2 derivation pass)
    refreshes the row's dependency edges only.
    """
    if not derived_attributes_clean(application):
        return False
    application.name = name
    application.description = description
    application.owner = owner
    application.fqdns = list(fqdns)
    stamp_derived_watermark(application, now=now)
    return True
