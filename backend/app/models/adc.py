"""ADC (F5 BIG-IP) inventory rows: virtual servers + pools (ADR-0050 §4, W1-T3).

Relational projections of the Pydantic models in :mod:`app.schemas.normalized`
(:class:`~app.schemas.normalized.NormalizedVirtualServer` /
:class:`~app.schemas.normalized.NormalizedPool`), mirroring the
``Normalized*Row`` pattern in :mod:`app.models.inventory` field-for-field.

``NormalizedPoolRow.members`` stores the nested
:class:`~app.schemas.normalized.NormalizedPoolMember` tuple as a JSON list of
plain dicts (the ``NormalizedNeighborRow.neighbor_capabilities`` precedent for
a list-shaped column) — members are not a separate table: they nest inside
their pool exactly as F5 returns them (ADR-0050 §4.5), and read-only
surfacing has no need to query across pools by member.

Read-only surfacing (W1-T3): no write endpoint populates these tables yet.
Rows are inserted the same way the existing ``Normalized*Row`` fixtures are in
tests — directly via the ORM — pending a future task wiring a live F5
collection pass into an upsert pipeline (the ``collect_device``/
``persist_device_result`` SSH/SNMP-only dispatch in
:mod:`app.engines.discovery` does not cover ``ADC_SERVICES``, a REST
capability; extending it is a named deferral, not silently dropped).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.inventory import _ProvenanceMixin, _wire_enum
from app.models.mixins import JSON_VARIANT, TimestampMixin, UuidPkMixin
from app.schemas.normalized import AdcAvailability, AdcProtocol

__all__ = ["NormalizedPoolRow", "NormalizedVirtualServerRow"]


class NormalizedVirtualServerRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedVirtualServer`."""

    __tablename__ = "adc_virtual_servers"
    __table_args__ = (UniqueConstraint("device_id", "name"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vip_address: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None]
    protocol: Mapped[AdcProtocol] = mapped_column(_wire_enum(AdcProtocol), nullable=False)
    vrf: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(nullable=False)
    availability: Mapped[AdcAvailability] = mapped_column(
        _wire_enum(AdcAvailability), nullable=False
    )
    pool_name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)


class NormalizedPoolRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedPool`.

    ``members`` is the JSON-encoded ``tuple[NormalizedPoolMember, ...]`` — each
    element a dict with ``name``/``address``/``fqdn``/``port``/``vrf``/
    ``admin_state``/``availability`` keys, matching the Pydantic sub-model
    field-for-field (ADR-0050 §4.3).
    """

    __tablename__ = "adc_pools"
    __table_args__ = (UniqueConstraint("device_id", "name"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    monitors: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    availability: Mapped[AdcAvailability] = mapped_column(
        _wire_enum(AdcAvailability), nullable=False
    )
    members: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_VARIANT, nullable=False, default=list
    )
    description: Mapped[str | None] = mapped_column(Text)
