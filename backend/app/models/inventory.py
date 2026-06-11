"""Inventory + discovery evidence models (brief §6, ADR-0004, ADR-0011, MVP §3).

Aggregates:

- :class:`DeviceCredential` — envelope-encrypted secrets (AES-256-GCM): the
  table holds ciphertext/nonces/wrapped-DEK **only**; there is no plaintext
  column anywhere, and ``__repr__`` never renders secret bytes.
- :class:`Device` — the device inventory keyed by unique ``mgmt_ip``.
- :class:`DiscoveryRun` — one seed-expansion discovery job and its outcome.
- :class:`RawArtifact` — verbatim command output (D11 auditability), range-
  partitioned by ``created_at`` on PostgreSQL ⇒ composite PK (id, created_at).
- ``Normalized*Row`` — relational projections of the Pydantic models in
  :mod:`app.schemas.normalized`, with natural-key unique constraints so the
  normalization pipeline can upsert idempotently (MVP §3 exit criteria).

Design decision (fixed): rows reference ``raw_artifacts`` via a plain indexed
``raw_artifact_id`` UUID with **no** DB-level FK — PostgreSQL requires FKs to
partitioned tables to include the partition key, which is not worth it here;
linkage integrity is enforced by tests (M1-18).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy import Enum as SaEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.mixins import JSON_VARIANT, TimestampMixin, UtcDateTime, UuidPkMixin, utcnow
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

# ---------------------------------------------------------------------------
# Wire-value StrEnums (REPO-STRUCTURE §4.1)
# ---------------------------------------------------------------------------


class DeviceStatus(StrEnum):
    """Reachability lifecycle of an inventory device."""

    NEW = "new"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"


class CredentialKind(StrEnum):
    """What the encrypted secret unlocks."""

    SSH = "ssh"
    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"


class DiscoveryRunStatus(StrEnum):
    """Lifecycle of a discovery run."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


def _wire_enum(enum_cls: type[StrEnum], *, length: int = 32) -> SaEnum:
    """Portable enum column persisting StrEnum *values* as VARCHAR.

    ``native_enum=False`` keeps SQLite/Postgres DDL identical and avoids
    Postgres ``CREATE TYPE`` churn; values (not member names) go on the wire.
    """
    return SaEnum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda enum_type: [member.value for member in enum_type],
    )


# ---------------------------------------------------------------------------
# Credentials + devices
# ---------------------------------------------------------------------------


class DeviceCredential(UuidPkMixin, TimestampMixin, Base):
    """Envelope-encrypted device credential (D11, ADR-0011).

    Secret material exists only as AES-256-GCM ciphertext plus the wrapped
    data-encryption key; ``params`` holds non-secret protocol metadata only
    (e.g. SNMPv3 auth/priv protocol names — never keys or passphrases).
    """

    __tablename__ = "device_credentials"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    kind: Mapped[CredentialKind] = mapped_column(_wire_enum(CredentialKind), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kek_version: Mapped[str] = mapped_column(String(64), nullable=False)
    params: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT)

    def __repr__(self) -> str:
        """Identity only — secret-bearing columns are never rendered."""
        return f"<DeviceCredential id={self.id} name={self.name!r} kind={self.kind!s}>"


class Device(UuidPkMixin, TimestampMixin, Base):
    """A managed network device, keyed operationally by unique ``mgmt_ip``."""

    __tablename__ = "devices"

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    mgmt_ip: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    vendor_id: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    serial: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[DeviceStatus] = mapped_column(
        _wire_enum(DeviceStatus), nullable=False, default=DeviceStatus.NEW
    )
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("device_credentials.id"), index=True
    )
    last_discovered_at: Mapped[datetime | None] = mapped_column(UtcDateTime())

    credential: Mapped[DeviceCredential | None] = relationship(lazy="joined")


# ---------------------------------------------------------------------------
# Discovery runs + raw evidence
# ---------------------------------------------------------------------------


class DiscoveryRun(UuidPkMixin, TimestampMixin, Base):
    """One discovery job: seeds, bounds, credentials tried, and the outcome."""

    __tablename__ = "discovery_runs"

    status: Mapped[DiscoveryRunStatus] = mapped_column(
        _wire_enum(DiscoveryRunStatus), nullable=False, default=DiscoveryRunStatus.PENDING
    )
    seeds: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    hop_limit: Mapped[int] = mapped_column(nullable=False)
    allowlist: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    credential_names: Mapped[list[str]] = mapped_column(JSON_VARIANT, nullable=False, default=list)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON_VARIANT, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime())


class RawArtifact(Base):
    """Verbatim device output stored before parsing (D11 auditability).

    Range-partitioned by ``created_at`` on PostgreSQL (option ignored on
    SQLite), hence the composite PK ``(id, created_at)``. Other tables point
    at rows here via plain ``raw_artifact_id`` UUID columns — see module
    docstring for why there is no DB-level FK.
    """

    __tablename__ = "raw_artifacts"
    __table_args__ = {"postgresql_partition_by": "RANGE (created_at)"}

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), primary_key=True, default=utcnow)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("discovery_runs.id"), index=True)
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    parsed: Mapped[dict[str, Any] | list[dict[str, Any]] | None] = mapped_column(JSON_VARIANT)


# ---------------------------------------------------------------------------
# Normalized projections (mirror app/schemas/normalized.py)
# ---------------------------------------------------------------------------


class _ProvenanceMixin:
    """Provenance triple + raw-artifact linkage shared by normalized rows."""

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True
    )
    raw_artifact_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    collected_at: Mapped[datetime] = mapped_column(UtcDateTime(), nullable=False)
    source_vendor: Mapped[str] = mapped_column(String(64), nullable=False)


class NormalizedInterfaceRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedInterface`."""

    __tablename__ = "normalized_interfaces"
    __table_args__ = (UniqueConstraint("device_id", "name"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    admin_status: Mapped[InterfaceAdminStatus] = mapped_column(
        _wire_enum(InterfaceAdminStatus), nullable=False
    )
    oper_status: Mapped[InterfaceOperStatus] = mapped_column(
        _wire_enum(InterfaceOperStatus), nullable=False
    )
    mac_address: Mapped[str | None] = mapped_column(String(17))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    mtu: Mapped[int | None]
    speed_mbps: Mapped[int | None]
    duplex: Mapped[InterfaceDuplex | None] = mapped_column(_wire_enum(InterfaceDuplex))
    vlan_id: Mapped[int | None]
    input_errors: Mapped[int | None] = mapped_column(BigInteger)
    output_errors: Mapped[int | None] = mapped_column(BigInteger)


class NormalizedRouteRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedRoute`.

    ``prefix`` is the CIDR string of ``NormalizedRoute.destination``.
    """

    __tablename__ = "normalized_routes"
    __table_args__ = (
        UniqueConstraint("device_id", "vrf", "prefix", "protocol", "next_hop", "interface"),
    )

    prefix: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[RouteProtocol] = mapped_column(_wire_enum(RouteProtocol), nullable=False)
    next_hop: Mapped[str | None] = mapped_column(String(64))
    interface: Mapped[str | None] = mapped_column(String(255))
    vrf: Mapped[str | None] = mapped_column(String(64))
    distance: Mapped[int | None]
    metric: Mapped[int | None] = mapped_column(BigInteger)


class NormalizedNeighborRow(UuidPkMixin, TimestampMixin, _ProvenanceMixin, Base):
    """Relational projection of :class:`app.schemas.normalized.NormalizedNeighbor`."""

    __tablename__ = "normalized_neighbors"
    __table_args__ = (
        UniqueConstraint(
            "device_id", "protocol", "local_interface", "neighbor_name", "neighbor_interface"
        ),
    )

    protocol: Mapped[NeighborProtocol] = mapped_column(_wire_enum(NeighborProtocol), nullable=False)
    local_interface: Mapped[str] = mapped_column(String(255), nullable=False)
    neighbor_name: Mapped[str] = mapped_column(String(255), nullable=False)
    neighbor_interface: Mapped[str | None] = mapped_column(String(255))
    neighbor_platform: Mapped[str | None] = mapped_column(String(255))
    neighbor_address: Mapped[str | None] = mapped_column(String(64))
    neighbor_capabilities: Mapped[list[str]] = mapped_column(
        JSON_VARIANT, nullable=False, default=list
    )
