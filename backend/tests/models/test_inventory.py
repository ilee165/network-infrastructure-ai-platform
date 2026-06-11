"""Inventory model roundtrips, JSON columns, enum wire values, natural keys."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import null, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CredentialKind,
    Device,
    DeviceCredential,
    DeviceStatus,
    DiscoveryRun,
    DiscoveryRunStatus,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

COLLECTED_AT = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


def _credential(**overrides: Any) -> DeviceCredential:
    values: dict[str, Any] = {
        "name": "lab-ssh",
        "kind": CredentialKind.SSH,
        "username": "netops",
        "ciphertext": b"\x01\x02\x03",
        "nonce": b"\x04" * 12,
        "wrapped_dek": b"\x05" * 40,
        "dek_nonce": b"\x06" * 12,
        "kek_version": "v1",
        "params": None,
    }
    values.update(overrides)
    return DeviceCredential(**values)


def _provenance(device: Device, artifact_id: uuid.UUID) -> dict[str, Any]:
    return {
        "device_id": device.id,
        "raw_artifact_id": artifact_id,
        "collected_at": COLLECTED_AT,
        "source_vendor": "cisco_ios",
    }


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------


async def test_device_roundtrip_and_status_wire_value(
    session: AsyncSession, device: Device
) -> None:
    """Devices persist with the StrEnum *value* (not name) in the column."""
    await session.commit()

    reloaded = (
        await session.execute(
            select(Device).where(Device.id == device.id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.status is DeviceStatus.NEW
    assert reloaded.mgmt_ip == "192.0.2.10"
    assert reloaded.credential_id is None
    assert reloaded.last_discovered_at is None

    stored = (await session.execute(text("SELECT status FROM devices"))).scalar_one()
    assert stored == "new"


async def test_device_mgmt_ip_unique(session: AsyncSession, device: Device) -> None:
    session.add(Device(hostname="other", mgmt_ip=device.mgmt_ip))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_device_links_to_credential(session: AsyncSession) -> None:
    credential = _credential()
    session.add(credential)
    await session.flush()
    device = Device(hostname="fw-1", mgmt_ip="192.0.2.20", credential_id=credential.id)
    session.add(device)
    await session.commit()

    reloaded = (
        await session.execute(
            select(Device).where(Device.id == device.id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.credential is not None
    assert reloaded.credential.name == "lab-ssh"


# ---------------------------------------------------------------------------
# DeviceCredential
# ---------------------------------------------------------------------------


async def test_credential_roundtrip_binary_and_json_params(session: AsyncSession) -> None:
    params = {"auth_protocol": "SHA-256", "priv_protocol": "AES-128", "security_level": "authPriv"}
    credential = _credential(name="lab-snmpv3", kind=CredentialKind.SNMP_V3, params=params)
    session.add(credential)
    await session.commit()

    reloaded = (
        await session.execute(
            select(DeviceCredential)
            .where(DeviceCredential.id == credential.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.kind is CredentialKind.SNMP_V3
    assert reloaded.ciphertext == b"\x01\x02\x03"
    assert reloaded.nonce == b"\x04" * 12
    assert reloaded.wrapped_dek == b"\x05" * 40
    assert reloaded.dek_nonce == b"\x06" * 12
    assert reloaded.kek_version == "v1"
    assert reloaded.params == params


async def test_credential_name_unique(session: AsyncSession) -> None:
    session.add(_credential(name="dup"))
    await session.flush()
    session.add(_credential(name="dup", kind=CredentialKind.SNMP_V2C))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_credential_repr_contains_no_secret_material(session: AsyncSession) -> None:
    credential = _credential(ciphertext=b"supersecretciphertext")
    session.add(credential)
    await session.flush()
    rendered = repr(credential)
    assert "supersecret" not in rendered
    assert "ciphertext" not in rendered


# ---------------------------------------------------------------------------
# DiscoveryRun
# ---------------------------------------------------------------------------


async def test_discovery_run_defaults_and_json_roundtrip(session: AsyncSession) -> None:
    run = DiscoveryRun(
        seeds=["192.0.2.10"],
        hop_limit=2,
        allowlist=["192.0.2.0/24"],
        credential_names=["lab-ssh", "lab-snmpv3"],
    )
    session.add(run)
    await session.flush()
    assert run.status is DiscoveryRunStatus.PENDING
    assert run.stats == {}
    assert run.error is None
    assert run.started_at is None
    assert run.finished_at is None

    run.status = DiscoveryRunStatus.SUCCEEDED
    run.stats = {"devices": 3, "interfaces": 42, "per_device": {"lab-sw-01": "ok"}}
    run.started_at = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    run.finished_at = datetime(2026, 6, 10, 12, 5, tzinfo=UTC)
    await session.commit()

    reloaded = (
        await session.execute(
            select(DiscoveryRun)
            .where(DiscoveryRun.id == run.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.status is DiscoveryRunStatus.SUCCEEDED
    assert reloaded.seeds == ["192.0.2.10"]
    assert reloaded.allowlist == ["192.0.2.0/24"]
    assert reloaded.credential_names == ["lab-ssh", "lab-snmpv3"]
    assert reloaded.stats == {"devices": 3, "interfaces": 42, "per_device": {"lab-sw-01": "ok"}}
    assert reloaded.finished_at == datetime(2026, 6, 10, 12, 5, tzinfo=UTC)


# ---------------------------------------------------------------------------
# RawArtifact
# ---------------------------------------------------------------------------


async def test_raw_artifact_roundtrip_with_parsed_json(
    session: AsyncSession, device: Device
) -> None:
    run = DiscoveryRun(seeds=[], hop_limit=1, allowlist=[], credential_names=[])
    session.add(run)
    await session.flush()

    parsed = [{"interface": "GigabitEthernet0/1", "status": "up"}]
    artifact = RawArtifact(
        device_id=device.id,
        run_id=run.id,
        command="show interfaces",
        raw_text="GigabitEthernet0/1 is up, line protocol is up\n",
        parsed=parsed,
    )
    session.add(artifact)
    await session.commit()

    reloaded = (
        await session.execute(
            select(RawArtifact)
            .where(RawArtifact.id == artifact.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.raw_text.startswith("GigabitEthernet0/1 is up")
    assert reloaded.parsed == parsed
    assert reloaded.run_id == run.id
    assert reloaded.created_at.tzinfo == UTC


async def test_raw_artifact_run_id_nullable(session: AsyncSession, device: Device) -> None:
    artifact = RawArtifact(
        device_id=device.id, command="show version", raw_text="Cisco IOS Software ...\n"
    )
    session.add(artifact)
    await session.flush()
    assert artifact.run_id is None
    assert artifact.parsed is None


# ---------------------------------------------------------------------------
# Normalized rows
# ---------------------------------------------------------------------------


async def test_normalized_rows_roundtrip(session: AsyncSession, device: Device) -> None:
    artifact_id = uuid.uuid4()
    interface = NormalizedInterfaceRow(
        **_provenance(device, artifact_id),
        name="GigabitEthernet0/1",
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        mac_address="fa:16:3e:11:22:33",
        ip_address="192.0.2.1/24",
        mtu=1500,
        speed_mbps=1000,
        input_errors=0,
        output_errors=12,
    )
    route = NormalizedRouteRow(
        **_provenance(device, artifact_id),
        prefix="10.0.0.0/8",
        protocol=RouteProtocol.OSPF,
        next_hop="192.0.2.254",
        interface="GigabitEthernet0/1",
        vrf="CORP",
        distance=110,
        metric=20,
    )
    neighbor = NormalizedNeighborRow(
        **_provenance(device, artifact_id),
        protocol=NeighborProtocol.LLDP,
        local_interface="GigabitEthernet0/1",
        neighbor_name="lab-sw-02",
        neighbor_interface="Ethernet1",
        neighbor_platform="Arista vEOS",
        neighbor_address="192.0.2.11",
        neighbor_capabilities=["bridge", "router"],
    )
    session.add_all([interface, route, neighbor])
    await session.commit()

    loaded_interface = (
        await session.execute(
            select(NormalizedInterfaceRow).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert loaded_interface.admin_status is InterfaceAdminStatus.UP
    assert loaded_interface.raw_artifact_id == artifact_id
    assert loaded_interface.collected_at == COLLECTED_AT

    loaded_route = (
        await session.execute(select(NormalizedRouteRow).execution_options(populate_existing=True))
    ).scalar_one()
    assert loaded_route.protocol is RouteProtocol.OSPF
    assert loaded_route.prefix == "10.0.0.0/8"

    loaded_neighbor = (
        await session.execute(
            select(NormalizedNeighborRow).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert loaded_neighbor.protocol is NeighborProtocol.LLDP
    assert loaded_neighbor.neighbor_capabilities == ["bridge", "router"]


async def test_interface_natural_key_unique(session: AsyncSession, device: Device) -> None:
    common = {
        **_provenance(device, uuid.uuid4()),
        "name": "Loopback0",
        "admin_status": InterfaceAdminStatus.UP,
        "oper_status": InterfaceOperStatus.UP,
    }
    session.add(NormalizedInterfaceRow(**common))
    await session.flush()
    session.add(NormalizedInterfaceRow(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_route_natural_key_unique(session: AsyncSession, device: Device) -> None:
    common = {
        **_provenance(device, uuid.uuid4()),
        "prefix": "0.0.0.0/0",
        "protocol": RouteProtocol.STATIC,
        "next_hop": "192.0.2.254",
        "interface": "GigabitEthernet0/1",
        "vrf": "CORP",
    }
    session.add(NormalizedRouteRow(**common))
    await session.flush()

    # A different next_hop is a different row (ECMP), not a violation.
    session.add(NormalizedRouteRow(**{**common, "next_hop": "192.0.2.253"}))
    await session.flush()

    session.add(NormalizedRouteRow(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_neighbor_natural_key_unique(session: AsyncSession, device: Device) -> None:
    common = {
        **_provenance(device, uuid.uuid4()),
        "protocol": NeighborProtocol.CDP,
        "local_interface": "GigabitEthernet0/2",
        "neighbor_name": "lab-rtr-01",
        "neighbor_interface": "GigabitEthernet0/0",
    }
    session.add(NormalizedNeighborRow(**common))
    await session.flush()
    session.add(NormalizedNeighborRow(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


# ---------------------------------------------------------------------------
# Natural keys with absent optional components ('' sentinel, not NULL)
# ---------------------------------------------------------------------------


async def test_route_natural_key_unique_for_global_connected_route(
    session: AsyncSession, device: Device
) -> None:
    """Global-table connected routes (no vrf, no next_hop) must still dedupe.

    Optional key columns store the ``''`` sentinel instead of NULL, so the
    unique constraint fires under default NULLS DISTINCT semantics on both
    SQLite and PostgreSQL.
    """
    common = {
        **_provenance(device, uuid.uuid4()),
        "prefix": "192.0.2.0/24",
        "protocol": RouteProtocol.CONNECTED,
        "interface": "GigabitEthernet0/1",
    }
    session.add(NormalizedRouteRow(**common))
    await session.flush()
    session.add(NormalizedRouteRow(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_neighbor_natural_key_unique_without_neighbor_interface(
    session: AsyncSession, device: Device
) -> None:
    """Neighbors that omit neighbor_interface must still dedupe ('' sentinel)."""
    common = {
        **_provenance(device, uuid.uuid4()),
        "protocol": NeighborProtocol.LLDP,
        "local_interface": "GigabitEthernet0/3",
        "neighbor_name": "lab-ap-01",
    }
    session.add(NormalizedNeighborRow(**common))
    await session.flush()
    session.add(NormalizedNeighborRow(**common))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_route_optional_key_columns_default_to_sentinel(
    session: AsyncSession, device: Device
) -> None:
    """Omitted vrf/next_hop/interface persist as '' (the absent sentinel)."""
    route = NormalizedRouteRow(
        **_provenance(device, uuid.uuid4()),
        prefix="198.51.100.1/32",
        protocol=RouteProtocol.LOCAL,
    )
    session.add(route)
    await session.commit()

    reloaded = (
        await session.execute(
            select(NormalizedRouteRow)
            .where(NormalizedRouteRow.id == route.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.vrf == ""
    assert reloaded.next_hop == ""
    assert reloaded.interface == ""


async def test_neighbor_interface_defaults_to_sentinel(
    session: AsyncSession, device: Device
) -> None:
    """Omitted neighbor_interface persists as '' (the absent sentinel)."""
    neighbor = NormalizedNeighborRow(
        **_provenance(device, uuid.uuid4()),
        protocol=NeighborProtocol.CDP,
        local_interface="GigabitEthernet0/4",
        neighbor_name="lab-phone-01",
    )
    session.add(neighbor)
    await session.commit()

    reloaded = (
        await session.execute(
            select(NormalizedNeighborRow)
            .where(NormalizedNeighborRow.id == neighbor.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.neighbor_interface == ""


async def test_explicit_none_coerces_to_sentinel_in_orm(
    session: AsyncSession, device: Device
) -> None:
    """ORM writers passing Pydantic ``None`` get the '' sentinel automatically.

    SQLAlchemy applies the Python-side default when an attribute is None, so
    naive ``next_hop=route.next_hop`` mappings stay NULL-free.
    """
    route = NormalizedRouteRow(
        **_provenance(device, uuid.uuid4()),
        prefix="10.1.0.0/16",
        protocol=RouteProtocol.CONNECTED,
        next_hop=None,
        vrf=None,
        interface="GigabitEthernet0/6",
    )
    session.add(route)
    await session.flush()
    stored = (
        await session.execute(
            text("SELECT vrf, next_hop FROM normalized_routes WHERE prefix = '10.1.0.0/16'")
        )
    ).one()
    assert tuple(stored) == ("", "")


async def test_natural_key_columns_reject_sql_null(session: AsyncSession, device: Device) -> None:
    """A forced SQL NULL in a natural-key column violates NOT NULL.

    NULL would silently disable the unique constraint (NULLS DISTINCT), so the
    DDL must reject it outright.
    """
    session.add(
        NormalizedRouteRow(
            **_provenance(device, uuid.uuid4()),
            prefix="10.2.0.0/16",
            protocol=RouteProtocol.CONNECTED,
            next_hop=null(),
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()

    session.add(
        NormalizedNeighborRow(
            **_provenance(device, uuid.uuid4()),
            protocol=NeighborProtocol.LLDP,
            local_interface="GigabitEthernet0/5",
            neighbor_name="lab-sw-03",
            neighbor_interface=null(),
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()
