"""M1-13 persistence: raw artifacts + idempotent normalized upserts (aiosqlite).

Covers the MVP exit criteria: every normalized row joins back to the raw
artifact holding the verbatim command output; re-running persistence with
identical collected data is idempotent (second pass is all updates, zero
duplicates); changed input updates rows in place without changing identity.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.engines.discovery.engine import DeviceCollectionResult
from app.engines.discovery.persistence import (
    persist_device_result,
    store_artifact,
    upsert_device,
    upsert_interfaces,
    upsert_neighbors,
    upsert_routes,
)
from app.models import (
    Base,
    Device,
    DeviceStatus,
    DiscoveryRun,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
    RawArtifact,
)
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedInterface,
    NormalizedNeighbor,
    NormalizedRoute,
    RouteProtocol,
)

COLLECTED_AT = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)
#: device_id stamped by the engine at collection time; persistence must key
#: rows on the *upserted* inventory device, not this placeholder.
ENGINE_DEVICE_ID = uuid.uuid4()
MGMT_IP = "192.0.2.10"


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


@pytest.fixture()
async def run(session: AsyncSession) -> DiscoveryRun:
    discovery_run = DiscoveryRun(seeds=[MGMT_IP], hop_limit=1)
    session.add(discovery_run)
    await session.flush()
    return discovery_run


def _facts(**overrides: Any) -> DeviceFacts:
    values: dict[str, Any] = {
        "hostname": "lab-sw-01",
        "vendor_id": "cisco_ios",
        "model": "C9300-24T",
        "os_version": "17.9.4",
        "serial": "FCW0000A0AA",
    }
    values.update(overrides)
    return DeviceFacts(**values)


def _provenance() -> dict[str, Any]:
    return {
        "device_id": ENGINE_DEVICE_ID,
        "collected_at": COLLECTED_AT,
        "source_vendor": "cisco_ios",
    }


def _interface(**overrides: Any) -> NormalizedInterface:
    values: dict[str, Any] = {
        **_provenance(),
        "name": "GigabitEthernet0/1",
        "description": "uplink",
        "admin_status": InterfaceAdminStatus.UP,
        "oper_status": InterfaceOperStatus.UP,
        "mac_address": "fa:16:3e:11:22:33",
        "ip_address": IPv4Interface("192.0.2.10/24"),
        "mtu": 1500,
        "speed_mbps": 1000,
    }
    values.update(overrides)
    return NormalizedInterface(**values)


def _route(**overrides: Any) -> NormalizedRoute:
    values: dict[str, Any] = {
        **_provenance(),
        "destination": IPv4Network("10.0.0.0/24"),
        "protocol": RouteProtocol.OSPF,
        "next_hop": IPv4Address("192.0.2.1"),
        "interface": "GigabitEthernet0/1",
        "distance": 110,
        "metric": 20,
    }
    values.update(overrides)
    return NormalizedRoute(**values)


def _neighbor(**overrides: Any) -> NormalizedNeighbor:
    values: dict[str, Any] = {
        **_provenance(),
        "protocol": NeighborProtocol.LLDP,
        "local_interface": "GigabitEthernet0/1",
        "neighbor_name": "lab-sw-02",
        "neighbor_interface": "GigabitEthernet0/24",
        "neighbor_address": IPv4Address("192.0.2.11"),
        "neighbor_capabilities": ("bridge", "router"),
    }
    values.update(overrides)
    return NormalizedNeighbor(**values)


RAW_OUTPUTS = {
    "show version": "Cisco IOS XE Software, Version 17.9.4",
    "show interfaces": "GigabitEthernet0/1 is up, line protocol is up",
    "show ip route": "O 10.0.0.0/24 [110/20] via 192.0.2.1",
    "show lldp neighbors detail": "System Name: lab-sw-02",
    "show cdp neighbors detail": "Device ID: lab-sw-03",
}


def _result(**overrides: Any) -> DeviceCollectionResult:
    values: dict[str, Any] = {
        "facts": _facts(),
        "interfaces": [_interface()],
        "routes": [_route(), _route(destination=IPv4Network("10.0.1.0/24"))],
        "neighbors": [
            _neighbor(),
            _neighbor(
                protocol=NeighborProtocol.CDP,
                neighbor_name="lab-sw-03",
                neighbor_interface=None,
            ),
        ],
        "raw_outputs": dict(RAW_OUTPUTS),
    }
    values.update(overrides)
    return DeviceCollectionResult(**values)


async def _count(session: AsyncSession, model: type[Any]) -> int:
    return (await session.execute(select(func.count()).select_from(model))).scalar_one()


# ---------------------------------------------------------------------------
# store_artifact / upsert_device
# ---------------------------------------------------------------------------


async def test_store_artifact_roundtrip(session: AsyncSession, run: DiscoveryRun) -> None:
    device = Device(hostname="lab-sw-01", mgmt_ip=MGMT_IP)
    session.add(device)
    await session.flush()

    artifact = await store_artifact(
        session,
        device_id=device.id,
        run_id=run.id,
        command="show version",
        raw_text="Cisco IOS XE Software",
        parsed=[{"version": "17.9.4"}],
    )
    reloaded = (
        await session.execute(select(RawArtifact).where(RawArtifact.id == artifact.id))
    ).scalar_one()
    assert reloaded.command == "show version"
    assert reloaded.raw_text == "Cisco IOS XE Software"
    assert reloaded.parsed == [{"version": "17.9.4"}]
    assert reloaded.device_id == device.id
    assert reloaded.run_id == run.id


async def test_upsert_device_inserts_as_reachable(session: AsyncSession) -> None:
    device = await upsert_device(session, facts=_facts(), mgmt_ip=MGMT_IP, credential_id=None)
    assert device.status is DeviceStatus.REACHABLE
    assert device.hostname == "lab-sw-01"
    assert device.mgmt_ip == MGMT_IP
    assert device.vendor_id == "cisco_ios"
    assert device.serial == "FCW0000A0AA"
    assert device.last_discovered_at is not None


async def test_upsert_device_updates_existing_row_by_mgmt_ip(session: AsyncSession) -> None:
    stale = Device(hostname="old-name", mgmt_ip=MGMT_IP, status=DeviceStatus.NEW)
    session.add(stale)
    await session.flush()

    device = await upsert_device(
        session,
        facts=_facts(os_version="17.12.1"),
        mgmt_ip=MGMT_IP,
        credential_id=None,
    )
    assert device.id == stale.id
    assert device.hostname == "lab-sw-01"
    assert device.os_version == "17.12.1"
    assert device.status is DeviceStatus.REACHABLE
    assert await _count(session, Device) == 1


# ---------------------------------------------------------------------------
# persist_device_result: artifact linkage
# ---------------------------------------------------------------------------


async def test_every_normalized_row_joins_back_to_its_artifact(
    session: AsyncSession, run: DiscoveryRun
) -> None:
    await persist_device_result(
        session, run=run, device_result=_result(), mgmt_ip=MGMT_IP, credential_id=None
    )
    await session.commit()

    artifacts = {
        artifact.id: artifact for artifact in (await session.execute(select(RawArtifact))).scalars()
    }
    assert {a.command for a in artifacts.values()} == set(RAW_OUTPUTS)
    assert all(a.raw_text == RAW_OUTPUTS[a.command] for a in artifacts.values())

    device = (await session.execute(select(Device).where(Device.mgmt_ip == MGMT_IP))).scalar_one()

    for model in (NormalizedInterfaceRow, NormalizedRouteRow, NormalizedNeighborRow):
        rows = list((await session.execute(select(model))).scalars())
        assert rows, f"no {model.__name__} rows persisted"
        for row in rows:
            assert row.device_id == device.id
            assert row.raw_artifact_id in artifacts

    interface_row = (await session.execute(select(NormalizedInterfaceRow))).scalar_one()
    assert artifacts[interface_row.raw_artifact_id].command == "show interfaces"
    for route_row in (await session.execute(select(NormalizedRouteRow))).scalars():
        assert artifacts[route_row.raw_artifact_id].command == "show ip route"
    for neighbor_row in (await session.execute(select(NormalizedNeighborRow))).scalars():
        expected = (
            "show lldp neighbors detail"
            if neighbor_row.protocol is NeighborProtocol.LLDP
            else "show cdp neighbors detail"
        )
        assert artifacts[neighbor_row.raw_artifact_id].command == expected


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


async def test_double_run_with_identical_fixtures_is_idempotent(
    session: AsyncSession, run: DiscoveryRun
) -> None:
    first = await persist_device_result(
        session, run=run, device_result=_result(), mgmt_ip=MGMT_IP, credential_id=None
    )
    await session.commit()
    assert first == {
        "interfaces": {"inserted": 1, "updated": 0},
        "routes": {"inserted": 2, "updated": 0},
        "neighbors": {"inserted": 2, "updated": 0},
    }

    second = await persist_device_result(
        session, run=run, device_result=_result(), mgmt_ip=MGMT_IP, credential_id=None
    )
    await session.commit()
    assert second == {
        "interfaces": {"inserted": 0, "updated": 1},
        "routes": {"inserted": 0, "updated": 2},
        "neighbors": {"inserted": 0, "updated": 2},
    }

    assert await _count(session, Device) == 1
    assert await _count(session, NormalizedInterfaceRow) == 1
    assert await _count(session, NormalizedRouteRow) == 2
    assert await _count(session, NormalizedNeighborRow) == 2
    # Raw artifacts are append-only evidence: one per command per pass.
    assert await _count(session, RawArtifact) == 2 * len(RAW_OUTPUTS)


async def test_changed_input_updates_in_place(session: AsyncSession, run: DiscoveryRun) -> None:
    await persist_device_result(
        session, run=run, device_result=_result(), mgmt_ip=MGMT_IP, credential_id=None
    )
    await session.commit()
    original = (await session.execute(select(NormalizedInterfaceRow))).scalar_one()
    original_id = original.id

    changed = _result(
        interfaces=[_interface(oper_status=InterfaceOperStatus.DOWN, description="flapped")]
    )
    counts = await persist_device_result(
        session, run=run, device_result=changed, mgmt_ip=MGMT_IP, credential_id=None
    )
    await session.commit()
    assert counts["interfaces"] == {"inserted": 0, "updated": 1}

    reloaded = (
        await session.execute(
            select(NormalizedInterfaceRow).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.id == original_id
    assert reloaded.oper_status is InterfaceOperStatus.DOWN
    assert reloaded.description == "flapped"


# ---------------------------------------------------------------------------
# Direct upserts: sentinel handling for optional natural-key parts
# ---------------------------------------------------------------------------


async def test_route_upsert_maps_none_key_parts_to_sentinel(session: AsyncSession) -> None:
    device = await upsert_device(session, facts=_facts(), mgmt_ip=MGMT_IP, credential_id=None)
    artifact = await store_artifact(
        session,
        device_id=device.id,
        run_id=None,
        command="show ip route",
        raw_text="C 192.0.2.0/24 is directly connected",
        parsed=None,
    )
    connected = _route(
        destination=IPv4Network("192.0.2.0/24"),
        protocol=RouteProtocol.CONNECTED,
        next_hop=None,
        interface=None,
        vrf=None,
        distance=0,
        metric=0,
    )
    first = await upsert_routes(session, device, [connected], artifact.id)
    second = await upsert_routes(session, device, [connected], artifact.id)
    assert first == {"inserted": 1, "updated": 0}
    assert second == {"inserted": 0, "updated": 1}

    row = (await session.execute(select(NormalizedRouteRow))).scalar_one()
    assert row.next_hop == ""
    assert row.interface == ""
    assert row.vrf == ""


async def test_neighbor_upsert_maps_none_interface_to_sentinel(session: AsyncSession) -> None:
    device = await upsert_device(session, facts=_facts(), mgmt_ip=MGMT_IP, credential_id=None)
    artifact = await store_artifact(
        session,
        device_id=device.id,
        run_id=None,
        command="show cdp neighbors detail",
        raw_text="Device ID: lab-sw-03",
        parsed=None,
    )
    neighbor = _neighbor(
        protocol=NeighborProtocol.CDP, neighbor_name="lab-sw-03", neighbor_interface=None
    )
    first = await upsert_neighbors(session, device, [neighbor], artifact.id)
    second = await upsert_neighbors(session, device, [neighbor], artifact.id)
    assert first == {"inserted": 1, "updated": 0}
    assert second == {"inserted": 0, "updated": 1}

    row = (await session.execute(select(NormalizedNeighborRow))).scalar_one()
    assert row.neighbor_interface == ""
    assert row.neighbor_capabilities == ["bridge", "router"]


async def test_interface_upsert_counts_and_no_duplicates(session: AsyncSession) -> None:
    device = await upsert_device(session, facts=_facts(), mgmt_ip=MGMT_IP, credential_id=None)
    artifact = await store_artifact(
        session,
        device_id=device.id,
        run_id=None,
        command="show interfaces",
        raw_text="GigabitEthernet0/1 is up",
        parsed=None,
    )
    rows = [_interface(), _interface(name="GigabitEthernet0/2", ip_address=None)]
    first = await upsert_interfaces(session, device, rows, artifact.id)
    second = await upsert_interfaces(session, device, rows, artifact.id)
    assert first == {"inserted": 2, "updated": 0}
    assert second == {"inserted": 0, "updated": 2}
    assert await _count(session, NormalizedInterfaceRow) == 2
