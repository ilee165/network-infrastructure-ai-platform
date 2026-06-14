"""Seed an example small-business network scenario for live platform testing.

Idempotent demo fixture (NOT production data): a four-device HQ network for
"Northwind Traders" — a Palo Alto edge firewall, an Arista L3 core switch, and
two Cisco IOS access switches — with normalized interfaces, routes, and
LLDP/CDP neighbors so the inventory API, topology, and the Troubleshooting
Agent (``get_device_routes``) have realistic grounded data to read.

A fault is planted on purpose so the agent has something to diagnose: the guest
WiFi VLAN ``10.0.99.0/24`` is *connected* on the core switch but the edge
firewall has **no route back to it** (it was never advertised into OSPF), so
return traffic to guest clients blackholes at the firewall.

Run inside the api container (it has the app + DB config):

    docker compose -f deploy/docker/docker-compose.yml cp \\
        backend/scripts/seed_smb_scenario.py api:/tmp/seed_smb_scenario.py
    docker compose -f deploy/docker/docker-compose.yml exec -T api \\
        python /tmp/seed_smb_scenario.py

Re-running is safe: it upserts devices by ``mgmt_ip`` and replaces their
normalized rows. Device ids are deterministic (uuid5 of the mgmt IP) and are
printed at the end for use as the ``device_id`` argument to the agent.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, select

from app.core.config import get_settings
from app.db import create_engine, create_sessionmaker
from app.models import (
    Device,
    DeviceStatus,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceDuplex,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)

# Stable namespace so uuid5(device mgmt_ip) is reproducible across runs.
_NS = uuid.UUID("a1b2c3d4-0000-4000-8000-000000000001")

UP_A = InterfaceAdminStatus.UP
UP_O = InterfaceOperStatus.UP
DOWN_A = InterfaceAdminStatus.DOWN
DOWN_O = InterfaceOperStatus.DOWN
FULL = InterfaceDuplex.FULL


def _dev_id(mgmt_ip: str) -> uuid.UUID:
    return uuid.uuid5(_NS, mgmt_ip)


# --- Scenario: Northwind Traders HQ -----------------------------------------
# site "hq"; star topology  edge-fw-01 — core-sw-01 — {access-sw-01, access-sw-02}
#   VLAN 1  mgmt   10.0.0.0/24
#   VLAN 10 staff  10.0.10.0/24
#   VLAN 20 voice  10.0.20.0/24
#   VLAN 99 guest  10.0.99.0/24   <-- firewall is MISSING the return route (planted fault)

DEVICES = [
    {
        "mgmt_ip": "10.0.0.1",
        "hostname": "edge-fw-01",
        "vendor_id": "paloalto_panos",
        "model": "PA-440",
        "os_version": "11.1.2",
        "serial": "0123A4567890",
        "interfaces": [
            ("ethernet1/1", "ISP uplink (Northwind Fiber)", UP_A, UP_O, "203.0.113.2", 1000, None),
            ("ethernet1/2", "LAN trunk to core-sw-01", UP_A, UP_O, "10.0.0.1", 1000, 1),
        ],
        "routes": [
            ("0.0.0.0/0", RouteProtocol.STATIC, "203.0.113.1", "ethernet1/1", 10, None),
            ("203.0.113.0/30", RouteProtocol.CONNECTED, "", "ethernet1/1", 0, 0),
            ("10.0.0.0/24", RouteProtocol.CONNECTED, "", "ethernet1/2", 0, 0),
            ("10.0.10.0/24", RouteProtocol.OSPF, "10.0.0.2", "ethernet1/2", 110, 20),
            ("10.0.20.0/24", RouteProtocol.OSPF, "10.0.0.2", "ethernet1/2", 110, 20),
            # NOTE: 10.0.99.0/24 (guest) is intentionally ABSENT — the planted fault.
        ],
        "neighbors": [
            (
                NeighborProtocol.LLDP,
                "ethernet1/2",
                "core-sw-01",
                "Ethernet1",
                "Arista EOS",
                "10.0.0.2",
            ),
        ],
    },
    {
        "mgmt_ip": "10.0.0.2",
        "hostname": "core-sw-01",
        "vendor_id": "arista_eos",
        "model": "DCS-7050SX3-48YC8",
        "os_version": "4.31.2F",
        "serial": "JPE19000001",
        "interfaces": [
            ("Ethernet1", "uplink to edge-fw-01", UP_A, UP_O, None, 10000, None),
            ("Ethernet2", "to access-sw-01", UP_A, UP_O, None, 1000, None),
            ("Ethernet3", "to access-sw-02", UP_A, UP_O, None, 1000, None),
            ("Vlan1", "management", UP_A, UP_O, "10.0.0.2", None, 1),
            ("Vlan10", "staff gateway", UP_A, UP_O, "10.0.10.1", None, 10),
            ("Vlan20", "voice gateway", UP_A, UP_O, "10.0.20.1", None, 20),
            ("Vlan99", "guest wifi gateway", UP_A, UP_O, "10.0.99.1", None, 99),
        ],
        "routes": [
            ("0.0.0.0/0", RouteProtocol.STATIC, "10.0.0.1", "Vlan1", 1, None),
            ("10.0.0.0/24", RouteProtocol.CONNECTED, "", "Vlan1", 0, 0),
            ("10.0.10.0/24", RouteProtocol.CONNECTED, "", "Vlan10", 0, 0),
            ("10.0.20.0/24", RouteProtocol.CONNECTED, "", "Vlan20", 0, 0),
            ("10.0.99.0/24", RouteProtocol.CONNECTED, "", "Vlan99", 0, 0),
        ],
        "neighbors": [
            (NeighborProtocol.LLDP, "Ethernet1", "edge-fw-01", "ethernet1/2", "PAN-OS", "10.0.0.1"),
            (
                NeighborProtocol.CDP,
                "Ethernet2",
                "access-sw-01",
                "GigabitEthernet1/0/1",
                "cisco IOS",
                "10.0.10.2",
            ),
            (
                NeighborProtocol.CDP,
                "Ethernet3",
                "access-sw-02",
                "GigabitEthernet1/0/1",
                "cisco IOS",
                "10.0.20.2",
            ),
        ],
    },
    {
        "mgmt_ip": "10.0.10.2",
        "hostname": "access-sw-01",
        "vendor_id": "cisco_ios",
        "model": "C9200L-24P-4G",
        "os_version": "17.09.04a",
        "serial": "FCW2345L0AB",
        "interfaces": [
            ("GigabitEthernet1/0/1", "uplink to core-sw-01", UP_A, UP_O, None, 1000, 10),
            ("GigabitEthernet1/0/2", "staff workstation", UP_A, UP_O, None, 1000, 10),
            ("GigabitEthernet1/0/24", "spare", DOWN_A, DOWN_O, None, 1000, 10),
            ("Vlan10", "management", UP_A, UP_O, "10.0.10.2", None, 10),
        ],
        "routes": [
            ("0.0.0.0/0", RouteProtocol.STATIC, "10.0.10.1", "Vlan10", 1, None),
            ("10.0.10.0/24", RouteProtocol.CONNECTED, "", "Vlan10", 0, 0),
        ],
        "neighbors": [
            (
                NeighborProtocol.CDP,
                "GigabitEthernet1/0/1",
                "core-sw-01",
                "Ethernet2",
                "Arista EOS",
                "10.0.0.2",
            ),
        ],
    },
    {
        "mgmt_ip": "10.0.20.2",
        "hostname": "access-sw-02",
        "vendor_id": "cisco_ios",
        "model": "C9200L-24P-4G",
        "os_version": "17.09.04a",
        "serial": "FCW2345L0CD",
        "interfaces": [
            ("GigabitEthernet1/0/1", "uplink to core-sw-01", UP_A, UP_O, None, 1000, 20),
            ("GigabitEthernet1/0/5", "conference room phone", UP_A, UP_O, None, 1000, 20),
            ("Vlan20", "management", UP_A, UP_O, "10.0.20.2", None, 20),
        ],
        "routes": [
            ("0.0.0.0/0", RouteProtocol.STATIC, "10.0.20.1", "Vlan20", 1, None),
            ("10.0.20.0/24", RouteProtocol.CONNECTED, "", "Vlan20", 0, 0),
        ],
        "neighbors": [
            (
                NeighborProtocol.CDP,
                "GigabitEthernet1/0/1",
                "core-sw-01",
                "Ethernet3",
                "Arista EOS",
                "10.0.0.2",
            ),
        ],
    },
]


async def seed() -> None:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    now = datetime.now(UTC)

    summary: list[tuple[str, str, int, int, int]] = []
    async with sessionmaker() as session:
        for spec in DEVICES:
            did = _dev_id(spec["mgmt_ip"])

            # Upsert the device by its deterministic id / unique mgmt_ip.
            device = await session.get(Device, did)
            if device is None:
                device = Device(id=did, mgmt_ip=spec["mgmt_ip"])
                session.add(device)
            device.hostname = spec["hostname"]
            device.vendor_id = spec["vendor_id"]
            device.model = spec["model"]
            device.os_version = spec["os_version"]
            device.serial = spec["serial"]
            device.status = DeviceStatus.REACHABLE
            device.site = "hq"
            device.last_discovered_at = now

            # Replace this device's normalized rows so re-runs are idempotent.
            for model in (NormalizedInterfaceRow, NormalizedRouteRow, NormalizedNeighborRow):
                await session.execute(delete(model).where(model.device_id == did))

            vendor = spec["vendor_id"]
            for name, desc, admin, oper, ip, speed, vlan in spec["interfaces"]:
                session.add(
                    NormalizedInterfaceRow(
                        device_id=did,
                        raw_artifact_id=uuid.uuid4(),
                        collected_at=now,
                        source_vendor=vendor,
                        name=name,
                        description=desc,
                        admin_status=admin,
                        oper_status=oper,
                        ip_address=ip,
                        speed_mbps=speed,
                        duplex=FULL if oper is UP_O else None,
                        vlan_id=vlan,
                        input_errors=0,
                        output_errors=0,
                    )
                )
            for prefix, proto, next_hop, iface, distance, metric in spec["routes"]:
                session.add(
                    NormalizedRouteRow(
                        device_id=did,
                        raw_artifact_id=uuid.uuid4(),
                        collected_at=now,
                        source_vendor=vendor,
                        prefix=prefix,
                        protocol=proto,
                        next_hop=next_hop,
                        interface=iface,
                        vrf="",
                        distance=distance,
                        metric=metric,
                    )
                )
            for proto, local_if, nbr_name, nbr_if, platform, addr in spec["neighbors"]:
                session.add(
                    NormalizedNeighborRow(
                        device_id=did,
                        raw_artifact_id=uuid.uuid4(),
                        collected_at=now,
                        source_vendor=vendor,
                        protocol=proto,
                        local_interface=local_if,
                        neighbor_name=nbr_name,
                        neighbor_interface=nbr_if,
                        neighbor_platform=platform,
                        neighbor_address=addr,
                        neighbor_capabilities=["router", "switch"],
                    )
                )

            summary.append(
                (
                    spec["hostname"],
                    str(did),
                    len(spec["interfaces"]),
                    len(spec["routes"]),
                    len(spec["neighbors"]),
                )
            )

        await session.commit()

        total_devices = len((await session.execute(select(Device.id))).scalars().all())

    await engine.dispose()

    print("Seeded small-business scenario 'Northwind Traders HQ' (site=hq):")
    for hostname, did, n_if, n_rt, n_nb in summary:
        print(f"  {hostname:<14} {did}  interfaces={n_if} routes={n_rt} neighbors={n_nb}")
    print(f"Devices now in inventory: {total_devices}")
    print(
        "\nPlanted fault: edge-fw-01 has NO route to the guest VLAN 10.0.99.0/24 "
        "(connected on core-sw-01, never advertised into OSPF)."
    )
    print(
        "Try the Troubleshooting Agent: 'Guest WiFi users on 10.0.99.0/24 cannot reach "
        "the internet — check the routing on edge-fw-01 (device_id "
        f"{_dev_id('10.0.0.1')}).'"
    )


if __name__ == "__main__":
    asyncio.run(seed())
