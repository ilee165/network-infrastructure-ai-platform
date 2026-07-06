"""Tests for the virtualization inventory API (W1-T3): RBAC floor, pagination,
empty inventory, detail-not-found, Tools-less VMs, standalone hosts, and the
power-state/is_template + connection-state/maintenance-mode separate
dimensions.

Runs entirely over in-memory aiosqlite via the shared ``tests/api/conftest.py``
fixtures — no Postgres, Docker, or network. Rows are seeded directly via the
ORM (there is no write path — see ``app/api/v1/virtualization.py`` module
docstring), mirroring ``tests/api/test_devices.py::TestDeviceSubresources``.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Device,
    NormalizedComputeClusterRow,
    NormalizedHypervisorHostRow,
    NormalizedPortGroupRow,
    NormalizedVirtualMachineRow,
)

COLLECTED_AT = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


async def _make_device(session: AsyncSession, **overrides: object) -> Device:
    defaults: dict[str, object] = {
        "hostname": "vcenter-01",
        "mgmt_ip": "192.0.2.60",
        "vendor_id": "vmware",
    }
    defaults.update(overrides)
    device = Device(**defaults)
    session.add(device)
    await session.flush()
    return device


def _vm(device_id: uuid.UUID, **overrides: object) -> NormalizedVirtualMachineRow:
    defaults: dict[str, object] = {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "vmware",
        "name": "web-vm-01",
        "moref": "vm-1042",
        "instance_uuid": "5032c8a4-1111-2222-3333-444455556666",
        "is_template": False,
        "power_state": "powered_on",
        "guest_hostname": "web-vm-01.corp.example",
        "guest_ip_addresses": ["10.0.0.21"],
        "host_name": "esxi-01.corp.example",
        "cluster_name": "cluster-a",
        "datacenter": "dc-east",
        "nics": [
            {
                "label": "Network adapter 1",
                "mac_address": "00:50:56:aa:bb:cc",
                "port_group_name": "vlan-100",
                "switch_type": "distributed",
                "connected": True,
                "ip_addresses": ["10.0.0.21"],
            }
        ],
        "description": None,
    }
    defaults.update(overrides)
    return NormalizedVirtualMachineRow(**defaults)


def _host(device_id: uuid.UUID, **overrides: object) -> NormalizedHypervisorHostRow:
    defaults: dict[str, object] = {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "vmware",
        "name": "esxi-01.corp.example",
        "moref": "host-123",
        "cluster_name": "cluster-a",
        "datacenter": "dc-east",
        "vendor": "Dell Inc.",
        "model": "PowerEdge R650",
        "hypervisor_version": "VMware ESXi 8.0.2",
        "connection_state": "connected",
        "in_maintenance_mode": False,
        "management_ip": "10.0.1.5",
        "pnics": [{"name": "vmnic0", "mac_address": "00:11:22:33:44:55", "link_speed_mbps": 10000}],
    }
    defaults.update(overrides)
    return NormalizedHypervisorHostRow(**defaults)


def _cluster(device_id: uuid.UUID, **overrides: object) -> NormalizedComputeClusterRow:
    defaults: dict[str, object] = {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "vmware",
        "name": "cluster-a",
        "moref": "domain-c8",
        "datacenter": "dc-east",
        "drs_enabled": True,
        "ha_enabled": True,
    }
    defaults.update(overrides)
    return NormalizedComputeClusterRow(**defaults)


def _port_group(device_id: uuid.UUID, **overrides: object) -> NormalizedPortGroupRow:
    defaults: dict[str, object] = {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "vmware",
        "name": "vlan-100",
        "switch_name": "dvs-01",
        "switch_type": "distributed",
        "datacenter": "dc-east",
        "host_name": "",
        "vlan_id": 100,
        "moref": "dvportgroup-123",
        "uplink_pnic_names": ["vmnic0", "vmnic1"],
    }
    defaults.update(overrides)
    return NormalizedPortGroupRow(**defaults)


class TestVirtualMachineList:
    async def test_viewer_lists_vms(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_vm(device.id))
        session.add(_vm(device.id, name="app-vm-01", moref="vm-1043"))
        await session.flush()

        response = await client.get("/api/v1/virtualization/vms", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert [item["name"] for item in body["items"]] == ["app-vm-01", "web-vm-01"]

    async def test_below_viewer_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/virtualization/vms")
        assert response.status_code == 401

    async def test_empty_inventory_renders_as_empty_list_not_error(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get("/api/v1/virtualization/vms", headers=auth_headers("viewer"))
        assert response.status_code == 200
        assert response.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}

    async def test_pagination(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        for index in range(3):
            session.add(_vm(device.id, name=f"vm-{index:02d}", moref=f"vm-200{index}"))
        await session.flush()

        response = await client.get(
            "/api/v1/virtualization/vms",
            params={"limit": 1, "offset": 1},
            headers=auth_headers("viewer"),
        )
        body = response.json()
        assert body["total"] == 3
        assert body["items"][0]["name"] == "vm-01"

    async def test_tools_less_vm_renders_empty_guest_data_not_error(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(
            _vm(
                device.id,
                name="no-tools-vm",
                moref="vm-9999",
                guest_hostname=None,
                guest_ip_addresses=[],
                nics=[],
            )
        )
        await session.flush()

        response = await client.get("/api/v1/virtualization/vms", headers=auth_headers("viewer"))
        item = response.json()["items"][0]
        assert item["guest_hostname"] is None
        assert item["guest_ip_addresses"] == []
        assert item["nics"] == []

    async def test_power_state_and_is_template_are_separate_dimensions(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        """A template can report a power state independent of is_template."""
        device = await _make_device(session)
        session.add(
            _vm(
                device.id,
                name="template-01",
                moref="vm-tmpl",
                is_template=True,
                power_state="powered_off",
            )
        )
        await session.flush()

        response = await client.get("/api/v1/virtualization/vms", headers=auth_headers("viewer"))
        item = response.json()["items"][0]
        assert item["is_template"] is True
        assert item["power_state"] == "powered_off"


class TestVirtualMachineDetail:
    async def test_get_by_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        row = _vm(device.id)
        session.add(row)
        await session.flush()

        response = await client.get(
            f"/api/v1/virtualization/vms/{row.id}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["moref"] == "vm-1042"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/virtualization/vms/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404


class TestHypervisorHostList:
    async def test_viewer_lists_hosts(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_host(device.id))
        await session.flush()

        response = await client.get("/api/v1/virtualization/hosts", headers=auth_headers("viewer"))
        assert response.status_code == 200
        assert response.json()["total"] == 1

    async def test_standalone_host_renders_as_data_not_error(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_host(device.id, name="standalone-01", moref="host-999", cluster_name=None))
        await session.flush()

        response = await client.get("/api/v1/virtualization/hosts", headers=auth_headers("viewer"))
        item = response.json()["items"][0]
        assert item["cluster_name"] is None

    async def test_connection_state_and_maintenance_mode_are_separate_dimensions(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        """A drained (maintenance) host is not the same as a failed (disconnected) host."""
        device = await _make_device(session)
        session.add(
            _host(
                device.id,
                name="drained-01",
                moref="host-777",
                connection_state="connected",
                in_maintenance_mode=True,
            )
        )
        await session.flush()

        response = await client.get("/api/v1/virtualization/hosts", headers=auth_headers("viewer"))
        item = response.json()["items"][0]
        assert item["connection_state"] == "connected"
        assert item["in_maintenance_mode"] is True

    async def test_below_viewer_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/virtualization/hosts")
        assert response.status_code == 401


class TestHypervisorHostDetail:
    async def test_get_by_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        row = _host(device.id)
        session.add(row)
        await session.flush()

        response = await client.get(
            f"/api/v1/virtualization/hosts/{row.id}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["moref"] == "host-123"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/virtualization/hosts/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404


class TestComputeClusterList:
    async def test_viewer_lists_clusters(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_cluster(device.id))
        await session.flush()

        response = await client.get(
            "/api/v1/virtualization/clusters", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["total"] == 1

    async def test_below_viewer_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/virtualization/clusters")
        assert response.status_code == 401


class TestComputeClusterDetail:
    async def test_get_by_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        row = _cluster(device.id)
        session.add(row)
        await session.flush()

        response = await client.get(
            f"/api/v1/virtualization/clusters/{row.id}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["moref"] == "domain-c8"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/virtualization/clusters/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404


class TestPortGroupList:
    async def test_viewer_lists_port_groups(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_port_group(device.id))
        await session.flush()

        response = await client.get(
            "/api/v1/virtualization/port-groups", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        # '' natural-key sentinel maps back to None on the API surface.
        assert body["items"][0]["host_name"] is None

    async def test_standard_port_group_has_no_moref(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(
            _port_group(
                device.id,
                name="VM Network",
                switch_name="vSwitch0",
                switch_type="standard",
                host_name="esxi-01.corp.example",
                moref="",
            )
        )
        await session.flush()

        response = await client.get(
            "/api/v1/virtualization/port-groups", headers=auth_headers("viewer")
        )
        item = response.json()["items"][0]
        assert item["moref"] is None
        assert item["host_name"] == "esxi-01.corp.example"

    async def test_below_viewer_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/virtualization/port-groups")
        assert response.status_code == 401


class TestPortGroupDetail:
    async def test_get_by_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        row = _port_group(device.id)
        session.add(row)
        await session.flush()

        response = await client.get(
            f"/api/v1/virtualization/port-groups/{row.id}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["name"] == "vlan-100"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/virtualization/port-groups/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404
