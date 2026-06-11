"""Tests for the devices API (M1-15): CRUD matrix, RBAC, filters, audit trail.

Runs entirely over in-memory aiosqlite via the shared ``tests/api/conftest.py``
fixtures — no Postgres, Docker, or network.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, NormalizedInterfaceRow, NormalizedNeighborRow


def _payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "hostname": "core-sw-01",
        "mgmt_ip": "192.0.2.10",
        "vendor_id": "cisco_ios",
        "model": "C9300-48T",
        "os_version": "17.9.4",
        "serial": "FOC1234X0AB",
    }
    body.update(overrides)
    return body


async def _create_device(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    **overrides: Any,
) -> dict[str, Any]:
    response = await client.post("/api/v1/devices", json=_payload(**overrides), headers=headers)
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


async def _audit_actions(session: AsyncSession) -> list[str]:
    rows = (await session.execute(select(AuditLog))).scalars().all()
    return [row.action for row in rows]


class TestDeviceCreate:
    async def test_engineer_creates_device(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        body = await _create_device(client, auth_headers("engineer"))
        assert body["hostname"] == "core-sw-01"
        assert body["mgmt_ip"] == "192.0.2.10"
        assert body["status"] == "new"
        assert body["credential_id"] is None
        assert uuid.UUID(body["id"])
        assert "device.created" in await _audit_actions(session)

    async def test_admin_passes_engineer_gate(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        await _create_device(client, auth_headers("admin"))

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        role: str,
    ) -> None:
        response = await client.post("/api/v1/devices", json=_payload(), headers=auth_headers(role))
        assert response.status_code == 403

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.post("/api/v1/devices", json=_payload())
        assert response.status_code == 401

    async def test_duplicate_mgmt_ip_is_409(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        headers = auth_headers("engineer")
        await _create_device(client, headers)
        response = await client.post(
            "/api/v1/devices", json=_payload(hostname="other"), headers=headers
        )
        assert response.status_code == 409

    async def test_unknown_credential_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.post(
            "/api/v1/devices",
            json=_payload(credential_id=str(uuid.uuid4())),
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404

    async def test_invalid_mgmt_ip_is_422(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.post(
            "/api/v1/devices",
            json=_payload(mgmt_ip="not-an-ip"),
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 422


class TestDeviceList:
    async def test_viewer_lists_devices(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        engineer = auth_headers("engineer")
        await _create_device(client, engineer)
        await _create_device(
            client, engineer, hostname="edge-fw-01", mgmt_ip="192.0.2.20", vendor_id="eos"
        )
        response = await client.get("/api/v1/devices", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert [item["hostname"] for item in body["items"]] == ["core-sw-01", "edge-fw-01"]

    async def test_filter_by_vendor_and_status(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        engineer = auth_headers("engineer")
        await _create_device(client, engineer)
        await _create_device(
            client,
            engineer,
            hostname="edge-fw-01",
            mgmt_ip="192.0.2.20",
            vendor_id="eos",
            status="reachable",
        )
        by_vendor = await client.get(
            "/api/v1/devices", params={"vendor_id": "eos"}, headers=engineer
        )
        assert [item["hostname"] for item in by_vendor.json()["items"]] == ["edge-fw-01"]
        by_status = await client.get(
            "/api/v1/devices", params={"status": "reachable"}, headers=engineer
        )
        assert by_status.json()["total"] == 1
        assert by_status.json()["items"][0]["status"] == "reachable"

    async def test_pagination(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        engineer = auth_headers("engineer")
        for index in range(3):
            await _create_device(
                client, engineer, hostname=f"sw-{index:02d}", mgmt_ip=f"192.0.2.{30 + index}"
            )
        response = await client.get(
            "/api/v1/devices", params={"limit": 1, "offset": 1}, headers=engineer
        )
        body = response.json()
        assert body["total"] == 3
        assert body["limit"] == 1
        assert body["offset"] == 1
        assert [item["hostname"] for item in body["items"]] == ["sw-01"]

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/devices")
        assert response.status_code == 401


class TestDeviceDetail:
    async def test_get_by_id(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        created = await _create_device(client, auth_headers("engineer"))
        response = await client.get(
            f"/api/v1/devices/{created['id']}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["hostname"] == "core-sw-01"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/devices/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404


class TestDeviceSubresources:
    async def test_interfaces_and_neighbors(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        created = await _create_device(client, auth_headers("engineer"))
        device_id = uuid.UUID(created["id"])
        collected_at = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
        session.add(
            NormalizedInterfaceRow(
                device_id=device_id,
                raw_artifact_id=uuid.uuid4(),
                collected_at=collected_at,
                source_vendor="cisco_ios",
                name="GigabitEthernet0/1",
                admin_status="up",
                oper_status="up",
                ip_address="192.0.2.10",
                mtu=1500,
            )
        )
        session.add(
            NormalizedNeighborRow(
                device_id=device_id,
                raw_artifact_id=uuid.uuid4(),
                collected_at=collected_at,
                source_vendor="cisco_ios",
                protocol="lldp",
                local_interface="GigabitEthernet0/1",
                neighbor_name="dist-sw-01",
                neighbor_interface="",
                neighbor_capabilities=["bridge"],
            )
        )
        await session.flush()

        viewer = auth_headers("viewer")
        interfaces = await client.get(f"/api/v1/devices/{device_id}/interfaces", headers=viewer)
        assert interfaces.status_code == 200
        assert [item["name"] for item in interfaces.json()] == ["GigabitEthernet0/1"]

        neighbors = await client.get(f"/api/v1/devices/{device_id}/neighbors", headers=viewer)
        assert neighbors.status_code == 200
        (neighbor,) = neighbors.json()
        assert neighbor["neighbor_name"] == "dist-sw-01"
        # '' natural-key sentinel maps back to None on the API surface.
        assert neighbor["neighbor_interface"] is None

    async def test_unknown_device_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        viewer = auth_headers("viewer")
        for sub in ("interfaces", "neighbors"):
            response = await client.get(f"/api/v1/devices/{uuid.uuid4()}/{sub}", headers=viewer)
            assert response.status_code == 404


class TestDeviceUpdate:
    async def test_engineer_patches_device(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        created = await _create_device(client, auth_headers("engineer"))
        response = await client.patch(
            f"/api/v1/devices/{created['id']}",
            json={"hostname": "core-sw-01-renamed", "status": "reachable"},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["hostname"] == "core-sw-01-renamed"
        assert body["status"] == "reachable"
        assert body["mgmt_ip"] == "192.0.2.10"
        assert "device.updated" in await _audit_actions(session)

    async def test_patch_rbac_denial(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        created = await _create_device(client, auth_headers("engineer"))
        response = await client.patch(
            f"/api/v1/devices/{created['id']}",
            json={"hostname": "nope"},
            headers=auth_headers("operator"),
        )
        assert response.status_code == 403

    async def test_patch_unknown_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.patch(
            f"/api/v1/devices/{uuid.uuid4()}",
            json={"hostname": "ghost"},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404

    async def test_patch_mgmt_ip_conflict_is_409(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        engineer = auth_headers("engineer")
        await _create_device(client, engineer)
        other = await _create_device(client, engineer, hostname="b", mgmt_ip="192.0.2.99")
        response = await client.patch(
            f"/api/v1/devices/{other['id']}",
            json={"mgmt_ip": "192.0.2.10"},
            headers=engineer,
        )
        assert response.status_code == 409


class TestDeviceDelete:
    async def test_engineer_deletes_device(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        created = await _create_device(client, auth_headers("engineer"))
        response = await client.delete(
            f"/api/v1/devices/{created['id']}", headers=auth_headers("engineer")
        )
        assert response.status_code == 204
        gone = await client.get(f"/api/v1/devices/{created['id']}", headers=auth_headers("viewer"))
        assert gone.status_code == 404
        assert "device.deleted" in await _audit_actions(session)

    async def test_delete_rbac_denial(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        created = await _create_device(client, auth_headers("engineer"))
        response = await client.delete(
            f"/api/v1/devices/{created['id']}", headers=auth_headers("viewer")
        )
        assert response.status_code == 403

    async def test_delete_unknown_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.delete(
            f"/api/v1/devices/{uuid.uuid4()}", headers=auth_headers("engineer")
        )
        assert response.status_code == 404


class TestDeviceAuditTrail:
    async def test_full_crud_audit_rows(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        engineer = auth_headers("engineer")
        created = await _create_device(client, engineer)
        await client.patch(
            f"/api/v1/devices/{created['id']}", json={"hostname": "renamed"}, headers=engineer
        )
        await client.delete(f"/api/v1/devices/{created['id']}", headers=engineer)

        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.target_id == created["id"])))
            .scalars()
            .all()
        )
        actions = [row.action for row in rows]
        assert actions == ["device.created", "device.updated", "device.deleted"]
        assert all(row.actor == "user:engineer_user" for row in rows)
        assert all(row.target_type == "device" for row in rows)
