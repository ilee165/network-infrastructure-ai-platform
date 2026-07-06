"""Tests for the ADC inventory API (W1-T3): RBAC floor, pagination, empty
inventory, detail-not-found, nested members, availability/admin-state kept
separate.

Runs entirely over in-memory aiosqlite via the shared ``tests/api/conftest.py``
fixtures — no Postgres, Docker, or network. Rows are seeded directly via the
ORM (there is no write path — see ``app/api/v1/adc.py`` module docstring),
mirroring ``tests/api/test_devices.py::TestDeviceSubresources``.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Device, NormalizedPoolRow, NormalizedVirtualServerRow

COLLECTED_AT = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


async def _make_device(session: AsyncSession, **overrides: object) -> Device:
    defaults: dict[str, object] = {
        "hostname": "f5-lb-01",
        "mgmt_ip": "192.0.2.50",
        "vendor_id": "f5_bigip",
    }
    defaults.update(overrides)
    device = Device(**defaults)
    session.add(device)
    await session.flush()
    return device


def _virtual_server(device_id: uuid.UUID, **overrides: object) -> NormalizedVirtualServerRow:
    defaults: dict[str, object] = {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "f5_bigip",
        "name": "/Common/vs_web",
        "vip_address": "203.0.113.10",
        "port": 443,
        "protocol": "tcp",
        "vrf": None,
        "enabled": True,
        "availability": "available",
        "pool_name": "/Common/pool_web",
        "description": None,
    }
    defaults.update(overrides)
    return NormalizedVirtualServerRow(**defaults)


def _pool(device_id: uuid.UUID, **overrides: object) -> NormalizedPoolRow:
    defaults: dict[str, object] = {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "f5_bigip",
        "name": "/Common/pool_web",
        "monitors": ["/Common/http"],
        "availability": "available",
        "members": [
            {
                "name": "/Common/web01:80",
                "address": "10.0.0.11",
                "fqdn": None,
                "port": 80,
                "vrf": None,
                "admin_state": "enabled",
                "availability": "available",
            }
        ],
        "description": None,
    }
    defaults.update(overrides)
    return NormalizedPoolRow(**defaults)


class TestVirtualServerList:
    async def test_viewer_lists_virtual_servers(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_virtual_server(device.id))
        session.add(_virtual_server(device.id, name="/Common/vs_api", port=8443))
        await session.flush()

        response = await client.get("/api/v1/adc/virtual-servers", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert [item["name"] for item in body["items"]] == ["/Common/vs_api", "/Common/vs_web"]

    async def test_below_viewer_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/adc/virtual-servers")
        assert response.status_code == 401

    async def test_inactive_authenticated_user_is_rejected(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        """An authenticated-but-inactive user is rejected — a valid token is not
        sufficient (viewer is the lowest rank, so this is the meaningful
        authenticated-failure case for a viewer floor)."""
        response = await client.get("/api/v1/adc/virtual-servers", headers=auth_headers("inactive"))
        assert response.status_code == 401

    async def test_filters_by_device_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device_a = await _make_device(session)
        device_b = await _make_device(session, hostname="f5-lb-02", mgmt_ip="192.0.2.51")
        session.add(_virtual_server(device_a.id, name="/Common/vs_a"))
        session.add(_virtual_server(device_b.id, name="/Common/vs_b"))
        await session.flush()

        response = await client.get(
            "/api/v1/adc/virtual-servers",
            params={"device_id": str(device_a.id)},
            headers=auth_headers("viewer"),
        )
        body = response.json()
        assert body["total"] == 1
        assert [item["name"] for item in body["items"]] == ["/Common/vs_a"]

    async def test_filters_by_availability(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_virtual_server(device.id, name="/Common/vs_up", availability="available"))
        session.add(_virtual_server(device.id, name="/Common/vs_down", availability="offline"))
        await session.flush()

        response = await client.get(
            "/api/v1/adc/virtual-servers",
            params={"availability": "offline"},
            headers=auth_headers("viewer"),
        )
        body = response.json()
        assert body["total"] == 1
        assert [item["name"] for item in body["items"]] == ["/Common/vs_down"]

    async def test_rejects_out_of_range_limit(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        # Both bounds of the ge=1/le=500 limit validation, plus the ge=0 offset.
        for params in ({"limit": 0}, {"limit": 501}, {"offset": -1}):
            response = await client.get(
                "/api/v1/adc/virtual-servers",
                params=params,
                headers=auth_headers("viewer"),
            )
            assert response.status_code == 422, f"expected 422 for {params}"

    async def test_empty_inventory_renders_as_empty_list_not_error(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get("/api/v1/adc/virtual-servers", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body == {"items": [], "total": 0, "limit": 50, "offset": 0}

    async def test_pagination(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        for index in range(3):
            session.add(_virtual_server(device.id, name=f"/Common/vs_{index:02d}"))
        await session.flush()

        response = await client.get(
            "/api/v1/adc/virtual-servers",
            params={"limit": 1, "offset": 1},
            headers=auth_headers("viewer"),
        )
        body = response.json()
        assert body["total"] == 3
        assert body["limit"] == 1
        assert body["offset"] == 1
        assert body["items"][0]["name"] == "/Common/vs_01"

    async def test_availability_and_enabled_are_separate_dimensions(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        """A disabled VS can still report an availability state — not collapsed."""
        device = await _make_device(session)
        session.add(_virtual_server(device.id, enabled=False, availability="offline"))
        await session.flush()

        response = await client.get("/api/v1/adc/virtual-servers", headers=auth_headers("viewer"))
        item = response.json()["items"][0]
        assert item["enabled"] is False
        assert item["availability"] == "offline"


class TestVirtualServerDetail:
    async def test_get_by_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        row = _virtual_server(device.id)
        session.add(row)
        await session.flush()

        response = await client.get(
            f"/api/v1/adc/virtual-servers/{row.id}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        assert response.json()["name"] == "/Common/vs_web"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/adc/virtual-servers/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404


class TestPoolList:
    async def test_viewer_lists_pools_with_nested_members(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_pool(device.id))
        await session.flush()

        response = await client.get("/api/v1/adc/pools", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        (member,) = body["items"][0]["members"]
        assert member["name"] == "/Common/web01:80"
        assert member["admin_state"] == "enabled"
        assert member["availability"] == "available"

    async def test_empty_pool_renders_as_data_not_error(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        session.add(_pool(device.id, name="/Common/pool_empty", members=[]))
        await session.flush()

        response = await client.get("/api/v1/adc/pools", headers=auth_headers("viewer"))
        assert response.status_code == 200
        assert response.json()["items"][0]["members"] == []

    async def test_below_viewer_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/adc/pools")
        assert response.status_code == 401

    async def test_filters_by_device_id_and_availability(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device_a = await _make_device(session)
        device_b = await _make_device(session, hostname="f5-lb-02", mgmt_ip="192.0.2.51")
        session.add(_pool(device_a.id, name="/Common/pool_a", availability="available"))
        session.add(_pool(device_a.id, name="/Common/pool_a_down", availability="offline"))
        session.add(_pool(device_b.id, name="/Common/pool_b"))
        await session.flush()

        by_device = await client.get(
            "/api/v1/adc/pools",
            params={"device_id": str(device_a.id)},
            headers=auth_headers("viewer"),
        )
        assert by_device.json()["total"] == 2

        by_avail = await client.get(
            "/api/v1/adc/pools",
            params={"device_id": str(device_a.id), "availability": "offline"},
            headers=auth_headers("viewer"),
        )
        body = by_avail.json()
        assert [item["name"] for item in body["items"]] == ["/Common/pool_a_down"]


class TestPoolDetail:
    async def test_get_by_id(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _make_device(session)
        row = _pool(device.id)
        session.add(row)
        await session.flush()

        response = await client.get(f"/api/v1/adc/pools/{row.id}", headers=auth_headers("viewer"))
        assert response.status_code == 200
        assert response.json()["name"] == "/Common/pool_web"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/adc/pools/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404
