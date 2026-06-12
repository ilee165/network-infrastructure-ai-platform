"""Tests for the discovery API (M1-16): start run, list, status, results.

Runs entirely over in-memory aiosqlite via the shared ``tests/api/conftest.py``
fixtures — no Postgres, Redis, Docker, or network. ``celery_app.send_task`` is
monkeypatched so enqueueing is asserted (task name, queue, args) without a
broker.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import discovery as discovery_api
from app.models import (
    AuditLog,
    Device,
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

COLLECTED_AT = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "seeds": ["192.0.2.10"],
        "hop_limit": 1,
        "allowlist": ["192.0.2.0/24"],
        "credential_names": ["lab-ssh"],
    }
    body.update(overrides)
    return body


@pytest.fixture()
def sent_tasks(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture ``celery_app.send_task`` calls instead of touching a broker."""
    calls: list[dict[str, Any]] = []

    def _fake_send_task(
        name: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        **options: Any,
    ) -> Any:
        calls.append({"name": name, "args": args, "kwargs": kwargs, "queue": options.get("queue")})

        class _Result:
            id = "unit-test-task-id"

        return _Result()

    monkeypatch.setattr(discovery_api.celery_app, "send_task", _fake_send_task)
    return calls


async def _run_rows(session: AsyncSession) -> list[DiscoveryRun]:
    return list((await session.execute(select(DiscoveryRun))).scalars().all())


async def _audit_actions(session: AsyncSession) -> list[str]:
    rows = (await session.execute(select(AuditLog))).scalars().all()
    return [row.action for row in rows]


def _make_run(*, created_at: datetime, seeds: list[str] | None = None) -> DiscoveryRun:
    return DiscoveryRun(
        seeds=seeds or ["192.0.2.10"],
        hop_limit=1,
        allowlist=["192.0.2.0/24"],
        credential_names=["lab-ssh"],
        created_at=created_at,
        updated_at=created_at,
    )


def _make_device(hostname: str, mgmt_ip: str) -> Device:
    return Device(hostname=hostname, mgmt_ip=mgmt_ip, vendor_id="cisco_ios")


def _make_artifact(device_id: uuid.UUID, run_id: uuid.UUID | None) -> RawArtifact:
    return RawArtifact(
        device_id=device_id,
        run_id=run_id,
        command="show version",
        raw_text="Cisco IOS Software",
    )


def _provenance(device_id: uuid.UUID) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "raw_artifact_id": uuid.uuid4(),
        "collected_at": COLLECTED_AT,
        "source_vendor": "cisco_ios",
    }


def _make_interface(device_id: uuid.UUID, name: str) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        name=name,
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        **_provenance(device_id),
    )


def _make_route(device_id: uuid.UUID, prefix: str) -> NormalizedRouteRow:
    return NormalizedRouteRow(
        prefix=prefix,
        protocol=RouteProtocol.CONNECTED,
        **_provenance(device_id),
    )


def _make_neighbor(device_id: uuid.UUID, local_interface: str) -> NormalizedNeighborRow:
    return NormalizedNeighborRow(
        protocol=NeighborProtocol.LLDP,
        local_interface=local_interface,
        neighbor_name="peer-sw-01",
        **_provenance(device_id),
    )


class TestStartRun:
    async def test_engineer_starts_run(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs", json=_body(), headers=auth_headers("engineer")
        )
        assert response.status_code == 202, response.text
        body = response.json()
        assert body["status"] == "pending"
        assert body["seeds"] == ["192.0.2.10"]
        assert body["hop_limit"] == 1
        assert body["allowlist"] == ["192.0.2.0/24"]
        assert body["credential_names"] == ["lab-ssh"]
        assert body["error"] is None
        assert body["started_at"] is None
        assert body["finished_at"] is None
        run_id = uuid.UUID(body["id"])

        runs = await _run_rows(session)
        assert len(runs) == 1
        assert runs[0].id == run_id
        assert runs[0].status == DiscoveryRunStatus.PENDING

    async def test_enqueues_discovery_run_task(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs", json=_body(), headers=auth_headers("engineer")
        )
        assert response.status_code == 202
        run_id = response.json()["id"]
        assert sent_tasks == [
            {
                "name": "discovery.run",
                "args": [run_id],
                "kwargs": None,
                "queue": "discovery",
            }
        ]

    async def test_audits_run_started(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs", json=_body(), headers=auth_headers("engineer")
        )
        assert response.status_code == 202
        entries = (await session.execute(select(AuditLog))).scalars().all()
        assert [e.action for e in entries] == ["discovery.run_started"]
        entry = entries[0]
        assert entry.actor == "user:engineer_user"
        assert entry.target_type == "discovery_run"
        assert entry.target_id == response.json()["id"]
        assert entry.detail is not None
        assert entry.detail["seeds"] == ["192.0.2.10"]
        assert entry.detail["hop_limit"] == 1

    async def test_admin_passes_engineer_gate(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs", json=_body(), headers=auth_headers("admin")
        )
        assert response.status_code == 202

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        sent_tasks: list[dict[str, Any]],
        role: str,
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs", json=_body(), headers=auth_headers(role)
        )
        assert response.status_code == 403
        assert await _run_rows(session) == []
        assert sent_tasks == []

    async def test_unauthenticated_is_401(
        self,
        client: httpx.AsyncClient,
        session: AsyncSession,
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        response = await client.post("/api/v1/discovery/runs", json=_body())
        assert response.status_code == 401
        assert await _run_rows(session) == []
        assert sent_tasks == []

    @pytest.mark.parametrize(
        "overrides",
        [
            {"seeds": ["not-an-ip"]},
            {"seeds": ["198.51.100.1"]},  # outside the allowlist
            {"seeds": []},
            {"allowlist": ["not-a-cidr"]},
            {"allowlist": []},
            {"hop_limit": -1},
            {"unexpected": "field"},
        ],
    )
    async def test_invalid_plan_is_422(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        sent_tasks: list[dict[str, Any]],
        overrides: dict[str, Any],
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs",
            json=_body(**overrides),
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 422, response.text
        assert await _run_rows(session) == []
        assert sent_tasks == []
        assert await _audit_actions(session) == []

    async def test_seeds_and_allowlist_are_normalized(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        response = await client.post(
            "/api/v1/discovery/runs",
            json=_body(seeds=["2001:DB8::1"], allowlist=["2001:DB8::/32"]),
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 202
        body = response.json()
        assert body["seeds"] == ["2001:db8::1"]
        assert body["allowlist"] == ["2001:db8::/32"]
        runs = await _run_rows(session)
        assert runs[0].seeds == ["2001:db8::1"]
        assert runs[0].allowlist == ["2001:db8::/32"]


class TestListRuns:
    async def test_newest_first_and_pagination(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        base = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
        older = _make_run(created_at=base)
        newer = _make_run(created_at=base + timedelta(minutes=5))
        session.add_all([older, newer])
        await session.commit()

        response = await client.get("/api/v1/discovery/runs", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert [item["id"] for item in body["items"]] == [str(newer.id), str(older.id)]

        page = await client.get(
            "/api/v1/discovery/runs",
            params={"limit": 1, "offset": 1},
            headers=auth_headers("viewer"),
        )
        page_body = page.json()
        assert page_body["total"] == 2
        assert page_body["limit"] == 1
        assert page_body["offset"] == 1
        assert [item["id"] for item in page_body["items"]] == [str(older.id)]

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/api/v1/discovery/runs")
        assert response.status_code == 401


class TestGetRun:
    async def test_returns_run_status(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        run = _make_run(created_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC))
        run.status = DiscoveryRunStatus.PARTIAL
        run.stats = {"devices_succeeded": 2, "devices_failed": 1}
        run.error = None
        run.started_at = datetime(2026, 6, 1, 12, 1, tzinfo=UTC)
        run.finished_at = datetime(2026, 6, 1, 12, 5, tzinfo=UTC)
        session.add(run)
        await session.commit()

        response = await client.get(
            f"/api/v1/discovery/runs/{run.id}", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        body = response.json()
        assert body["id"] == str(run.id)
        assert body["status"] == "partial"
        assert body["stats"] == {"devices_succeeded": 2, "devices_failed": 1}
        assert body["error"] is None
        assert body["started_at"] is not None
        assert body["finished_at"] is not None

    async def test_unknown_run_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/discovery/runs/{uuid.uuid4()}", headers=auth_headers("viewer")
        )
        assert response.status_code == 404


class TestRunResults:
    async def test_aggregates_only_devices_touched_by_the_run(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        base = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
        run = _make_run(created_at=base)
        other_run = _make_run(created_at=base + timedelta(minutes=1))
        device_a = _make_device("core-sw-01", "192.0.2.10")
        device_b = _make_device("edge-rt-01", "192.0.2.11")
        device_c = _make_device("other-sw-01", "192.0.2.12")
        session.add_all([run, other_run, device_a, device_b, device_c])
        await session.flush()

        session.add_all(
            [
                # Device A touched twice by the run — must still count once.
                _make_artifact(device_a.id, run.id),
                _make_artifact(device_a.id, run.id),
                _make_artifact(device_b.id, run.id),
                # Device C belongs to a different run.
                _make_artifact(device_c.id, other_run.id),
            ]
        )
        session.add_all(
            [
                _make_interface(device_a.id, "GigabitEthernet0/0"),
                _make_interface(device_a.id, "GigabitEthernet0/1"),
                _make_interface(device_b.id, "Ethernet1"),
                _make_interface(device_c.id, "Ethernet2"),
                _make_route(device_a.id, "192.0.2.0/24"),
                _make_route(device_c.id, "198.51.100.0/24"),
                _make_neighbor(device_a.id, "GigabitEthernet0/0"),
                _make_neighbor(device_c.id, "Ethernet2"),
            ]
        )
        await session.commit()

        response = await client.get(
            f"/api/v1/discovery/runs/{run.id}/results", headers=auth_headers("viewer")
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["run_id"] == str(run.id)
        assert body["device_count"] == 2
        assert body["interface_count"] == 3
        assert body["route_count"] == 1
        assert body["neighbor_count"] == 1
        assert [d["hostname"] for d in body["devices"]] == ["core-sw-01", "edge-rt-01"]
        summary = body["devices"][0]
        assert summary["id"] == str(device_a.id)
        assert summary["mgmt_ip"] == "192.0.2.10"
        assert summary["vendor_id"] == "cisco_ios"
        assert summary["status"] == "new"

    async def test_run_without_artifacts_returns_zeros(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        run = _make_run(created_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC))
        session.add(run)
        await session.commit()

        response = await client.get(
            f"/api/v1/discovery/runs/{run.id}/results", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        body = response.json()
        assert body["device_count"] == 0
        assert body["interface_count"] == 0
        assert body["route_count"] == 0
        assert body["neighbor_count"] == 0
        assert body["devices"] == []

    async def test_unknown_run_is_404(
        self, client: httpx.AsyncClient, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        response = await client.get(
            f"/api/v1/discovery/runs/{uuid.uuid4()}/results", headers=auth_headers("viewer")
        )
        assert response.status_code == 404

    async def test_unauthenticated_is_401(
        self, client: httpx.AsyncClient, session: AsyncSession
    ) -> None:
        run = _make_run(created_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC))
        session.add(run)
        await session.commit()
        response = await client.get(f"/api/v1/discovery/runs/{run.id}/results")
        assert response.status_code == 401
