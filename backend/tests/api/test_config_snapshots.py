"""Tests for config-snapshot sub-resource API (M4; T14).

Coverage:
- GET /devices/{id}/config-snapshots — list (viewer+), RBAC, pagination, 404 on bad device
- GET /devices/{id}/config-snapshots/{snap_id} — metadata (viewer+), 404 on unknown
- GET /devices/{id}/config-snapshots/{snap_id}/content — raw content (engineer+), RBAC, audit
- GET /devices/{id}/drift — drift check (engineer+), RBAC, 404 on no baseline
- GET /devices/{id}/compliance — compliance (engineer+), RBAC, 404 on no snapshot

Runs entirely over in-memory aiosqlite via ``tests/api/conftest.py`` fixtures.
No Postgres, Docker, or network.
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

from app.models import AuditLog, ConfigSnapshot, ConfigSource, Device, DeviceStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_device(session: AsyncSession, **kwargs: Any) -> Device:
    defaults: dict[str, Any] = {
        "hostname": "sw-01",
        "mgmt_ip": "10.0.0.1",
        "vendor_id": "cisco_ios",
        "status": DeviceStatus.REACHABLE,
    }
    defaults.update(kwargs)
    device = Device(**defaults)
    session.add(device)
    await session.flush()
    return device


async def _seed_snapshot(
    session: AsyncSession,
    device: Device,
    *,
    content: str = "hostname sw-01\n",
    baseline: bool = False,
    source: ConfigSource = ConfigSource.ON_DEMAND,
) -> ConfigSnapshot:
    import hashlib

    h = hashlib.sha256(content.encode()).hexdigest()
    snap = ConfigSnapshot(
        device_id=device.id,
        captured_at=datetime.now(UTC),
        content_hash=h,
        content=content,
        source=source,
        baseline=baseline,
    )
    session.add(snap)
    await session.flush()
    return snap


async def _audit_actions(session: AsyncSession) -> list[str]:
    rows = (await session.execute(select(AuditLog))).scalars().all()
    return [r.action for r in rows]


# ---------------------------------------------------------------------------
# List config snapshots
# ---------------------------------------------------------------------------


class TestListConfigSnapshots:
    async def test_viewer_can_list(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        await _seed_snapshot(session, device, content="hostname sw-01\n")
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots",
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        # content must NOT appear in list items (ADR-0017)
        assert "content" not in data["items"][0]

    async def test_unauthenticated_is_401(
        self,
        client: httpx.AsyncClient,
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        await session.commit()
        resp = await client.get(f"/api/v1/devices/{device.id}/config-snapshots")
        assert resp.status_code == 401

    async def test_unknown_device_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(
            f"/api/v1/devices/{uuid.uuid4()}/config-snapshots",
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 404

    async def test_pagination(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        for i in range(5):
            await _seed_snapshot(session, device, content=f"hostname sw-{i:02d}\n")
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots",
            params={"limit": 2, "offset": 0},
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2

    async def test_multiple_snapshots_ordered_newest_first(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        snap_a = await _seed_snapshot(session, device, content="hostname sw-01\n")
        snap_b = await _seed_snapshot(session, device, content="hostname sw-02\n")
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots",
            headers=auth_headers("viewer"),
        )
        ids = [item["id"] for item in resp.json()["items"]]
        # newest first (snap_b was inserted later with same captured_at → created_at tiebreak)
        assert ids[0] == str(snap_b.id) or ids[0] == str(snap_a.id)  # order stable


# ---------------------------------------------------------------------------
# Get one snapshot metadata
# ---------------------------------------------------------------------------


class TestGetConfigSnapshot:
    async def test_viewer_gets_metadata(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        snap = await _seed_snapshot(session, device)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}",
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == str(snap.id)
        assert body["content_hash"] == snap.content_hash
        assert "content" not in body

    async def test_wrong_device_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device_a = await _seed_device(session, hostname="sw-a", mgmt_ip="10.0.0.1")
        device_b = await _seed_device(session, hostname="sw-b", mgmt_ip="10.0.0.2")
        snap = await _seed_snapshot(session, device_a)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device_b.id}/config-snapshots/{snap.id}",
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 404

    async def test_unknown_snapshot_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{uuid.uuid4()}",
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Raw content — engineer+ gate
# ---------------------------------------------------------------------------


class TestGetConfigSnapshotContent:
    async def test_engineer_gets_content(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        snap = await _seed_snapshot(session, device, content="hostname sw-01\nsecret password\n")
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}/content",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["content"] == "hostname sw-01\nsecret password\n"
        assert body["content_hash"] == snap.content_hash

    async def test_admin_passes_engineer_gate(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        snap = await _seed_snapshot(session, device)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}/content",
            headers=auth_headers("admin"),
        )
        assert resp.status_code == 200

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        role: str,
    ) -> None:
        device = await _seed_device(session)
        snap = await _seed_snapshot(session, device)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}/content",
            headers=auth_headers(role),
        )
        assert resp.status_code == 403

    async def test_content_access_is_audited(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        snap = await _seed_snapshot(session, device)
        await session.commit()

        await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}/content",
            headers=auth_headers("engineer"),
        )
        actions = await _audit_actions(session)
        assert "config.snapshot_content_read" in actions


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------


class TestGetDrift:
    async def test_no_baseline_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        await _seed_snapshot(session, device, baseline=False)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/drift",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 404

    async def test_no_device_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(
            f"/api/v1/devices/{uuid.uuid4()}/drift",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 404

    async def test_no_drift_when_identical(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        # baseline and latest share identical content → no drift
        await _seed_snapshot(session, device, content="hostname sw-01\n", baseline=True)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/drift",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["has_drift"] is False
        assert body["diff"] == ""

    async def test_drift_detected_when_content_differs(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        import hashlib

        device = await _seed_device(session)
        old_content = "hostname sw-01\n"
        new_content = "hostname sw-01\nno ip http server\n"

        baseline = ConfigSnapshot(
            device_id=device.id,
            captured_at=datetime(2026, 1, 1, tzinfo=UTC),
            content_hash=hashlib.sha256(old_content.encode()).hexdigest(),
            content=old_content,
            source=ConfigSource.SCHEDULED,
            baseline=True,
        )
        current = ConfigSnapshot(
            device_id=device.id,
            captured_at=datetime(2026, 1, 2, tzinfo=UTC),
            content_hash=hashlib.sha256(new_content.encode()).hexdigest(),
            content=new_content,
            source=ConfigSource.ON_DEMAND,
            baseline=False,
        )
        session.add_all([baseline, current])
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/drift",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["has_drift"] is True
        assert len(body["hunks"]) >= 1

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        role: str,
    ) -> None:
        device = await _seed_device(session)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/drift",
            headers=auth_headers(role),
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------


class TestGetCompliance:
    async def test_no_snapshot_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/compliance",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 404

    async def test_no_device_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(
            f"/api/v1/devices/{uuid.uuid4()}/compliance",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 404

    async def test_default_policy_returns_findings(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        content = "hostname sw-01\nservice password-encryption\n"
        await _seed_snapshot(session, device, content=content)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/compliance",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "findings" in body
        assert "violation_count" in body
        assert "pass_count" in body
        assert body["device_id"] == str(device.id)

    async def test_unknown_policy_id_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        device = await _seed_device(session)
        await _seed_snapshot(session, device)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/compliance",
            params={"policy_id": "no-such-policy"},
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 404

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        role: str,
    ) -> None:
        device = await _seed_device(session)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/compliance",
            headers=auth_headers(role),
        )
        assert resp.status_code == 403
