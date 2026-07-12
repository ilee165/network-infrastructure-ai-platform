"""Real-route RBAC contract matrix (F3 residual, Wave 4 T6).

Wave 1 added ONE real-route test proving the forced-password-change guard
resolves through ``require_role`` -> ``get_active_user`` on a real protected
route (``tests/api/test_account.py::test_flagged_user_blocked_on_real_protected_route``,
GET ``/api/v1/devices``). This module generalizes that same shape — hit the
REAL app through the SAME ``client``/``users``/``auth_headers`` fixtures, never
a synthetic probe route or a mounted fake router — into one boundary-pair test
per router under ``app/api/v1/``, so a future router wired around
``require_role`` incorrectly fails a test here instead of surfacing only in
review (2026-07-10-testing-strategy-review.md F3(c) / WAVE4-PLAN.md T6).

Sizing is deliberate: **one router = one boundary-pair test**, not a full
4-role x N-router cross product. Most routers use only two of the four RBAC
ranks (``viewer < operator < engineer < admin``, ADR-0010), so asserting all
four against every router would exercise combinations nobody's wiring can
actually distinguish. Per router this asserts:

(a) a user at exactly the router's minimum ``require_role`` tier succeeds on a
    real route, and
(b) a user one rank BELOW that minimum is rejected 403 on the SAME route.

A router whose own routes span two distinct minimum tiers (e.g. viewer reads +
engineer writes) gets one boundary-pair per tier it actually uses. ``viewer``
is the RBAC floor (ADR-0010: no rank sits below it) — for a viewer-gated
route there is no lower-rank user to reject, so the "floor" pair is instead
(viewer succeeds, unauthenticated is 401), matching the existing convention in
e.g. ``test_adc.py::test_below_viewer_is_401`` /
``test_docs.py::test_all_roles_can_list``.

Router coverage (13, the current live set per ``app/api/v1/__init__.py`` and
``app/api/v1/auth/__init__.py`` — verified by grep, not by an older planning
doc): adc, agents, applications, config_snapshots, credentials, devices,
discovery, docs, topology, virtualization, integrations, auth/settings,
auth/users. ``auth/login``, ``auth/oidc``, ``auth/account`` are pre-auth or
self-service and carry no ``require_role`` gate — out of scope by construction.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.api import deps
from app.api.v1 import credentials as credentials_routes
from app.api.v1 import discovery as discovery_routes
from app.core.crypto import _StaticKeyProvider
from app.models import (
    AgentSession,
    AgentSessionStatus,
    ConfigSnapshot,
    ConfigSource,
    Device,
    DeviceStatus,
    DiscoveryRun,
    TopologySnapshot,
    User,
)

# ---------------------------------------------------------------------------
# Shared local seeding helpers (kept self-contained rather than importing from
# sibling per-router test modules, matching the rest of the suite's style).
# ---------------------------------------------------------------------------


async def _seed_device(session: AsyncSession, **kwargs: Any) -> Device:
    defaults: dict[str, Any] = {
        "hostname": "matrix-sw-01",
        "mgmt_ip": "192.0.2.50",
        "vendor_id": "cisco_ios",
        "status": DeviceStatus.REACHABLE,
    }
    defaults.update(kwargs)
    device = Device(**defaults)
    session.add(device)
    await session.flush()
    return device


async def _seed_snapshot(
    session: AsyncSession, device: Device, *, content: str = "hostname x\n"
) -> ConfigSnapshot:
    import hashlib

    snap = ConfigSnapshot(
        device_id=device.id,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
        content=content,
        source=ConfigSource.ON_DEMAND,
        baseline=False,
    )
    session.add(snap)
    await session.flush()
    return snap


def _device_payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "hostname": "matrix-new-sw",
        "mgmt_ip": "192.0.2.60",
        "vendor_id": "cisco_ios",
        "model": "C9300-48T",
        "os_version": "17.9.4",
        "serial": "FOC9999X0AB",
    }
    body.update(overrides)
    return body


def _discovery_payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "seeds": ["192.0.2.10"],
        "hop_limit": 1,
        "allowlist": ["192.0.2.0/24"],
    }
    body.update(overrides)
    return body


def _application_payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"name": "matrix-app"}
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Extra fixtures only some routers need — each mirrors an already-established
# per-router test pattern (no new harness invented for this file).
# ---------------------------------------------------------------------------


class _StaticProvider(_StaticKeyProvider):
    """One fixed 32-byte KEK, mirroring ``test_credentials.py``'s local fixture."""

    def __init__(self) -> None:
        super().__init__(b"\x24" * 32, "matrix-v1")


@pytest.fixture()
def key_provider(app: FastAPI) -> _StaticProvider:
    """Override ``credentials.get_key_provider`` so no real KMS is needed.

    Overriding it with a *working* provider (rather than leaving the default,
    which raises ``KekConfigurationError`` with no ``NETOPS_KEK`` configured)
    means the role check — not KEK bootstrap — is what a reject-side call
    exercises; ``get_key_provider`` runs regardless of the caller's rank, but
    never fails here, so ``require_role`` is the only thing that can 403.
    """
    provider = _StaticProvider()
    app.dependency_overrides[credentials_routes.get_key_provider] = lambda: provider
    return provider


@pytest.fixture()
def sent_tasks(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture ``celery_app.send_task`` instead of touching a broker (discovery)."""
    calls: list[dict[str, Any]] = []

    def _fake_send_task(
        name: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        **options: Any,
    ) -> Any:
        calls.append({"name": name, "args": args, "kwargs": kwargs, "queue": options.get("queue")})

        class _Result:
            id = "matrix-task-id"

        return _Result()

    monkeypatch.setattr(discovery_routes.celery_app, "send_task", _fake_send_task)
    return calls


@pytest.fixture()
def app_with_sessionmaker(app: FastAPI, engine: AsyncEngine) -> FastAPI:
    """Wire ``deps.get_sessionmaker`` onto the same in-memory engine.

    ``agents.py``'s session-scoped reads (``get_session``) use the raw
    sessionmaker, not the request-scoped ``get_db`` session the rest of the
    API layer uses — mirroring ``tests/api/test_agents.py``'s own bespoke
    conftest, just scoped locally to the one representative route this file
    needs (no full scripted-supervisor harness required for a plain read).
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    app.dependency_overrides[deps.get_sessionmaker] = lambda: maker
    return app


@pytest.fixture()
async def agents_client(app_with_sessionmaker: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app_with_sessionmaker)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Viewer-floor routers (no rank below viewer exists; floor pair is
# viewer-succeeds / unauthenticated-401).
# ---------------------------------------------------------------------------


class TestAdcRoleFloor:
    async def test_viewer_lists_virtual_servers(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/adc/virtual-servers", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/adc/virtual-servers")
        assert resp.status_code == 401


class TestDocsRoleFloor:
    async def test_viewer_lists_documents(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/docs", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/docs")
        assert resp.status_code == 401


class TestVirtualizationRoleFloor:
    async def test_viewer_lists_vms(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/virtualization/vms", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/virtualization/vms")
        assert resp.status_code == 401


class TestTopologyRoleFloor:
    async def test_viewer_diffs_a_snapshot_against_itself(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        session: AsyncSession,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        run = DiscoveryRun(seeds=["192.0.2.10"], hop_limit=1, allowlist=["192.0.2.0/24"])
        session.add(run)
        await session.flush()
        session.add(TopologySnapshot(run_id=run.id, nodes=[], edges=[]))
        await session.commit()

        resp = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(run.id), "to_run": str(run.id)},
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(uuid.uuid4()), "to_run": str(uuid.uuid4())},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Admin-floor routers (one rank below admin is engineer).
# ---------------------------------------------------------------------------


class TestIntegrationsRoleMatrix:
    async def test_admin_lists_integrations(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/integrations", headers=auth_headers("admin"))
        assert resp.status_code == 200

    async def test_engineer_one_tier_below_admin_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/integrations", headers=auth_headers("engineer"))
        assert resp.status_code == 403


class TestAuthSettingsRoleMatrix:
    async def test_admin_reads_system_settings(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/auth/settings", headers=auth_headers("admin"))
        assert resp.status_code == 200

    async def test_engineer_one_tier_below_admin_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/auth/settings", headers=auth_headers("engineer"))
        assert resp.status_code == 403


class TestAuthUsersRoleMatrix:
    async def test_admin_lists_users(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/auth/users", headers=auth_headers("admin"))
        assert resp.status_code == 200

    async def test_engineer_one_tier_below_admin_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/auth/users", headers=auth_headers("engineer"))
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Mixed-tier routers: a viewer-floor read pair + a full engineer boundary pair
# (one tier below engineer is operator).
# ---------------------------------------------------------------------------


class TestDevicesRoleMatrix:
    async def test_viewer_lists_devices(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/devices", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/devices")
        assert resp.status_code == 401

    async def test_engineer_creates_device(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.post(
            "/api/v1/devices", json=_device_payload(), headers=auth_headers("engineer")
        )
        assert resp.status_code == 201

    async def test_operator_one_tier_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.post(
            "/api/v1/devices", json=_device_payload(), headers=auth_headers("operator")
        )
        assert resp.status_code == 403


class TestDiscoveryRoleMatrix:
    async def test_viewer_lists_runs(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/discovery/runs", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/discovery/runs")
        assert resp.status_code == 401

    async def test_engineer_starts_run(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        resp = await client.post(
            "/api/v1/discovery/runs", json=_discovery_payload(), headers=auth_headers("engineer")
        )
        assert resp.status_code == 202

    async def test_operator_one_tier_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        resp = await client.post(
            "/api/v1/discovery/runs", json=_discovery_payload(), headers=auth_headers("operator")
        )
        assert resp.status_code == 403
        assert sent_tasks == []


class TestApplicationsRoleMatrix:
    async def test_viewer_lists_applications(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/applications", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/applications")
        assert resp.status_code == 401

    async def test_engineer_creates_application(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.post(
            "/api/v1/applications", json=_application_payload(), headers=auth_headers("engineer")
        )
        assert resp.status_code == 201

    async def test_operator_one_tier_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.post(
            "/api/v1/applications", json=_application_payload(), headers=auth_headers("operator")
        )
        assert resp.status_code == 403


class TestConfigSnapshotsRoleMatrix:
    async def test_viewer_lists_snapshots(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        session: AsyncSession,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        device = await _seed_device(session)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots", headers=auth_headers("viewer")
        )
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get(f"/api/v1/devices/{uuid.uuid4()}/config-snapshots")
        assert resp.status_code == 401

    async def test_engineer_reads_snapshot_content(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        session: AsyncSession,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        device = await _seed_device(session, hostname="matrix-sw-02", mgmt_ip="192.0.2.51")
        snap = await _seed_snapshot(session, device)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}/content",
            headers=auth_headers("engineer"),
        )
        assert resp.status_code == 200

    async def test_operator_one_tier_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        session: AsyncSession,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        device = await _seed_device(session, hostname="matrix-sw-03", mgmt_ip="192.0.2.52")
        snap = await _seed_snapshot(session, device)
        await session.commit()

        resp = await client.get(
            f"/api/v1/devices/{device.id}/config-snapshots/{snap.id}/content",
            headers=auth_headers("operator"),
        )
        assert resp.status_code == 403


class TestCredentialsRoleMatrix:
    async def test_viewer_lists_credentials(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/credentials", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/credentials")
        assert resp.status_code == 401

    async def test_engineer_reads_rotation_status(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        resp = await client.get(
            "/api/v1/credentials/rotation-status", headers=auth_headers("engineer")
        )
        assert resp.status_code == 200

    async def test_operator_one_tier_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        resp = await client.get(
            "/api/v1/credentials/rotation-status", headers=auth_headers("operator")
        )
        assert resp.status_code == 403


class TestAgentsRoleMatrix:
    async def test_viewer_reads_own_session(
        self,
        agents_client: httpx.AsyncClient,
        users: dict[str, User],
        session: AsyncSession,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        row = AgentSession(
            user_id=users["viewer"].id,
            invoking_role="viewer",
            intent="is the core link healthy?",
            status=AgentSessionStatus.COMPLETED,
        )
        session.add(row)
        await session.commit()

        resp = await agents_client.get(f"/api/v1/agents/{row.id}", headers=auth_headers("viewer"))
        assert resp.status_code == 200

    async def test_unauthenticated_is_401(self, agents_client: httpx.AsyncClient) -> None:
        resp = await agents_client.get(f"/api/v1/agents/{uuid.uuid4()}")
        assert resp.status_code == 401

    async def test_engineer_lists_change_requests(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/agents/changes", headers=auth_headers("engineer"))
        assert resp.status_code == 200

    async def test_operator_one_tier_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        users: dict[str, User],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get("/api/v1/agents/changes", headers=auth_headers("operator"))
        assert resp.status_code == 403
