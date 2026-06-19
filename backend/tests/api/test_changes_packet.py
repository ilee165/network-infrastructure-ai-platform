"""ChangeRequest + packet capture/analysis API tests (M5-T15).

Offline-first (D16): an in-memory aiosqlite engine carries the full schema and
both the request-scoped session and the lifecycle-owning sessionmaker bind to
the same engine. ``celery_app.send_task`` is monkeypatched so a capture launch is
asserted (task name, queue, args) without a broker, and the sandboxed tshark
analysis is replaced by a seam so no real pcap/subprocess is touched.

Covers the task's exit criteria:

- approve/reject require ``engineer`` or higher (viewer/operator -> 403);
- self-approval (approver == requester) is rejected **at the endpoint** under the
  default four-eyes config (defence in depth, in addition to the CR service);
- a non-approved CR cannot be driven to execute through the API (there is no
  execute edge on the surface, and approve cannot skip ``pending_approval``);
- a capture launch enqueues the ``packet.capture_segment`` task and returns the
  capture metadata (capture_id + queued status);
- the analysis endpoint returns normalized findings (no raw packet bytes);
- unauthenticated / under-privileged callers are rejected.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api import deps
from app.api.v1 import agents as agents_router
from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.engines.packet import Conversation, PacketFindings
from app.models import AuditLog, Base, ChangeRequest, PcapMetadata, User
from app.models import Role as RoleRow
from app.models.change_requests import ChangeRequestKind, ChangeRequestState
from app.models.mixins import utcnow

TEST_PASSWORD = "unit-test-password"
ROLE_ORDER = ("viewer", "operator", "engineer", "admin")


# --------------------------------------------------------------------------- #
# Engine + data fixtures (in-memory aiosqlite, full schema, FK enforcement).
# --------------------------------------------------------------------------- #
@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(eng.sync_engine, "connect")
    def _fks(dbapi_connection: Any, _record: Any) -> None:
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
async def users(sessionmaker: async_sessionmaker[AsyncSession]) -> dict[str, User]:
    """One active user per role plus one inactive viewer, keyed by role name."""
    password_hash = hash_password(TEST_PASSWORD)
    async with sessionmaker() as session:
        roles = {name: RoleRow(name=name) for name in ROLE_ORDER}
        session.add_all(roles.values())
        await session.flush()
        seeded: dict[str, User] = {}
        for name in ROLE_ORDER:
            user = User(username=f"{name}_user", password_hash=password_hash, role=roles[name])
            session.add(user)
            seeded[name] = user
        # A second engineer so an approver distinct from the requester exists.
        other = User(username="engineer2_user", password_hash=password_hash, role=roles["engineer"])
        session.add(other)
        seeded["engineer2"] = other
        inactive = User(
            username="inactive_user",
            password_hash=password_hash,
            role=roles["viewer"],
            is_active=False,
        )
        session.add(inactive)
        seeded["inactive"] = inactive
        await session.commit()
        for user in seeded.values():
            await session.refresh(user, attribute_names=["role"])
        return seeded


@pytest.fixture()
def token_for(users: dict[str, User], settings: Settings) -> Callable[[str], str]:
    def _mint(role: str) -> str:
        user = users[role]
        return create_access_token(
            str(user.id),
            settings,
            extra_claims={"type": "access", "roles": [user.role.name]},
        )

    return _mint


@pytest.fixture()
def auth(token_for: Callable[[str], str]) -> Callable[[str], dict[str, str]]:
    def _headers(role: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token_for(role)}"}

    return _headers


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

    monkeypatch.setattr(agents_router.celery_app, "send_task", _fake_send_task)
    return calls


@pytest.fixture()
def findings() -> PacketFindings:
    """A representative normalized findings object the analysis seam returns."""
    return PacketFindings(
        packet_count=3,
        top_talkers=[Conversation(src="10.0.0.1", dst="10.0.0.2", packets=2, bytes=200)],
        protocol_hierarchy=[],
        tcp_resets=1,
        tcp_retransmissions=0,
    )


@pytest.fixture()
def app(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    findings: PacketFindings,
) -> Iterator[FastAPI]:
    """The app wired to the in-memory engine + a stubbed analysis seam."""
    from app.main import create_app

    application = create_app(settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            yield session

    application.dependency_overrides[deps.get_db] = _override_db
    application.dependency_overrides[deps.get_sessionmaker] = lambda: sessionmaker
    # Replace the sandboxed tshark analysis so no real pcap/subprocess is touched.
    application.dependency_overrides[agents_router.get_pcap_analyzer] = lambda: (
        lambda capture_id, display_filter: findings
    )
    yield application
    application.dependency_overrides.clear()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Helpers: seed a CR directly so lifecycle edges can be exercised over the API.
# --------------------------------------------------------------------------- #
async def _seed_cr(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    requester: User,
    state: ChangeRequestState = ChangeRequestState.PENDING_APPROVAL,
    four_eyes_required: bool = True,
) -> ChangeRequest:
    async with sessionmaker() as session:
        cr = ChangeRequest(
            state=state,
            kind=ChangeRequestKind.CONFIG,
            requester_id=requester.id,
            four_eyes_required=four_eyes_required,
            target_refs={"device_ids": ["d-1"]},
            payload={"diff": "secret config fragment"},
        )
        session.add(cr)
        await session.commit()
        await session.refresh(cr)
        return cr


async def _cr_state(
    sessionmaker: async_sessionmaker[AsyncSession], cr_id: uuid.UUID
) -> ChangeRequestState:
    async with sessionmaker() as session:
        row = await session.get(ChangeRequest, cr_id)
        assert row is not None
        return row.state


async def _audit_actions(sessionmaker: async_sessionmaker[AsyncSession]) -> list[str]:
    async with sessionmaker() as session:
        rows = (await session.execute(select(AuditLog))).scalars().all()
        return [row.action for row in rows]


# --------------------------------------------------------------------------- #
# ChangeRequest surface: authentication + RBAC.
# --------------------------------------------------------------------------- #
class TestChangeRequestAuthz:
    async def test_list_requires_authentication(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/agents/changes")
        assert resp.status_code == 401

    async def test_list_rejects_viewer(
        self, client: httpx.AsyncClient, auth: Callable[[str], dict[str, str]]
    ) -> None:
        resp = await client.get("/api/v1/agents/changes", headers=auth("viewer"))
        assert resp.status_code == 403

    async def test_engineer_may_list(
        self, client: httpx.AsyncClient, auth: Callable[[str], dict[str, str]]
    ) -> None:
        resp = await client.get("/api/v1/agents/changes", headers=auth("engineer"))
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    async def test_get_unknown_cr_is_404(
        self, client: httpx.AsyncClient, auth: Callable[[str], dict[str, str]]
    ) -> None:
        resp = await client.get(f"/api/v1/agents/changes/{uuid.uuid4()}", headers=auth("engineer"))
        assert resp.status_code == 404


class TestApproveRbac:
    async def test_operator_cannot_approve(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        cr = await _seed_cr(sessionmaker, requester=users["engineer"])
        resp = await client.post(
            f"/api/v1/agents/changes/{cr.id}/approve", headers=auth("operator"), json={}
        )
        assert resp.status_code == 403
        assert await _cr_state(sessionmaker, cr.id) is ChangeRequestState.PENDING_APPROVAL

    async def test_engineer_distinct_from_requester_may_approve(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        cr = await _seed_cr(sessionmaker, requester=users["engineer"])
        resp = await client.post(
            f"/api/v1/agents/changes/{cr.id}/approve", headers=auth("engineer2"), json={}
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == ChangeRequestState.APPROVED.value
        assert await _cr_state(sessionmaker, cr.id) is ChangeRequestState.APPROVED


class TestFourEyesAtEndpoint:
    async def test_self_approval_rejected_at_endpoint(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        # The engineer who requested the CR attempts to approve it themselves.
        cr = await _seed_cr(sessionmaker, requester=users["engineer"])
        resp = await client.post(
            f"/api/v1/agents/changes/{cr.id}/approve", headers=auth("engineer"), json={}
        )
        assert resp.status_code == 403
        # Endpoint-layer guard fired: the CR never left pending_approval and no
        # ``approved`` transition audit was written.
        assert await _cr_state(sessionmaker, cr.id) is ChangeRequestState.PENDING_APPROVAL
        actions = await _audit_actions(sessionmaker)
        assert "change_request.pending_approval_to_approved" not in actions

    async def test_requester_may_reject_own_cr(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        # Four-eyes constrains approve, not reject — the requester may withdraw.
        cr = await _seed_cr(sessionmaker, requester=users["engineer"])
        resp = await client.post(
            f"/api/v1/agents/changes/{cr.id}/reject", headers=auth("engineer"), json={}
        )
        assert resp.status_code == 200
        assert await _cr_state(sessionmaker, cr.id) is ChangeRequestState.DRAFT


class TestNonApprovedCannotExecute:
    async def test_approve_on_draft_cr_conflicts(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        # A draft CR is not pending approval: approve must conflict, and the CR
        # can never be driven toward execution through the API.
        cr = await _seed_cr(
            sessionmaker, requester=users["engineer"], state=ChangeRequestState.DRAFT
        )
        resp = await client.post(
            f"/api/v1/agents/changes/{cr.id}/approve", headers=auth("engineer2"), json={}
        )
        assert resp.status_code == 409
        assert await _cr_state(sessionmaker, cr.id) is ChangeRequestState.DRAFT

    async def test_no_execute_edge_on_surface(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        # Even an approved CR exposes no API edge to executing/completed — the
        # Automation Agent service principal is the only driver of execution.
        cr = await _seed_cr(
            sessionmaker, requester=users["engineer"], state=ChangeRequestState.APPROVED
        )
        for verb in ("execute", "mark-executing", "complete"):
            resp = await client.post(
                f"/api/v1/agents/changes/{cr.id}/{verb}", headers=auth("engineer2"), json={}
            )
            assert resp.status_code in (404, 405)
        assert await _cr_state(sessionmaker, cr.id) is ChangeRequestState.APPROVED


# --------------------------------------------------------------------------- #
# Packet capture / analysis surface.
# --------------------------------------------------------------------------- #
class TestCaptureLaunch:
    async def test_launch_requires_authentication(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/api/v1/agents/captures", json={"interface": "eth0"})
        assert resp.status_code == 401

    async def test_launch_rejects_viewer(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        resp = await client.post(
            "/api/v1/agents/captures", headers=auth("viewer"), json={"interface": "eth0"}
        )
        assert resp.status_code == 403
        assert sent_tasks == []

    async def test_engineer_launch_enqueues_and_returns_metadata(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        resp = await client.post(
            "/api/v1/agents/captures",
            headers=auth("engineer"),
            json={"interface": "eth0", "capture_filter": "tcp port 443"},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "queued"
        capture_id = body["capture_id"]
        assert uuid.UUID(capture_id)  # well-formed
        assert body["interface"] == "eth0"
        # The work was enqueued to the packet queue, never run inline.
        assert len(sent_tasks) == 1
        task = sent_tasks[0]
        assert task["name"] == "packet.capture_segment"
        assert task["queue"] == "packet"
        assert capture_id in task["args"]
        # The launch is audited.
        assert "packet.capture_requested" in await _audit_actions(sessionmaker)

    async def test_launch_rejects_dash_prefixed_filter(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        sent_tasks: list[dict[str, Any]],
    ) -> None:
        # A dash-prefixed filter token would inject a tshark flag — rejected
        # before anything is enqueued (422), nothing queued.
        resp = await client.post(
            "/api/v1/agents/captures",
            headers=auth("engineer"),
            json={"interface": "eth0", "capture_filter": "-w/evil"},
        )
        assert resp.status_code == 422
        assert sent_tasks == []


class TestCaptureStatus:
    async def test_status_unknown_is_404(
        self, client: httpx.AsyncClient, auth: Callable[[str], dict[str, str]]
    ) -> None:
        resp = await client.get(f"/api/v1/agents/captures/{uuid.uuid4()}", headers=auth("engineer"))
        assert resp.status_code == 404

    async def test_status_returns_metadata(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        capture_id = uuid.uuid4()
        async with sessionmaker() as session:
            session.add(
                PcapMetadata(
                    capture_id=capture_id,
                    interface="eth0",
                    requester_id=users["engineer"].id,
                    storage_path=f"/data/pcaps/{capture_id}.pcap",
                    sha256="a" * 64,
                    byte_count=2048,
                    packet_count=7,
                    started_at=utcnow(),
                    retention_expires_at=utcnow(),
                )
            )
            await session.commit()
        resp = await client.get(f"/api/v1/agents/captures/{capture_id}", headers=auth("engineer"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["capture_id"] == str(capture_id)
        assert body["interface"] == "eth0"
        assert body["byte_count"] == 2048
        assert body["status"] == "completed"

    async def test_status_rejects_viewer(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(f"/api/v1/agents/captures/{uuid.uuid4()}", headers=auth("viewer"))
        assert resp.status_code == 403


class TestCaptureAnalysis:
    async def _seed_capture(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        requester: User,
    ) -> uuid.UUID:
        capture_id = uuid.uuid4()
        async with sessionmaker() as session:
            session.add(
                PcapMetadata(
                    capture_id=capture_id,
                    interface="eth0",
                    requester_id=requester.id,
                    storage_path=f"/data/pcaps/{capture_id}.pcap",
                    sha256="b" * 64,
                    byte_count=4096,
                    started_at=utcnow(),
                    retention_expires_at=utcnow(),
                )
            )
            await session.commit()
        return capture_id

    async def test_analysis_returns_normalized_findings(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        capture_id = await self._seed_capture(sessionmaker, users["engineer"])
        resp = await client.get(
            f"/api/v1/agents/captures/{capture_id}/analysis", headers=auth("engineer")
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["packet_count"] == 3
        assert body["tcp_resets"] == 1
        assert body["top_talkers"][0]["src"] == "10.0.0.1"
        # Normalized findings only — no raw packet payload field is surfaced.
        assert "payload" not in body
        assert "raw" not in body

    async def test_analysis_unknown_capture_is_404(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(
            f"/api/v1/agents/captures/{uuid.uuid4()}/analysis", headers=auth("engineer")
        )
        assert resp.status_code == 404

    async def test_analysis_rejects_operator(
        self,
        client: httpx.AsyncClient,
        auth: Callable[[str], dict[str, str]],
        users: dict[str, User],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        capture_id = await self._seed_capture(sessionmaker, users["engineer"])
        resp = await client.get(
            f"/api/v1/agents/captures/{capture_id}/analysis", headers=auth("operator")
        )
        assert resp.status_code == 403
