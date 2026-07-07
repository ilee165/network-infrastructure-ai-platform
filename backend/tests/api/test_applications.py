"""Tests for the manual application-tagging API (P4 W2-T3, ADR-0052 §7).

Direct write at the ``engineer`` role floor with a full ADR-0038 hash-chained
audit entry per mutation; reads at ``viewer``+. Covers the RBAC matrix, input
validation (length caps, target kinds, target existence), the derived-row
protections (delete refused; PATCH hands attribute ownership to the user under
manual-wins §3.3.3), the manual cascade delete, audit before/after payloads,
hash-chain membership with a tamper negative control, the rate-limit wiring,
and the "no agent-facing tagging tool ships in P4" guard.

Runs entirely over in-memory aiosqlite via the shared ``tests/api/conftest.py``
fixtures — real-PostgreSQL semantics (cascade + audit ordering) are re-asserted
in ``tests/pg/test_application_tagging_pg.py``.
"""

from __future__ import annotations

import importlib
import pkgutil
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Application,
    ApplicationDependency,
    AuditLog,
    Device,
    NormalizedInterfaceRow,
    User,
)
from app.models.applications import (
    ApplicationOrigin,
    DependencySource,
    derived_attributes_clean,
    stamp_derived_watermark,
)
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus
from app.services import audit
from app.services.audit.verify import verify_chain

BASE = "/api/v1/applications"

Headers = Callable[[str], dict[str, str]]


def _payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "payroll",
        "description": "HR payroll stack",
        "owner": "team-hr",
        "fqdns": ["payroll.corp.example.com"],
    }
    body.update(overrides)
    return body


async def _create_application(
    client: httpx.AsyncClient, headers: dict[str, str], **overrides: Any
) -> dict[str, Any]:
    response = await client.post(BASE, json=_payload(**overrides), headers=headers)
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


async def _seed_device(session: AsyncSession, **overrides: Any) -> Device:
    values: dict[str, Any] = {"hostname": f"sw-{uuid.uuid4().hex[:8]}", "mgmt_ip": None}
    values.update(overrides)
    if values["mgmt_ip"] is None:
        values["mgmt_ip"] = f"192.0.2.{uuid.uuid4().int % 200 + 10}"
    device = Device(**values)
    session.add(device)
    await session.flush()
    return device


async def _seed_interface(
    session: AsyncSession, device: Device, *, ip_address: str | None = "192.0.2.77/24"
) -> NormalizedInterfaceRow:
    row = NormalizedInterfaceRow(
        device_id=device.id,
        raw_artifact_id=uuid.uuid4(),
        collected_at=datetime(2026, 7, 6, 12, 0, tzinfo=UTC),
        source_vendor="cisco_ios",
        name=f"Gi0/{uuid.uuid4().int % 48}",
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        ip_address=ip_address,
    )
    session.add(row)
    await session.flush()
    return row


async def _seed_derived_application(session: AsyncSession, *, name: str = "vs-crm") -> Application:
    application = Application(
        name=name,
        origin=ApplicationOrigin.DERIVED,
        origin_ref=f"f5:{uuid.uuid4()}:/Common/{name}",
        fqdns=[],
    )
    stamp_derived_watermark(application)
    session.add(application)
    await session.flush()
    return application


async def _audit_rows(session: AsyncSession, action: str | None = None) -> list[AuditLog]:
    query = select(AuditLog).order_by(AuditLog.seq)
    if action is not None:
        query = query.where(AuditLog.action == action)
    return list((await session.execute(query)).scalars().all())


# ---------------------------------------------------------------------------
# Application create (POST /applications)
# ---------------------------------------------------------------------------


class TestApplicationCreate:
    async def test_engineer_creates_manual_application(
        self,
        client: httpx.AsyncClient,
        auth_headers: Headers,
        session: AsyncSession,
        users: dict[str, User],
    ) -> None:
        body = await _create_application(client, auth_headers("engineer"))
        assert body["name"] == "payroll"
        assert body["description"] == "HR payroll stack"
        assert body["owner"] == "team-hr"
        assert body["fqdns"] == ["payroll.corp.example.com"]
        assert body["origin"] == "manual"
        assert body["origin_ref"] is None
        assert body["created_by"] == str(users["engineer"].id)
        assert uuid.UUID(body["id"])

        [entry] = await _audit_rows(session, audit.APPLICATION_CREATE)
        assert entry.actor == "user:engineer_user"
        assert entry.target_type == "application"
        assert entry.target_id == body["id"]
        assert entry.detail is not None and entry.detail["after"]["name"] == "payroll"

    async def test_admin_passes_engineer_gate(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        await _create_application(client, auth_headers("admin"))

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self, client: httpx.AsyncClient, auth_headers: Headers, role: str
    ) -> None:
        response = await client.post(BASE, json=_payload(), headers=auth_headers(role))
        assert response.status_code == 403

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.post(BASE, json=_payload())
        assert response.status_code == 401

    async def test_duplicate_name_is_409_case_insensitively(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        headers = auth_headers("engineer")
        await _create_application(client, headers)
        response = await client.post(BASE, json=_payload(name="Payroll"), headers=headers)
        assert response.status_code == 409

    async def test_name_colliding_with_derived_application_is_409(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        await _seed_derived_application(session, name="vs-crm")
        response = await client.post(
            BASE, json=_payload(name="VS-CRM"), headers=auth_headers("engineer")
        )
        assert response.status_code == 409

    @pytest.mark.parametrize(
        "overrides",
        [
            {"name": ""},
            {"name": "x" * 256},
            {"description": "x" * 4097},
            {"owner": "x" * 256},
            {"fqdns": ["x" * 254]},
            {"fqdns": [f"h{i}.example.com" for i in range(65)]},
            {"unexpected": "field"},
        ],
    )
    async def test_invalid_payload_is_422(
        self, client: httpx.AsyncClient, auth_headers: Headers, overrides: dict[str, Any]
    ) -> None:
        response = await client.post(
            BASE, json=_payload(**overrides), headers=auth_headers("engineer")
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# Application reads (GET /applications, GET /applications/{id})
# ---------------------------------------------------------------------------


class TestApplicationRead:
    async def test_viewer_lists_applications(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        await _create_application(client, auth_headers("engineer"))
        await _seed_derived_application(session, name="vs-crm")

        response = await client.get(BASE, headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert [item["name"] for item in body["items"]] == ["payroll", "vs-crm"]

    async def test_origin_filter(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        await _create_application(client, auth_headers("engineer"))
        await _seed_derived_application(session, name="vs-crm")

        response = await client.get(
            BASE, params={"origin": "derived"}, headers=auth_headers("viewer")
        )
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["origin"] == "derived"

    async def test_name_search_is_case_insensitive(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        headers = auth_headers("engineer")
        await _create_application(client, headers)
        await _create_application(client, headers, name="crm-frontend", fqdns=[])

        response = await client.get(BASE, params={"q": "PAY"}, headers=auth_headers("viewer"))
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["name"] == "payroll"

    async def test_pagination(self, client: httpx.AsyncClient, auth_headers: Headers) -> None:
        headers = auth_headers("engineer")
        for name in ("app-a", "app-b", "app-c"):
            await _create_application(client, headers, name=name, fqdns=[])

        response = await client.get(
            BASE, params={"limit": 1, "offset": 1}, headers=auth_headers("viewer")
        )
        body = response.json()
        assert body["total"] == 3
        assert [item["name"] for item in body["items"]] == ["app-b"]

    async def test_viewer_gets_detail(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.get(f"{BASE}/{created['id']}", headers=auth_headers("viewer"))
        assert response.status_code == 200
        assert response.json()["name"] == "payroll"

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        response = await client.get(f"{BASE}/{uuid.uuid4()}", headers=auth_headers("viewer"))
        assert response.status_code == 404

    async def test_unauthenticated_read_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get(BASE)
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Application update (PATCH /applications/{id})
# ---------------------------------------------------------------------------


class TestApplicationUpdate:
    async def test_engineer_updates_with_before_after_audit(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.patch(
            f"{BASE}/{created['id']}",
            json={"name": "payroll-v2", "owner": None},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["name"] == "payroll-v2"
        assert body["owner"] is None

        [entry] = await _audit_rows(session, audit.APPLICATION_UPDATE)
        assert entry.target_id == created["id"]
        assert entry.detail is not None
        assert entry.detail["before"]["name"] == "payroll"
        assert entry.detail["after"]["name"] == "payroll-v2"
        assert entry.detail["before"]["owner"] == "team-hr"
        assert entry.detail["after"]["owner"] is None

    async def test_rename_to_taken_name_is_409(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        headers = auth_headers("engineer")
        await _create_application(client, headers)
        other = await _create_application(client, headers, name="crm-frontend", fqdns=[])
        response = await client.patch(
            f"{BASE}/{other['id']}", json={"name": "PAYROLL"}, headers=headers
        )
        assert response.status_code == 409

    async def test_case_only_rename_of_same_row_is_allowed(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.patch(
            f"{BASE}/{created['id']}", json={"name": "Payroll"}, headers=auth_headers("engineer")
        )
        assert response.status_code == 200
        assert response.json()["name"] == "Payroll"

    async def test_null_name_means_unchanged(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.patch(
            f"{BASE}/{created['id']}",
            json={"name": None, "description": None},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 200
        body = response.json()
        assert body["name"] == "payroll"  # non-nullable: null = leave unchanged
        assert body["description"] is None  # nullable: null clears

    async def test_patch_on_derived_row_hands_ownership_to_user(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        """ADR-0052 §3.3.3/§7: user curation of a derived app is allowed and
        permanently wins over derivation (updated_at moves; watermark stays)."""
        derived = await _seed_derived_application(session, name="vs-crm")
        assert derived_attributes_clean(derived)

        response = await client.patch(
            f"{BASE}/{derived.id}", json={"name": "crm"}, headers=auth_headers("engineer")
        )
        assert response.status_code == 200

        await session.refresh(derived)
        assert derived.name == "crm"
        # Origin/lifecycle are untouched by an attribute edit ...
        assert ApplicationOrigin(derived.origin) is ApplicationOrigin.DERIVED
        assert derived.origin_ref is not None
        # ... but attribute ownership is now the user's (manual-wins).
        assert derived.derived_watermark is not None
        assert derived.updated_at != derived.derived_watermark
        assert not derived_attributes_clean(derived)

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self, client: httpx.AsyncClient, auth_headers: Headers, role: str
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.patch(
            f"{BASE}/{created['id']}", json={"name": "nope"}, headers=auth_headers(role)
        )
        assert response.status_code == 403

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        response = await client.patch(
            f"{BASE}/{uuid.uuid4()}", json={"name": "x"}, headers=auth_headers("engineer")
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Application delete (DELETE /applications/{id})
# ---------------------------------------------------------------------------


class TestApplicationDelete:
    async def test_manual_delete_cascades_dependencies_and_audits(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        headers = auth_headers("engineer")
        created = await _create_application(client, headers)
        device = await _seed_device(session)
        dep_response = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=headers,
        )
        assert dep_response.status_code == 201
        dependency_id = dep_response.json()["id"]

        response = await client.delete(f"{BASE}/{created['id']}", headers=headers)
        assert response.status_code == 204

        assert await session.get(Application, uuid.UUID(created["id"])) is None
        remaining = (await session.execute(select(ApplicationDependency))).scalars().all()
        assert remaining == []  # ON DELETE CASCADE took the dependency rows

        [entry] = await _audit_rows(session, audit.APPLICATION_DELETE)
        assert entry.target_id == created["id"]
        assert entry.detail is not None
        assert entry.detail["before"]["name"] == "payroll"
        cascaded = entry.detail["cascaded_dependencies"]
        assert [row["id"] for row in cascaded] == [dependency_id]
        assert cascaded[0]["target_kind"] == "device"

    async def test_derived_delete_is_refused_409(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        derived = await _seed_derived_application(session, name="vs-crm")
        response = await client.delete(f"{BASE}/{derived.id}", headers=auth_headers("engineer"))
        assert response.status_code == 409
        assert await session.get(Application, derived.id) is not None
        assert await _audit_rows(session, audit.APPLICATION_DELETE) == []

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self, client: httpx.AsyncClient, auth_headers: Headers, role: str
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.delete(f"{BASE}/{created['id']}", headers=auth_headers(role))
        assert response.status_code == 403

    async def test_unknown_id_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        response = await client.delete(f"{BASE}/{uuid.uuid4()}", headers=auth_headers("engineer"))
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Dependency create (POST /applications/{id}/dependencies)
# ---------------------------------------------------------------------------


class TestDependencyCreate:
    async def test_engineer_adds_device_dependency(
        self,
        client: httpx.AsyncClient,
        auth_headers: Headers,
        session: AsyncSession,
        users: dict[str, User],
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)

        response = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["application_id"] == created["id"]
        assert body["target_kind"] == "device"
        assert body["target_ref"] == str(device.id)
        assert body["source"] == "manual"
        assert body["created_by"] == str(users["engineer"].id)
        # Manual provenance is the single user step (ADR-0052 §2 source 4).
        assert body["provenance"] == [{"kind": "user", "ref": str(users["engineer"].id)}]

        [entry] = await _audit_rows(session, audit.APPLICATION_DEPENDENCY_CREATE)
        assert entry.actor == "user:engineer_user"
        assert entry.target_type == "application_dependency"
        assert entry.target_id == body["id"]
        assert entry.detail is not None
        assert entry.detail["after"]["target_ref"] == str(device.id)
        assert entry.detail["after"]["application_id"] == created["id"]

    async def test_engineer_adds_ip_address_dependency(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        interface = await _seed_interface(session, device)

        response = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "ip_address", "target_ref": str(interface.id)},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 201, response.text
        assert response.json()["target_kind"] == "ip_address"

    async def test_interface_without_address_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        bare = await _seed_interface(session, device, ip_address=None)

        response = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "ip_address", "target_ref": str(bare.id)},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404

    @pytest.mark.parametrize("target_kind", ["device", "ip_address"])
    async def test_unknown_target_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers, target_kind: str
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": target_kind, "target_ref": str(uuid.uuid4())},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404

    async def test_unknown_application_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        device = await _seed_device(session)
        response = await client.post(
            f"{BASE}/{uuid.uuid4()}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404

    async def test_duplicate_manual_dependency_is_409(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        body = {"target_kind": "device", "target_ref": str(device.id)}
        first = await client.post(
            f"{BASE}/{created['id']}/dependencies", json=body, headers=auth_headers("engineer")
        )
        assert first.status_code == 201
        second = await client.post(
            f"{BASE}/{created['id']}/dependencies", json=body, headers=auth_headers("engineer")
        )
        assert second.status_code == 409

    @pytest.mark.parametrize(
        "body",
        [
            {"target_kind": "dns_record", "target_ref": str(uuid.uuid4())},
            {"target_kind": "device", "target_ref": "not-a-uuid"},
            {"target_kind": "device"},
        ],
    )
    async def test_invalid_body_is_422(
        self, client: httpx.AsyncClient, auth_headers: Headers, body: dict[str, Any]
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.post(
            f"{BASE}/{created['id']}/dependencies", json=body, headers=auth_headers("engineer")
        )
        assert response.status_code == 422

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Headers,
        session: AsyncSession,
        role: str,
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        response = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=auth_headers(role),
        )
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Dependency list + delete
# ---------------------------------------------------------------------------


class TestDependencyListAndDelete:
    async def test_viewer_lists_all_source_rows(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=auth_headers("engineer"),
        )
        # A derivation-owned row for the same app (seeded directly, source=f5).
        session.add(
            ApplicationDependency(
                application_id=uuid.UUID(created["id"]),
                target_kind="device",
                target_ref=str(uuid.uuid4()),
                source=DependencySource.F5,
                provenance=[{"kind": "virtual_server", "ref": "vs-1"}],
                derived_at=datetime(2026, 7, 6, 12, 0, tzinfo=UTC),
            )
        )
        await session.flush()

        response = await client.get(
            f"{BASE}/{created['id']}/dependencies", headers=auth_headers("viewer")
        )
        assert response.status_code == 200
        rows = response.json()
        assert {row["source"] for row in rows} == {"manual", "f5"}

    async def test_list_unknown_application_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        response = await client.get(
            f"{BASE}/{uuid.uuid4()}/dependencies", headers=auth_headers("viewer")
        )
        assert response.status_code == 404

    async def test_engineer_removes_manual_dependency(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        dep = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=auth_headers("engineer"),
        )
        dependency_id = dep.json()["id"]

        response = await client.delete(
            f"{BASE}/{created['id']}/dependencies/{dependency_id}",
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 204
        assert await session.get(ApplicationDependency, uuid.UUID(dependency_id)) is None

        [entry] = await _audit_rows(session, audit.APPLICATION_DEPENDENCY_DELETE)
        assert entry.target_id == dependency_id
        assert entry.detail is not None
        assert entry.detail["before"]["target_ref"] == str(device.id)
        assert entry.detail["before"]["source"] == "manual"

    async def test_derivation_owned_row_delete_is_refused_409(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        derived_row = ApplicationDependency(
            application_id=uuid.UUID(created["id"]),
            target_kind="device",
            target_ref=str(uuid.uuid4()),
            source=DependencySource.F5,
            provenance=[{"kind": "virtual_server", "ref": "vs-1"}],
            derived_at=datetime(2026, 7, 6, 12, 0, tzinfo=UTC),
        )
        session.add(derived_row)
        await session.flush()

        response = await client.delete(
            f"{BASE}/{created['id']}/dependencies/{derived_row.id}",
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 409
        assert await session.get(ApplicationDependency, derived_row.id) is not None

    async def test_dependency_of_other_application_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        headers = auth_headers("engineer")
        first = await _create_application(client, headers)
        second = await _create_application(client, headers, name="crm-frontend", fqdns=[])
        device = await _seed_device(session)
        dep = await client.post(
            f"{BASE}/{first['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=headers,
        )
        response = await client.delete(
            f"{BASE}/{second['id']}/dependencies/{dep.json()['id']}", headers=headers
        )
        assert response.status_code == 404

    async def test_unknown_dependency_is_404(
        self, client: httpx.AsyncClient, auth_headers: Headers
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        response = await client.delete(
            f"{BASE}/{created['id']}/dependencies/{uuid.uuid4()}",
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Headers,
        session: AsyncSession,
        role: str,
    ) -> None:
        created = await _create_application(client, auth_headers("engineer"))
        device = await _seed_device(session)
        dep = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=auth_headers("engineer"),
        )
        response = await client.delete(
            f"{BASE}/{created['id']}/dependencies/{dep.json()['id']}",
            headers=auth_headers(role),
        )
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# ADR-0038 hash-chain membership (+ tamper negative control)
# ---------------------------------------------------------------------------


class TestAuditChainMembership:
    async def _run_tagging_sequence(
        self, client: httpx.AsyncClient, headers: dict[str, str], session: AsyncSession
    ) -> None:
        created = await _create_application(client, headers)
        device = await _seed_device(session)
        dep = await client.post(
            f"{BASE}/{created['id']}/dependencies",
            json={"target_kind": "device", "target_ref": str(device.id)},
            headers=headers,
        )
        assert dep.status_code == 201
        patched = await client.patch(
            f"{BASE}/{created['id']}", json={"owner": "team-fin"}, headers=headers
        )
        assert patched.status_code == 200
        removed = await client.delete(
            f"{BASE}/{created['id']}/dependencies/{dep.json()['id']}", headers=headers
        )
        assert removed.status_code == 204
        deleted = await client.delete(f"{BASE}/{created['id']}", headers=headers)
        assert deleted.status_code == 204

    async def test_chain_verifies_over_tagging_mutations(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        await self._run_tagging_sequence(client, auth_headers("engineer"), session)
        actions = [row.action for row in await _audit_rows(session)]
        assert actions == [
            audit.APPLICATION_CREATE,
            audit.APPLICATION_DEPENDENCY_CREATE,
            audit.APPLICATION_UPDATE,
            audit.APPLICATION_DEPENDENCY_DELETE,
            audit.APPLICATION_DELETE,
        ]
        result = await verify_chain(session)
        assert result.ok, result.break_
        assert result.checked == 5

    async def test_tampered_tagging_entry_breaks_the_chain(
        self, client: httpx.AsyncClient, auth_headers: Headers, session: AsyncSession
    ) -> None:
        """Negative control: mutating a tagging entry's detail is DETECTED."""
        await self._run_tagging_sequence(client, auth_headers("engineer"), session)
        [target] = await _audit_rows(session, audit.APPLICATION_DEPENDENCY_CREATE)
        target.detail = {"after": {"target_ref": "attacker-swapped-ref"}}
        await session.flush()

        result = await verify_chain(session)
        assert not result.ok
        assert result.break_ is not None
        assert result.break_.reason == "entry_hash_mismatch"
        assert result.break_.entry_id == str(target.id)


# ---------------------------------------------------------------------------
# No agent-facing tagging tool ships in P4 (spec "Out" scope)
# ---------------------------------------------------------------------------


class TestNoAgentTaggingTool:
    def test_no_mutating_application_or_tag_tool_is_registered(self) -> None:
        """Walk every ``app.agents.*.tools`` module: any tool touching the
        application/tagging domain must be READ_ONLY (a future tagging tool is
        STATE_CHANGING and CR-gated by the unchanged brief-§5 rule — none may
        ship in P4), and no tagging-mutation tool name may exist at all."""
        import app.agents as agents_pkg
        from app.agents.framework.tools import NetOpsTool, ToolClassification

        tools: list[NetOpsTool] = []
        for module_info in pkgutil.walk_packages(agents_pkg.__path__, prefix="app.agents."):
            if not module_info.name.endswith(".tools"):
                continue
            module = importlib.import_module(module_info.name)
            tools.extend(value for value in vars(module).values() if isinstance(value, NetOpsTool))
        assert tools, "tool walk found no agent tools — the guard would be vacuous"

        mutating_tagging_tools = [
            tool.name
            for tool in tools
            if ("application" in tool.name or "tag" in tool.name.split("_"))
            and tool.classification is not ToolClassification.READ_ONLY
        ]
        assert mutating_tagging_tools == []

        forbidden = {
            "tag_application",
            "create_application",
            "update_application",
            "delete_application",
            "add_application_dependency",
            "remove_application_dependency",
        }
        assert forbidden.isdisjoint({tool.name for tool in tools})


# ---------------------------------------------------------------------------
# Standard rate limiting covers the tagging endpoints (W6-T6 wiring)
# ---------------------------------------------------------------------------


class TestRateLimitWiring:
    @staticmethod
    def _effective_routes(app: FastAPI) -> list[Any]:
        """Flatten the lazy FastAPI 0.137+ include tree into effective routes.

        Mirrors ``tests/api/test_agents_rate_limit_wiring.py`` (ARCH_DEBT #3):
        ``include_router`` no longer flattens child routes onto ``app.routes``
        and the include-time ``dependencies=`` only appear on the *effective*
        view, so the wiring assertion must walk ``effective_candidates()``.
        """
        from fastapi.routing import _EffectiveRouteContext, _IncludedRouter

        def expand(route: object) -> list[Any]:
            if isinstance(route, _IncludedRouter):
                flattened: list[Any] = []
                for candidate in route.effective_candidates():
                    flattened.extend(expand(candidate))
                return flattened
            if isinstance(route, _EffectiveRouteContext):
                return [route.starlette_route if route.starlette_route is not None else route]
            return [route]

        routes: list[Any] = []
        for top in app.routes:
            routes.extend(expand(top))
        return routes

    def test_every_applications_route_carries_the_api_rate_limit(self, app: FastAPI) -> None:
        from app.api.deps import enforce_api_rate_limit

        applications_routes = [
            route
            for route in self._effective_routes(app)
            if getattr(route, "path", "").startswith("/api/v1/applications")
        ]
        assert applications_routes, "no /api/v1/applications routes registered"
        for route in applications_routes:
            assert any(
                dependency.call is enforce_api_rate_limit
                for dependency in route.dependant.dependencies
            ), f"{route.path} is missing the API rate-limit dependency"
