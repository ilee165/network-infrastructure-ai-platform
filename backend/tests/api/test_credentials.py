"""Tests for the credentials API (M1-15): write-only secrets, RBAC, audit.

The KEK provider dependency is overridden with an in-memory static provider so
no NETOPS_KEK configuration (or any external KMS) is needed. The submitted
secret is a sentinel string asserted absent from every response body.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import credentials as credentials_routes
from app.core.crypto import _StaticKeyProvider
from app.models import AuditLog, DeviceCredential
from app.services import credentials as credentials_service

#: Unguessable marker: if this ever shows up in a response body, we leaked.
SECRET_SENTINEL = "SENTINEL-hunter2-3c1f9a"
ROTATED_SENTINEL = "SENTINEL-rotated-77e0bd"


class _StaticProvider(_StaticKeyProvider):
    """Minimal wrap/unwrap KeyProvider: one fixed 32-byte KEK, version ``test-v1``."""

    def __init__(self) -> None:
        super().__init__(b"\x42" * 32, "test-v1")


@pytest.fixture()
def key_provider(app: FastAPI) -> _StaticProvider:
    provider = _StaticProvider()
    app.dependency_overrides[credentials_routes.get_key_provider] = lambda: provider
    return provider


def _payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "lab-ssh",
        "kind": "ssh",
        "username": "netops",
        "secret": SECRET_SENTINEL,
        "params": {"port": 22},
    }
    body.update(overrides)
    return body


async def _create_credential(
    client: httpx.AsyncClient, headers: dict[str, str], **overrides: Any
) -> dict[str, Any]:
    response = await client.post("/api/v1/credentials", json=_payload(**overrides), headers=headers)
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


class TestCredentialCreate:
    async def test_engineer_creates_credential(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        session: AsyncSession,
    ) -> None:
        response = await client.post(
            "/api/v1/credentials", json=_payload(), headers=auth_headers("engineer")
        )
        assert response.status_code == 201, response.text
        assert SECRET_SENTINEL not in response.text
        body = response.json()
        assert body["name"] == "lab-ssh"
        assert body["kind"] == "ssh"
        assert body["username"] == "netops"
        assert body["params"] == {"port": 22}
        assert body["kek_version"] == "test-v1"
        assert uuid.UUID(body["id"])
        assert "created_at" in body and "updated_at" in body
        # The contract is structural too: no secret-bearing keys at all.
        forbidden = {"secret", "ciphertext", "nonce", "wrapped_dek", "dek_nonce"}
        assert forbidden.isdisjoint(body.keys())

    async def test_secret_round_trips_through_vault(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        session: AsyncSession,
    ) -> None:
        created = await _create_credential(client, auth_headers("engineer"))
        row = await session.get(DeviceCredential, uuid.UUID(created["id"]))
        assert row is not None
        decrypted = await credentials_service.decrypt(
            session, key_provider, row, actor="test", reason="round-trip assertion"
        )
        assert decrypted.plaintext == SECRET_SENTINEL.encode()

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        role: str,
    ) -> None:
        response = await client.post(
            "/api/v1/credentials", json=_payload(), headers=auth_headers(role)
        )
        assert response.status_code == 403

    async def test_unauthenticated_is_401(
        self, client: httpx.AsyncClient, key_provider: _StaticProvider
    ) -> None:
        response = await client.post("/api/v1/credentials", json=_payload())
        assert response.status_code == 401

    async def test_duplicate_name_is_409(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        headers = auth_headers("engineer")
        await _create_credential(client, headers)
        response = await client.post("/api/v1/credentials", json=_payload(), headers=headers)
        assert response.status_code == 409
        assert SECRET_SENTINEL not in response.text

    async def test_audit_row_written_without_secret(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        session: AsyncSession,
    ) -> None:
        created = await _create_credential(client, auth_headers("engineer"))
        row = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "credential.created")))
            .scalars()
            .one()
        )
        assert row.actor == "user:engineer_user"
        assert row.target_type == "credential"
        assert row.target_id == created["id"]
        assert SECRET_SENTINEL not in str(row.detail)


class TestCredentialList:
    async def test_viewer_lists_without_secrets(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        engineer = auth_headers("engineer")
        await _create_credential(client, engineer)
        await _create_credential(
            client, engineer, name="lab-snmp", kind="snmp_v2c", username=None, params=None
        )
        response = await client.get("/api/v1/credentials", headers=auth_headers("viewer"))
        assert response.status_code == 200
        assert SECRET_SENTINEL not in response.text
        body = response.json()
        assert body["total"] == 2
        assert [item["name"] for item in body["items"]] == ["lab-snmp", "lab-ssh"]
        for item in body["items"]:
            assert "secret" not in item

    async def test_pagination(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        engineer = auth_headers("engineer")
        for index in range(3):
            await _create_credential(client, engineer, name=f"cred-{index:02d}")
        response = await client.get(
            "/api/v1/credentials", params={"limit": 1, "offset": 2}, headers=engineer
        )
        body = response.json()
        assert body["total"] == 3
        assert [item["name"] for item in body["items"]] == ["cred-02"]

    async def test_unauthenticated_is_401(
        self, client: httpx.AsyncClient, key_provider: _StaticProvider
    ) -> None:
        response = await client.get("/api/v1/credentials")
        assert response.status_code == 401


class TestCredentialRotate:
    async def test_engineer_rotates_secret(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        session: AsyncSession,
    ) -> None:
        created = await _create_credential(client, auth_headers("engineer"))
        response = await client.post(
            f"/api/v1/credentials/{created['id']}/rotate",
            json={"secret": ROTATED_SENTINEL},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 200, response.text
        assert ROTATED_SENTINEL not in response.text
        assert SECRET_SENTINEL not in response.text
        assert response.json()["id"] == created["id"]

        row = await session.get(DeviceCredential, uuid.UUID(created["id"]))
        assert row is not None
        decrypted = await credentials_service.decrypt(
            session, key_provider, row, actor="test", reason="rotation assertion"
        )
        assert decrypted.plaintext == ROTATED_SENTINEL.encode()

        actions = [r.action for r in (await session.execute(select(AuditLog))).scalars().all()]
        assert "credential.rotated" in actions

    async def test_rotate_unknown_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        response = await client.post(
            f"/api/v1/credentials/{uuid.uuid4()}/rotate",
            json={"secret": ROTATED_SENTINEL},
            headers=auth_headers("engineer"),
        )
        assert response.status_code == 404
        assert ROTATED_SENTINEL not in response.text

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_rotate_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        role: str,
    ) -> None:
        created = await _create_credential(client, auth_headers("engineer"))
        response = await client.post(
            f"/api/v1/credentials/{created['id']}/rotate",
            json={"secret": ROTATED_SENTINEL},
            headers=auth_headers(role),
        )
        assert response.status_code == 403


class TestRotationStatus:
    """KEK rotation-status endpoint (W6-T3): versions/counts only, engineer+ RBAC."""

    async def test_engineer_reads_versions_and_counts_only(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        await _create_credential(client, auth_headers("engineer"))
        response = await client.get(
            "/api/v1/credentials/rotation-status", headers=auth_headers("engineer")
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # The active provider version matches every freshly-created row → zero pending.
        assert body == {"from_version": None, "to_version": "test-v1", "rows_pending": 0}
        # Structural no-blob contract: never a wrapped_dek / per-row kek_version field.
        forbidden = {"wrapped_dek", "dek_nonce", "ciphertext", "nonce", "kek_version"}
        assert forbidden.isdisjoint(body.keys())

    async def test_empty_corpus_reports_zero_pending(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
    ) -> None:
        response = await client.get(
            "/api/v1/credentials/rotation-status", headers=auth_headers("admin")
        )
        assert response.status_code == 200
        assert response.json() == {
            "from_version": None,
            "to_version": "test-v1",
            "rows_pending": 0,
        }

    @pytest.mark.parametrize("role", ["viewer", "operator"])
    async def test_below_engineer_is_403(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        key_provider: _StaticProvider,
        role: str,
    ) -> None:
        response = await client.get(
            "/api/v1/credentials/rotation-status", headers=auth_headers(role)
        )
        assert response.status_code == 403

    async def test_unauthenticated_is_401(
        self, client: httpx.AsyncClient, key_provider: _StaticProvider
    ) -> None:
        response = await client.get("/api/v1/credentials/rotation-status")
        assert response.status_code == 401
