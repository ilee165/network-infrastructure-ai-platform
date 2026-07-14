"""Device conflict diagnostics exercised through the API on real PostgreSQL."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.config import Settings
from app.core.security import create_access_token
from app.models import AuditLog, Device, Role, User
from app.services import audit
from app.services.devices import DeviceService

pytestmark = pytest.mark.integration

BASE = "/api/v1/devices"
_DUPLICATE_IP = "192.0.2.44"


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="pg-device-harness-signing-key-000000",
        access_token_expire_minutes=5,
    )


@pytest.fixture()
async def engineer(pg_session: AsyncSession) -> User:
    role = (await pg_session.execute(select(Role).where(Role.name == "engineer"))).scalar_one()
    user = User(
        username=f"pg-device-eng-{uuid.uuid4().hex[:8]}",
        password_hash="not-used-by-token-harness",
        role_id=role.id,
    )
    pg_session.add(user)
    await pg_session.commit()
    return user


@pytest.fixture()
async def client(settings: Settings, pg_session: AsyncSession) -> AsyncIterator[httpx.AsyncClient]:
    from app.main import create_app

    application = create_app(settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield pg_session

    application.dependency_overrides[deps.get_db] = _override_db
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as test_client:
        yield test_client


def _headers(user: User, settings: Settings) -> dict[str, str]:
    token = create_access_token(
        str(user.id),
        settings,
        extra_claims={"type": "access", "roles": ["engineer"]},
    )
    return {"Authorization": f"Bearer {token}"}


async def test_create_duplicate_mgmt_ip_real_asyncpg_violation_is_409(
    client: httpx.AsyncClient,
    pg_session: AsyncSession,
    engineer: User,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A race past the pre-check maps asyncpg's real named violation to 409."""
    existing = Device(hostname="existing-pg-device", mgmt_ip=_DUPLICATE_IP)
    pg_session.add(existing)
    await pg_session.commit()

    precheck_calls: list[str] = []

    async def _bypass_precheck(
        _service: DeviceService,
        mgmt_ip: str,
        *,
        exclude_id: uuid.UUID | None = None,
    ) -> None:
        assert exclude_id is None
        precheck_calls.append(mgmt_ip)

    monkeypatch.setattr(DeviceService, "_ensure_mgmt_ip_free", _bypass_precheck)

    from app.services import devices as devices_service

    classify = devices_service._is_mgmt_ip_unique_violation
    observed: list[IntegrityError] = []

    def _observe_real_exception(exc: IntegrityError) -> bool:
        observed.append(exc)
        return classify(exc)

    monkeypatch.setattr(devices_service, "_is_mgmt_ip_unique_violation", _observe_real_exception)

    response = await client.post(
        BASE,
        json={"hostname": "racing-pg-device", "mgmt_ip": _DUPLICATE_IP},
        headers=_headers(engineer, settings),
    )

    assert precheck_calls == [_DUPLICATE_IP]
    assert response.status_code == 409, response.text
    assert response.json()["type"] == "urn:netops:error:conflict"

    [integrity_error] = observed
    adapter_error = integrity_error.orig
    assert getattr(adapter_error, "sqlstate", None) == "23505"
    driver_error = adapter_error.__cause__
    assert driver_error is not None
    assert type(driver_error).__module__.startswith("asyncpg")
    assert getattr(driver_error, "constraint_name", None) == "uq_devices_mgmt_ip"

    pg_session.expire_all()
    devices = list((await pg_session.scalars(select(Device))).all())
    assert [(row.hostname, row.mgmt_ip) for row in devices] == [
        ("existing-pg-device", _DUPLICATE_IP)
    ]
    assert (
        list(
            (
                await pg_session.scalars(
                    select(AuditLog).where(AuditLog.action == audit.DEVICE_CREATED)
                )
            ).all()
        )
        == []
    )
