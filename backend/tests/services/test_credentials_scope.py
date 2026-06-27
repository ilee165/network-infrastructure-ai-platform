"""Per-credential scope enforcement at session open (ADR-0040 §2).

The structural least-privilege deny: a SCOPED device credential may only open a
session against a device its scope (site / role / device-group) covers. The check
runs BEFORE any KEK unwrap, audits ``credential.scope_denied`` (ids only — never
the scope values / device attributes / secret), and raises ``CredentialScopeError``.

Runs entirely on in-memory aiosqlite — no Docker, no network. The plaintext
sentinel below must never appear in any audit ``detail`` row or captured log event.
"""

from __future__ import annotations

import base64
import os

import pytest
import structlog.testing
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import KEY_BYTES, EnvKeyProvider
from app.core.errors import CredentialScopeError, ForbiddenError
from app.models import AuditLog
from app.models.inventory import CredentialKind, Device, DeviceCredential, DeviceStatus
from app.services.credentials import service as vault

_SECRET = "sc0pe-Sup3rS3cret!"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


def _provider(version: str = "v1") -> EnvKeyProvider:
    kek = base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")
    return EnvKeyProvider(_settings(kek=kek, kek_version=version))


async def _create(
    session: AsyncSession,
    provider: EnvKeyProvider,
    *,
    name: str = "scoped-ssh",
    scope_site: str | None = None,
    scope_role: str | None = None,
    scope_device_group: str | None = None,
) -> DeviceCredential:
    credential = await vault.create_credential(
        session,
        provider,
        name=name,
        kind=CredentialKind.SSH,
        username="netops",
        secret=_SECRET,
        params={"port": 22},
        actor="user:alice",
    )
    credential.scope_site = scope_site
    credential.scope_role = scope_role
    credential.scope_device_group = scope_device_group
    await session.flush()
    return credential


def _device(
    *,
    hostname: str = "core-1",
    mgmt_ip: str = "10.0.0.1",
    site: str | None = None,
    role: str | None = None,
    device_group: str | None = None,
) -> Device:
    return Device(
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        status=DeviceStatus.NEW,
        site=site,
        role=role,
        device_group=device_group,
    )


async def _scope_denied_rows(session: AsyncSession) -> list[AuditLog]:
    result = await session.execute(
        select(AuditLog).where(AuditLog.action == "credential.scope_denied")
    )
    return list(result.scalars())


# ---------------------------------------------------------------------------
# Unscoped credential — covers everything (backward compatible)
# ---------------------------------------------------------------------------


async def test_unscoped_credential_covers_any_device(session: AsyncSession) -> None:
    """An all-NULL-scope credential opens a session against any device (and no target)."""
    provider = _provider()
    credential = await _create(session, provider)
    assert credential.is_scoped is False

    target = _device(site="nyc", role="core")
    session.add(target)
    await session.flush()

    decrypted = await vault.decrypt(
        session, provider, credential, actor="system:config", reason="ssh", target=target
    )
    assert decrypted.plaintext == _SECRET.encode()

    # No target at all is fine for an unscoped credential.
    again = await vault.decrypt(session, provider, credential, actor="system:config", reason="ssh")
    assert again.plaintext == _SECRET.encode()


# ---------------------------------------------------------------------------
# Scoped credential — in-scope succeeds, out-of-scope is refused
# ---------------------------------------------------------------------------


async def test_in_scope_device_session_open_succeeds(session: AsyncSession) -> None:
    """A credential scoped to a site/role opens a session on a matching device."""
    provider = _provider()
    credential = await _create(session, provider, scope_site="nyc", scope_role="core")
    assert credential.is_scoped is True

    target = _device(site="nyc", role="core", device_group="dc-a")
    session.add(target)
    await session.flush()

    decrypted = await vault.decrypt(
        session, provider, credential, actor="system:config", reason="ssh", target=target
    )
    assert decrypted.plaintext == _SECRET.encode()


async def test_out_of_scope_device_session_open_raises(session: AsyncSession) -> None:
    """A scoped credential refuses a device its scope does not cover (structural deny)."""
    provider = _provider()
    credential = await _create(session, provider, scope_site="nyc")

    target = _device(mgmt_ip="10.9.9.9", site="lon")  # wrong site
    session.add(target)
    await session.flush()

    with pytest.raises(CredentialScopeError) as excinfo:
        await vault.decrypt(
            session, provider, credential, actor="user:mallory", reason="ssh", target=target
        )
    # 403 family, and the boundary values never leak in the message.
    assert isinstance(excinfo.value, ForbiddenError)
    assert excinfo.value.status_code == 403
    assert "nyc" not in str(excinfo.value)
    assert "lon" not in str(excinfo.value)


async def test_scoped_credential_with_no_target_is_refused(session: AsyncSession) -> None:
    """Fail-closed: a scoped credential is never materialized without a proven target."""
    provider = _provider()
    credential = await _create(session, provider, scope_role="firewall")

    with pytest.raises(CredentialScopeError):
        await vault.decrypt(session, provider, credential, actor="system:x", reason="ssh")


async def test_set_dimension_against_absent_device_attr_denies(session: AsyncSession) -> None:
    """A SET scope dimension never matches a device that omits that attribute (fail-closed)."""
    provider = _provider()
    credential = await _create(session, provider, scope_device_group="dc-a")

    target = _device(site="nyc", role="core")  # no device_group on the device
    session.add(target)
    await session.flush()

    with pytest.raises(CredentialScopeError):
        await vault.decrypt(
            session, provider, credential, actor="system:x", reason="ssh", target=target
        )


# ---------------------------------------------------------------------------
# Deny audit — ids only, no key access, no leak
# ---------------------------------------------------------------------------


async def test_scope_deny_audits_ids_only_and_does_no_key_access(session: AsyncSession) -> None:
    """The deny audits credential.scope_denied (ids only) and emits NO kek.unwrap row."""
    provider = _provider()
    credential = await _create(session, provider, scope_site="nyc", name="audit-scoped")

    target = _device(mgmt_ip="10.5.5.5", site="sfo")
    session.add(target)
    await session.flush()

    with structlog.testing.capture_logs() as captured, pytest.raises(CredentialScopeError):
        await vault.decrypt(
            session, provider, credential, actor="user:bob", reason="ssh", target=target
        )

    deny_rows = await _scope_denied_rows(session)
    assert len(deny_rows) == 1
    row = deny_rows[0]
    assert row.target_type == "credential"
    assert row.target_id == str(credential.id)
    assert row.detail is not None
    assert row.detail.get("device_id") == str(target.id)
    # The scope values + the secret never appear in the audit detail or the logs.
    assert "nyc" not in str(row.detail)
    assert "sfo" not in str(row.detail)
    assert _SECRET not in str(row.detail)
    assert _SECRET not in str(captured)

    # A denied target performs NO key access: no kek.unwrap / credential.decrypted row.
    unwrap = await session.execute(select(AuditLog).where(AuditLog.action == "kek.unwrap"))
    assert list(unwrap.scalars()) == []
    decrypted = await session.execute(
        select(AuditLog).where(AuditLog.action == "credential.decrypted")
    )
    assert list(decrypted.scalars()) == []
