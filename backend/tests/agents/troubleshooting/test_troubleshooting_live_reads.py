"""Wired live-read tests for the Troubleshooting Agent tools (2026-07-01 audit, W1).

The audit found the ``_read_live`` credential/transport seam was never wired
after M5 ("TODO(M5)" left behind): every live BGP/OSPF/ACL read returned a
"not yet wired" error and no test covered the wired path. These tests pin the
wired behaviour:

- happy path: bound SSH credential is decrypted (scope-enforced against the
  target device, ADR-0040 §2), a transport is opened from the decrypted
  material, the capability class is instantiated on it, and normalized records
  come back as tool JSON;
- fail-fast ordering: a vendor without the capability never triggers a
  credential decryption (no needless secret-access audit row, ADR-0006);
- typed error paths: missing/bound-but-unusable credential, scope refusal,
  transport failure — all degrade to ``{"error": ...}``, never an exception;
- regression pin: the "not yet wired" sentinel is gone from the module.

No network, no Postgres: in-memory aiosqlite provides inventory rows and the
decrypt / key-provider / transport seams are monkeypatched.
"""

from __future__ import annotations

import inspect
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import TracebackType
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

import app.db as _db
import app.plugins.registry as registry_module
from app.agents.troubleshooting import tools as tools_module
from app.core.errors import CredentialScopeError, PluginError
from app.models import Base, CredentialKind, Device, DeviceCredential
from app.plugins.transport import SshParams, SshTransportError
from app.schemas.normalized import BgpPeerState, NormalizedBgpPeer
from app.services import credentials as credentials_service

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Stands in for the netmiko session handed to the capability."""


@dataclass
class _FakeSshSession:
    """Context manager recorded by the ``_open_ssh`` seam."""

    params: SshParams
    transport: _FakeTransport = field(default_factory=_FakeTransport)

    def __enter__(self) -> _FakeTransport:
        return self.transport

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


def _peer(device_id: uuid.UUID) -> NormalizedBgpPeer:
    return NormalizedBgpPeer(
        device_id=device_id,
        collected_at=datetime(2026, 7, 1, tzinfo=UTC),
        source_vendor="cisco_ios",
        peer_address="10.0.0.2",
        remote_as=65002,
        local_as=65001,
        state=BgpPeerState.IDLE,
    )


class _FakeBgpCapability:
    """Capability double matching the ``impl_cls(transport, device_id)`` shape."""

    instances: list[_FakeBgpCapability] = []

    def __init__(self, transport: Any, device_id: uuid.UUID) -> None:
        self.transport = transport
        self.device_id = device_id
        _FakeBgpCapability.instances.append(self)

    def get_bgp_peers(self) -> list[NormalizedBgpPeer]:
        return [_peer(self.device_id)]


@dataclass
class _FakeRegistry:
    """Registry double: resolves to the fake capability or refuses."""

    refuse_with: PluginError | None = None
    resolved: list[tuple[str, Any]] = field(default_factory=list)

    def resolve(self, vendor_id: str, capability: Any) -> type[_FakeBgpCapability]:
        self.resolved.append((vendor_id, capability))
        if self.refuse_with is not None:
            raise self.refuse_with
        return _FakeBgpCapability


@dataclass
class _DecryptRecorder:
    """Recorded stand-in for ``credentials.decrypt``."""

    plaintext: bytes = b"live-read-secret"
    refuse_with: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(
        self,
        session: Any,
        provider: Any,
        credential: Any,
        *,
        actor: str,
        reason: str,
        target: Any = None,
        sessionmaker: Any = None,
    ) -> Any:
        self.calls.append(
            {
                "credential_id": credential.id,
                "actor": actor,
                "reason": reason,
                "target_id": getattr(target, "id", None),
                "has_autonomous_sessionmaker": sessionmaker is not None,
            }
        )
        if self.refuse_with is not None:
            raise self.refuse_with

        class _Secret:
            plaintext = self.plaintext

        return _Secret()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def seeded(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> tuple[uuid.UUID, uuid.UUID]:
    """Seed one SSH-credentialed cisco_ios device; bind ``app.db`` to the engine.

    Returns ``(device_id, credential_id)``.
    """
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        credential = DeviceCredential(
            name="lab-ssh",
            kind=CredentialKind.SSH,
            username="netops",
            ciphertext=b"\x01",
            nonce=b"\x02",
            wrapped_dek=b"\x03",
            dek_nonce=b"\x04",
            kek_version="v1",
            params={"port": 2222},
        )
        session.add(credential)
        await session.flush()
        device = Device(
            hostname="edge-router-1",
            mgmt_ip="192.0.2.10",
            vendor_id="cisco_ios",
            credential_id=credential.id,
        )
        session.add(device)
        await session.commit()
        device_id, credential_id = device.id, credential.id

    monkeypatch.setattr(_db, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(tools_module, "_key_provider", lambda: object())
    _FakeBgpCapability.instances.clear()
    return device_id, credential_id


@pytest.fixture()
def fake_registry(monkeypatch: pytest.MonkeyPatch) -> _FakeRegistry:
    registry = _FakeRegistry()
    monkeypatch.setattr(registry_module, "get_default_registry", lambda: registry)
    return registry


@pytest.fixture()
def fake_decrypt(monkeypatch: pytest.MonkeyPatch) -> _DecryptRecorder:
    recorder = _DecryptRecorder()
    monkeypatch.setattr(credentials_service, "decrypt", recorder)
    return recorder


@pytest.fixture()
def open_ssh_recorder(monkeypatch: pytest.MonkeyPatch) -> list[SshParams]:
    opened: list[SshParams] = []

    def _fake_open(params: SshParams) -> _FakeSshSession:
        opened.append(params)
        return _FakeSshSession(params)

    monkeypatch.setattr(tools_module, "_open_ssh", _fake_open)
    return opened


# ---------------------------------------------------------------------------
# Wired happy path
# ---------------------------------------------------------------------------


async def test_live_read_opens_credentialed_transport_and_returns_records(
    seeded: tuple[uuid.UUID, uuid.UUID],
    fake_registry: _FakeRegistry,
    fake_decrypt: _DecryptRecorder,
    open_ssh_recorder: list[SshParams],
) -> None:
    device_id, credential_id = seeded

    payload = json.loads(await tools_module.read_live_bgp_peers.ainvoke({"device_id": str(device_id)}))

    assert "error" not in payload
    assert payload["device_id"] == str(device_id)
    assert payload["peers"][0]["peer_address"] == "10.0.0.2"
    assert payload["peers"][0]["state"] == "idle"

    # The transport was opened from the DECRYPTED credential + device inventory.
    assert len(open_ssh_recorder) == 1
    params = open_ssh_recorder[0]
    assert params.host == "192.0.2.10"
    assert params.device_type == "cisco_ios"
    assert params.username == "netops"
    assert params.password == "live-read-secret"
    assert params.port == 2222

    # The capability was instantiated ON the opened transport for this device.
    (instance,) = _FakeBgpCapability.instances
    assert isinstance(instance.transport, _FakeTransport)
    assert instance.device_id == device_id

    # The decryption is audited and scope-enforced against THIS device
    # (ADR-0040 §2: actor/reason recorded, target=the inventory row).
    (call,) = fake_decrypt.calls
    assert call["credential_id"] == credential_id
    assert call["actor"] == "agent:troubleshooting"
    assert call["reason"] == "troubleshooting_live_read"
    assert call["target_id"] == device_id
    assert call["has_autonomous_sessionmaker"] is True


# ---------------------------------------------------------------------------
# Fail-fast ordering: no secret access for a read that can never run
# ---------------------------------------------------------------------------


async def test_missing_capability_fails_before_any_decryption(
    seeded: tuple[uuid.UUID, uuid.UUID],
    fake_registry: _FakeRegistry,
    fake_decrypt: _DecryptRecorder,
    open_ssh_recorder: list[SshParams],
) -> None:
    device_id, _ = seeded
    fake_registry.refuse_with = PluginError("vendor 'cisco_ios' does not implement 'bgp'")

    payload = json.loads(await tools_module.read_live_bgp_peers.ainvoke({"device_id": str(device_id)}))

    assert "does not implement" in payload["error"]
    assert fake_decrypt.calls == []  # capability check precedes secret access
    assert open_ssh_recorder == []


# ---------------------------------------------------------------------------
# Typed error paths
# ---------------------------------------------------------------------------


async def test_device_without_bound_credential_is_typed_error(
    engine: AsyncEngine,
    seeded: tuple[uuid.UUID, uuid.UUID],
    fake_registry: _FakeRegistry,
    fake_decrypt: _DecryptRecorder,
) -> None:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        device = Device(hostname="no-cred", mgmt_ip="192.0.2.11", vendor_id="cisco_ios")
        session.add(device)
        await session.commit()
        orphan_id = device.id

    payload = json.loads(await tools_module.read_live_bgp_peers.ainvoke({"device_id": str(orphan_id)}))

    assert "no bound credential" in payload["error"]
    assert fake_decrypt.calls == []


async def test_non_ssh_credential_is_typed_error(
    engine: AsyncEngine,
    seeded: tuple[uuid.UUID, uuid.UUID],
    fake_registry: _FakeRegistry,
    fake_decrypt: _DecryptRecorder,
) -> None:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        snmp = DeviceCredential(
            name="lab-snmp",
            kind=CredentialKind.SNMP_V2C,
            ciphertext=b"\x01",
            nonce=b"\x02",
            wrapped_dek=b"\x03",
            dek_nonce=b"\x04",
            kek_version="v1",
        )
        session.add(snmp)
        await session.flush()
        device = Device(
            hostname="snmp-only",
            mgmt_ip="192.0.2.12",
            vendor_id="cisco_ios",
            credential_id=snmp.id,
        )
        session.add(device)
        await session.commit()
        snmp_device_id = device.id

    payload = json.loads(await tools_module.read_live_bgp_peers.ainvoke({"device_id": str(snmp_device_id)}))

    assert "no usable SSH credential" in payload["error"]
    assert fake_decrypt.calls == []


async def test_scope_refusal_degrades_to_error_not_exception(
    seeded: tuple[uuid.UUID, uuid.UUID],
    fake_registry: _FakeRegistry,
    fake_decrypt: _DecryptRecorder,
    open_ssh_recorder: list[SshParams],
) -> None:
    device_id, _ = seeded
    fake_decrypt.refuse_with = CredentialScopeError(
        "credential 'lab-ssh' does not cover device 'edge-router-1'"
    )

    payload = json.loads(await tools_module.read_live_bgp_peers.ainvoke({"device_id": str(device_id)}))

    assert payload["error"].startswith("CredentialScopeError:")
    assert open_ssh_recorder == []  # refused before any session was opened


async def test_transport_failure_degrades_to_error_not_exception(
    seeded: tuple[uuid.UUID, uuid.UUID],
    fake_registry: _FakeRegistry,
    fake_decrypt: _DecryptRecorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device_id, _ = seeded

    def _refuse(params: SshParams) -> _FakeSshSession:
        raise SshTransportError("SSH connect to 192.0.2.10:2222 failed (NetmikoTimeoutException)")

    monkeypatch.setattr(tools_module, "_open_ssh", _refuse)

    payload = json.loads(await tools_module.read_live_bgp_peers.ainvoke({"device_id": str(device_id)}))

    assert payload["error"].startswith("SshTransportError:")
    # The decrypted secret never appears in the surfaced error.
    assert "live-read-secret" not in payload["error"]


# ---------------------------------------------------------------------------
# Regression pin: the dead-seam sentinel cannot come back
# ---------------------------------------------------------------------------


def test_not_yet_wired_sentinel_is_gone() -> None:
    """The pre-W1 dead path returned "... not yet wired" on every live read."""
    assert "not yet wired" not in inspect.getsource(tools_module)
