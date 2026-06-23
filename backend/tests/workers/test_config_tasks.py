"""M4-T5 Celery config tasks: capture + nightly fan-out (eager mode).

No Docker, no network, no Postgres: tasks run with ``task_always_eager=True``
against a file-backed aiosqlite database (each task invocation opens its own
event loop via ``asyncio.run``, so the schema must live in a file, not a
per-connection ``:memory:`` database). Plugin, SSH transport, registry, and the
key provider are faked through the module seams in
:mod:`app.workers.tasks.config`.

Verifies the ADR-0017 capture contract end to end: a reachable device's running
config is content-addressed into ``config_snapshots``, an unchanged re-capture
stores no new blob, failures are audited (not raised) so the nightly run
degrades to ``partial``, transient SSH failures retry, and no credential
plaintext ever reaches a result, log, or audit row.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any, ClassVar
from uuid import UUID

import pytest
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.crypto import _StaticKeyProvider
from app.core.errors import PluginError
from app.models import (
    AuditLog,
    Base,
    ConfigSnapshot,
    CredentialKind,
    Device,
    DeviceStatus,
)
from app.plugins.base import Capability, ConfigBackupCapability, VendorPlugin
from app.plugins.registry import PluginRegistry
from app.plugins.transport import SshTransportError
from app.services import credentials as credentials_service
from app.workers.celery_app import celery_app
from app.workers.tasks import config as tasks

VENDOR = "fakeos"
SECRET = "hunter2-super-secret"
RUNNING_CONFIG = "hostname r1\n!\nsnmp-server community PUBLIC_secret RO\nend\n"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class StaticKeyProvider(_StaticKeyProvider):
    """Single static KEK for unit tests (wrap/unwrap KeyProvider protocol)."""

    def __init__(self) -> None:
        super().__init__(b"\x01" * 32, "test-v1")


class FakeSshTransport:
    """Context-managed fake satisfying CommandTransport for one host."""

    def __init__(self, host: str, *, dead: bool, config: str) -> None:
        self.host = host
        self._dead = dead
        self._config = config

    def __enter__(self) -> FakeSshTransport:
        if self._dead:
            raise SshTransportError(f"SSH connect failed for {self.host}:22: TimeoutError")
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def send_command(self, command: str) -> str:
        return self._config


class FakeConfigBackup(ConfigBackupCapability):
    def __init__(self, transport: FakeSshTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def fetch_running_config(self) -> str:
        output = self._transport.send_command("show running-config")
        self._record_raw("show running-config", output)
        if not output.strip():
            raise PluginError("fakeos: empty running-config")
        return output


class FakePlugin(VendorPlugin):
    vendor_id: ClassVar[str] = VENDOR
    display_name: ClassVar[str] = "Fake OS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.CONFIG_BACKUP})

    def _capability_classes(self) -> dict[Capability, type]:
        return {Capability.CONFIG_BACKUP: FakeConfigBackup}


class NoBackupPlugin(VendorPlugin):
    """A vendor with no config-backup capability (permanent failure path)."""

    vendor_id: ClassVar[str] = "nobackup"
    display_name: ClassVar[str] = "No Backup"
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.DISCOVERY_SSH})

    def _capability_classes(self) -> dict[Capability, type]:
        return {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


PROVIDER = StaticKeyProvider()


@pytest.fixture()
def eager_celery() -> Iterator[None]:
    previous = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = previous


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'config.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(tasks, "_make_engine", lambda: create_async_engine(url))
    return url


@pytest.fixture()
def registry() -> PluginRegistry:
    reg = PluginRegistry()
    reg.register(FakePlugin())
    reg.register(NoBackupPlugin())
    return reg


@pytest.fixture()
def wired(
    db_url: str, registry: PluginRegistry, monkeypatch: pytest.MonkeyPatch
) -> dict[str, FakeSshTransport]:
    """Wire all seams; returns a mutable transport-by-host map for injection."""
    transports: dict[str, FakeSshTransport] = {}

    def _open(params: Any) -> FakeSshTransport:
        return transports[params.host]

    monkeypatch.setattr(tasks, "_registry", lambda: registry)
    monkeypatch.setattr(tasks, "_key_provider", lambda: PROVIDER)
    monkeypatch.setattr(tasks, "_open_ssh", _open)
    return transports


def _run_async(coro: Any) -> Any:
    return asyncio.run(coro)


def _seed_device(
    db_url: str,
    *,
    mgmt_ip: str,
    vendor_id: str | None = VENDOR,
    status: DeviceStatus = DeviceStatus.REACHABLE,
    with_credential: bool = True,
    credential_kind: CredentialKind = CredentialKind.SSH,
) -> UUID:
    async def _go() -> UUID:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            credential_id: UUID | None = None
            if with_credential:
                cred = await credentials_service.create_credential(
                    session,
                    PROVIDER,
                    name=f"cred-{mgmt_ip}",
                    kind=credential_kind,
                    username="netops",
                    secret=SECRET,
                    params=None,
                    actor="test",
                )
                credential_id = cred.id
            device = Device(
                hostname=f"host-{mgmt_ip}",
                mgmt_ip=mgmt_ip,
                vendor_id=vendor_id,
                status=status,
                credential_id=credential_id,
            )
            session.add(device)
            await session.commit()
            device_id = device.id
        await engine.dispose()
        return device_id

    return _run_async(_go())


def _fetch_all(db_url: str, orm_cls: type) -> list[Any]:
    async def _go() -> list[Any]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(select(orm_cls))).scalars())
        await engine.dispose()
        return rows

    result: list[Any] = _run_async(_go())
    return result


# ---------------------------------------------------------------------------
# config.capture_device
# ---------------------------------------------------------------------------


def test_capture_stores_content_addressed_snapshot(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.1")
    wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)

    result = tasks.capture_device(str(device_id))

    assert result["ok"] is True
    assert result["created"] is True
    snapshots = _fetch_all(db_url, ConfigSnapshot)
    assert len(snapshots) == 1
    assert snapshots[0].device_id == device_id
    assert snapshots[0].content_hash == result["content_hash"]
    # Verbatim content stored unredacted at rest (ADR-0017).
    assert "PUBLIC_secret" in snapshots[0].content


def test_unchanged_recapture_does_not_store_a_second_blob(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.1")
    wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)

    first = tasks.capture_device(str(device_id))
    second = tasks.capture_device(str(device_id))

    assert first["created"] is True
    assert second["created"] is False
    assert second["content_hash"] == first["content_hash"]
    assert len(_fetch_all(db_url, ConfigSnapshot)) == 1


def test_capture_decryption_is_audited(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.1")
    wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)

    tasks.capture_device(str(device_id))

    actions = {row.action for row in _fetch_all(db_url, AuditLog)}
    assert "credential.decrypted" in actions
    assert "config.snapshot_captured" in actions


def test_unsupported_vendor_is_audited_failure_not_raise(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.9", vendor_id="nobackup")
    wired["10.0.0.9"] = FakeSshTransport("10.0.0.9", dead=False, config=RUNNING_CONFIG)

    result = tasks.capture_device(str(device_id))

    assert result["ok"] is False
    assert len(_fetch_all(db_url, ConfigSnapshot)) == 0
    actions = [row.action for row in _fetch_all(db_url, AuditLog)]
    assert "config.snapshot_failed" in actions


def test_device_without_credential_is_audited_failure(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.8", with_credential=False)

    result = tasks.capture_device(str(device_id))

    assert result["ok"] is False
    actions = [row.action for row in _fetch_all(db_url, AuditLog)]
    assert "config.snapshot_failed" in actions


def test_non_ssh_credential_is_not_capturable(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.7", credential_kind=CredentialKind.SNMP_V2C)

    result = tasks.capture_device(str(device_id))

    assert result["ok"] is False
    assert len(_fetch_all(db_url, ConfigSnapshot)) == 0


def test_transient_ssh_failure_retries_then_fails(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    device_id = _seed_device(db_url, mgmt_ip="10.0.0.2")
    wired["10.0.0.2"] = FakeSshTransport("10.0.0.2", dead=True, config=RUNNING_CONFIG)

    with pytest.raises(SshTransportError):
        tasks.capture_device(str(device_id))


# ---------------------------------------------------------------------------
# config.nightly_backup
# ---------------------------------------------------------------------------


def test_nightly_backup_fans_out_to_reachable_devices(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    d1 = _seed_device(db_url, mgmt_ip="10.0.0.1")
    d2 = _seed_device(db_url, mgmt_ip="10.0.0.2")
    # Unreachable device is excluded from the fan-out target set entirely.
    _seed_device(db_url, mgmt_ip="10.0.0.3", status=DeviceStatus.UNREACHABLE)
    wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)
    wired["10.0.0.2"] = FakeSshTransport("10.0.0.2", dead=False, config="hostname r2\nend\n")

    result = tasks.nightly_backup()

    assert result["status"] == "succeeded"
    assert result["succeeded"] == 2
    assert result["failed"] == 0
    captured_devices = {s.device_id for s in _fetch_all(db_url, ConfigSnapshot)}
    assert captured_devices == {d1, d2}


def test_nightly_backup_degrades_to_partial_on_one_dead_device(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    _seed_device(db_url, mgmt_ip="10.0.0.1")
    _seed_device(db_url, mgmt_ip="10.0.0.2")
    wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)
    wired["10.0.0.2"] = FakeSshTransport("10.0.0.2", dead=True, config=RUNNING_CONFIG)

    result = tasks.nightly_backup()

    assert result["status"] == "partial"
    assert result["succeeded"] == 1
    assert result["failed"] == 1


def test_nightly_backup_with_no_reachable_devices_is_empty(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    result = tasks.nightly_backup()

    assert result["status"] == "empty"
    assert result["succeeded"] == 0
    actions = [row.action for row in _fetch_all(db_url, AuditLog)]
    assert "config.backup_run_started" in actions
    assert "config.backup_run_finished" in actions


def test_nightly_backup_run_is_audited(
    eager_celery: None, db_url: str, wired: dict[str, FakeSshTransport]
) -> None:
    _seed_device(db_url, mgmt_ip="10.0.0.1")
    wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)

    tasks.nightly_backup()

    audit_rows = _fetch_all(db_url, AuditLog)
    actions = [row.action for row in audit_rows]
    assert "config.backup_run_started" in actions
    assert "config.backup_run_finished" in actions


# ---------------------------------------------------------------------------
# secret discipline
# ---------------------------------------------------------------------------


def test_secret_never_leaks_into_results_logs_or_audit(
    eager_celery: None,
    db_url: str,
    wired: dict[str, FakeSshTransport],
) -> None:
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        device_id = _seed_device(db_url, mgmt_ip="10.0.0.1")
        wired["10.0.0.1"] = FakeSshTransport("10.0.0.1", dead=False, config=RUNNING_CONFIG)
        result = tasks.capture_device(str(device_id))
    finally:
        structlog.reset_defaults()

    assert SECRET not in repr(result)
    log_blob = repr(cap.entries)
    assert SECRET not in log_blob
    for row in _fetch_all(db_url, AuditLog):
        assert SECRET not in repr(row.detail)
