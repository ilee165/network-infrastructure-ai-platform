"""M1-14 Celery discovery tasks: fan-out, retries, run lifecycle (eager mode).

No Docker, no network, no Postgres: tasks run with ``task_always_eager=True``
against a file-backed aiosqlite database (each task invocation opens its own
event loop via ``asyncio.run``, so the shared schema must live in a file, not
in a per-connection ``:memory:`` database). Plugins, transports, registry and
the key provider are faked through the module seams in
:mod:`app.workers.tasks.discovery`.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, ClassVar
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.crypto import _StaticKeyProvider
from app.core.errors import PluginError
from app.models import (
    Base,
    CredentialKind,
    Device,
    DeviceStatus,
    DiscoveryRun,
    DiscoveryRunStatus,
    NormalizedNeighborRow,
    RawArtifact,
)
from app.plugins.base import (
    Capability,
    DiscoverySnmpCapability,
    DiscoverySshCapability,
    NeighborsCapability,
    VendorPlugin,
)
from app.plugins.registry import PluginRegistry
from app.plugins.transport import SshTransportError
from app.schemas.discovery import DeviceFacts
from app.schemas.normalized import NeighborProtocol, NormalizedNeighbor
from app.services import credentials as credentials_service
from app.workers.celery_app import celery_app
from app.workers.tasks import discovery as tasks

VENDOR = "fakeos"


# ---------------------------------------------------------------------------
# Fakes: key provider, transports, plugin
# ---------------------------------------------------------------------------


class StaticKeyProvider(_StaticKeyProvider):
    """Single static KEK for unit tests (wrap/unwrap KeyProvider protocol)."""

    def __init__(self) -> None:
        super().__init__(b"\x01" * 32, "test-v1")


@dataclass
class FakeEnv:
    """Mutable test topology + failure injection, shared with the fakes."""

    #: host -> neighbor management IPs reported over LLDP.
    topology: dict[str, list[str]] = field(default_factory=dict)
    #: hosts whose `show version` output is unparseable (permanent failure).
    fail_facts: set[str] = field(default_factory=set)
    #: host -> queue of exceptions raised on SSH connect (consumed in order).
    connect_failures: dict[str, list[Exception]] = field(default_factory=dict)
    #: hosts where every SSH connect always fails (transient transport error).
    ssh_dead: set[str] = field(default_factory=set)
    #: number of SSH connect attempts per host.
    ssh_attempts: dict[str, int] = field(default_factory=dict)
    #: hosts reachable over SNMP.
    snmp_alive: set[str] = field(default_factory=set)


class FakeSshTransport:
    """Context-managed fake satisfying CommandTransport, driven by FakeEnv."""

    def __init__(self, env: FakeEnv, host: str) -> None:
        self.env = env
        self.host = host

    def __enter__(self) -> FakeSshTransport:
        self.env.ssh_attempts[self.host] = self.env.ssh_attempts.get(self.host, 0) + 1
        if self.host in self.env.ssh_dead:
            raise SshTransportError(f"SSH connect failed for {self.host}:22: TimeoutError")
        queued = self.env.connect_failures.get(self.host)
        if queued:
            raise queued.pop(0)
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def send_command(self, command: str) -> str:
        if command == "show version" and self.host in self.env.fail_facts:
            return "GARBAGE"
        return f"{command} from {self.host}"


class FakeSnmpClient:
    """Fake satisfying SnmpReadTransport, driven by FakeEnv."""

    def __init__(self, env: FakeEnv, host: str) -> None:
        self.env = env
        self.host = host

    def get(self, oids: Any) -> dict[str, str]:
        if self.host not in self.env.snmp_alive:
            raise tasks.SnmpTransportError(
                f"SNMP transport failure for {self.host}:161: TimeoutError"
            )
        return {str(oid): f"value-from-{self.host}" for oid in oids}


class FakeDiscoverySsh(DiscoverySshCapability):
    def __init__(self, transport: FakeSshTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def get_device_facts(self) -> DeviceFacts:
        output = self._transport.send_command("show version")
        self._record_raw("show version", output)
        if output == "GARBAGE":
            raise PluginError("fakeos: cannot parse 'show version' output")
        return DeviceFacts(hostname=f"host-{self._transport.host}", vendor_id=VENDOR)


class FakeDiscoverySnmp(DiscoverySnmpCapability):
    def __init__(self, snmp: FakeSnmpClient, device_id: UUID) -> None:
        super().__init__()
        self._snmp = snmp
        self._device_id = device_id

    def get_device_facts(self) -> DeviceFacts:
        values = self._snmp.get(["1.3.6.1.2.1.1.5.0"])
        self._record_raw("SNMP GET 1.3.6.1.2.1.1.5.0", str(values))
        return DeviceFacts(hostname=f"snmp-{self._snmp.host}", vendor_id=VENDOR)


class FakeNeighbors(NeighborsCapability):
    def __init__(self, transport: FakeSshTransport, device_id: UUID) -> None:
        super().__init__()
        self._transport = transport
        self._device_id = device_id

    def get_lldp_neighbors(self) -> list[NormalizedNeighbor]:
        output = self._transport.send_command("show lldp neighbors detail")
        self._record_raw("show lldp neighbors detail", output)
        host = self._transport.host
        return [
            NormalizedNeighbor(
                device_id=self._device_id,
                collected_at=datetime.now(UTC),
                source_vendor=VENDOR,
                protocol=NeighborProtocol.LLDP,
                local_interface=f"Ethernet{index}",
                neighbor_name=f"host-{address}",
                neighbor_address=ip_address(address),
            )
            for index, address in enumerate(self._transport.env.topology.get(host, []), start=1)
        ]

    def get_cdp_neighbors(self) -> list[NormalizedNeighbor]:  # pragma: no cover
        return []


class FakePlugin(VendorPlugin):
    vendor_id: ClassVar[str] = VENDOR
    display_name: ClassVar[str] = "Fake OS"
    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.DISCOVERY_SSH, Capability.DISCOVERY_SNMP, Capability.NEIGHBORS_LLDP}
    )

    def _capability_classes(self) -> dict[Capability, type]:
        return {
            Capability.DISCOVERY_SSH: FakeDiscoverySsh,
            Capability.DISCOVERY_SNMP: FakeDiscoverySnmp,
            Capability.NEIGHBORS_LLDP: FakeNeighbors,
        }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


PROVIDER = StaticKeyProvider()


@pytest.fixture()
def eager_celery() -> Iterator[None]:
    """Run all task dispatch synchronously in-process."""
    previous = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = previous


@pytest.fixture()
def env() -> FakeEnv:
    return FakeEnv()


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    """File-backed aiosqlite DB with the schema created; engine seam patched."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'discovery.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(tasks, "_make_engine", lambda: create_async_engine(url))
    return url


@pytest.fixture()
def fakes(env: FakeEnv, db_url: str, monkeypatch: pytest.MonkeyPatch) -> FakeEnv:
    """Wire all module seams: registry, transports, key provider."""
    registry = PluginRegistry()
    registry.register(FakePlugin())
    monkeypatch.setattr(tasks, "_registry", lambda: registry)
    monkeypatch.setattr(tasks, "_key_provider", lambda: PROVIDER)
    monkeypatch.setattr(tasks, "_open_ssh", lambda params: FakeSshTransport(env, params.host))
    monkeypatch.setattr(tasks, "_make_snmp_client", lambda params: FakeSnmpClient(env, params.host))
    # Neutralize the post-run topology projection by default so eager-mode runs
    # never reach a real Postgres/Neo4j; the dispatch-trigger test re-patches
    # send_task with its own spy on top of this no-op.
    monkeypatch.setattr(celery_app, "send_task", lambda *a, **k: None)
    return env


def _run_async(coro: Any) -> Any:
    return asyncio.run(coro)


def _seed_run(
    db_url: str,
    *,
    seeds: list[str],
    hop_limit: int,
    allowlist: list[str],
    credentials: list[dict[str, Any]],
) -> uuid.UUID:
    """Create credentials + a pending DiscoveryRun; returns the run id."""

    async def _go() -> uuid.UUID:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            for spec in credentials:
                await credentials_service.create_credential(
                    session,
                    PROVIDER,
                    name=spec["name"],
                    kind=spec["kind"],
                    username=spec.get("username", "netops"),
                    secret=spec.get("secret", "hunter2-secret"),
                    params=spec.get("params"),
                    actor="test",
                )
            run = DiscoveryRun(
                seeds=seeds,
                hop_limit=hop_limit,
                allowlist=allowlist,
                credential_names=[spec["name"] for spec in credentials],
            )
            session.add(run)
            await session.commit()
            run_id = run.id
        await engine.dispose()
        return run_id

    return _run_async(_go())


def _fetch_run(db_url: str, run_id: uuid.UUID) -> DiscoveryRun:
    async def _go() -> DiscoveryRun:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            run = await session.get(DiscoveryRun, run_id)
            assert run is not None
        await engine.dispose()
        return run

    result: DiscoveryRun = _run_async(_go())
    return result


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


SSH_CRED = {"name": "lab-ssh", "kind": CredentialKind.SSH, "secret": "hunter2-secret"}


# ---------------------------------------------------------------------------
# discovery.run lifecycle
# ---------------------------------------------------------------------------


def test_run_succeeds_and_expands_waves_within_hop_limit(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    # 10.0.0.1 -> {.2, .3}; .2 -> {.1 (visited), .4 outside allowlist}; .3 leaf.
    fakes.topology = {
        "10.0.0.1": ["10.0.0.2", "10.0.0.3"],
        "10.0.0.2": ["10.0.0.1", "192.168.99.9"],
        "10.0.0.3": [],
    }
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=2,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    outcome = tasks.run_discovery.apply(args=[str(run_id)]).get()

    assert outcome["status"] == DiscoveryRunStatus.SUCCEEDED.value
    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.SUCCEEDED
    assert run.started_at is not None and run.finished_at is not None
    assert run.error is None

    waves = run.stats["waves"]
    assert [wave["targets"] for wave in waves] == [["10.0.0.1"], ["10.0.0.2", "10.0.0.3"]]
    assert run.stats["devices_succeeded"] == 3
    assert run.stats["devices_failed"] == 0

    devices = _fetch_all(db_url, Device)
    assert sorted(d.mgmt_ip for d in devices) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert all(d.status is DeviceStatus.REACHABLE for d in devices)
    # Raw evidence + normalized neighbors persisted (M1-13 path was exercised).
    assert _fetch_all(db_url, RawArtifact)
    assert _fetch_all(db_url, NormalizedNeighborRow)


def test_hop_limit_zero_collects_seeds_only(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.topology = {"10.0.0.1": ["10.0.0.2"], "10.0.0.2": []}
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    tasks.run_discovery.apply(args=[str(run_id)]).get()

    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.SUCCEEDED
    assert len(run.stats["waves"]) == 1
    devices = _fetch_all(db_url, Device)
    assert [d.mgmt_ip for d in devices] == ["10.0.0.1"]


def test_partial_status_when_some_devices_fail(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.topology = {"10.0.0.1": ["10.0.0.2"], "10.0.0.2": []}
    fakes.fail_facts = {"10.0.0.2"}  # reachable but unrecognizable: permanent
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=1,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    outcome = tasks.run_discovery.apply(args=[str(run_id)]).get()

    assert outcome["status"] == DiscoveryRunStatus.PARTIAL.value
    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.PARTIAL
    assert run.stats["devices_succeeded"] == 1
    assert run.stats["devices_failed"] == 1
    assert run.finished_at is not None


def test_failed_status_when_no_device_succeeds(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.fail_facts = {"10.0.0.1"}
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=1,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    outcome = tasks.run_discovery.apply(args=[str(run_id)]).get()

    assert outcome["status"] == DiscoveryRunStatus.FAILED.value
    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.FAILED
    assert run.finished_at is not None


def test_topology_sync_enqueued_on_success_not_on_failure(
    eager_celery: None, fakes: FakeEnv, db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The topology projection is dispatched only when devices were discovered."""
    enqueued: list[tuple[str, list[Any]]] = []
    monkeypatch.setattr(
        celery_app,
        "send_task",
        lambda name, args=None, **kw: enqueued.append((name, args)),
    )

    ok_cred = {"name": "topo-ok-ssh", "kind": CredentialKind.SSH, "secret": "hunter2-secret"}
    bad_cred = {"name": "topo-bad-ssh", "kind": CredentialKind.SSH, "secret": "hunter2-secret"}

    # Success: one device, no expansion.
    fakes.topology = {"10.0.0.1": []}
    ok_run = _seed_run(
        db_url, seeds=["10.0.0.1"], hop_limit=0, allowlist=["10.0.0.0/24"], credentials=[ok_cred]
    )
    tasks.run_discovery.apply(args=[str(ok_run)]).get()
    assert enqueued == [("topology.sync_after_run", [str(ok_run)])]

    # Failure: the only seed is unrecognizable -> FAILED, no topology sync.
    enqueued.clear()
    fakes.fail_facts = {"10.0.0.9"}
    failed_run = _seed_run(
        db_url, seeds=["10.0.0.9"], hop_limit=0, allowlist=["10.0.0.0/24"], credentials=[bad_cred]
    )
    tasks.run_discovery.apply(args=[str(failed_run)]).get()
    assert enqueued == []


def test_invalid_plan_marks_run_failed(eager_celery: None, fakes: FakeEnv, db_url: str) -> None:
    run_id = _seed_run(
        db_url,
        seeds=["192.168.1.1"],  # outside the allowlist -> invalid plan
        hop_limit=1,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    outcome = tasks.run_discovery.apply(args=[str(run_id)]).get()

    assert outcome["status"] == DiscoveryRunStatus.FAILED.value
    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.FAILED
    assert run.error is not None
    assert run.finished_at is not None


def test_status_running_persisted_before_first_wave(
    eager_celery: None, fakes: FakeEnv, db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fakes.topology = {"10.0.0.1": []}
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    observed: list[DiscoveryRunStatus] = []
    original = tasks._enqueue_discovery_wave

    def _spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        observed.append(_fetch_run(db_url, run_id).status)
        return original(*args, **kwargs)

    monkeypatch.setattr(tasks, "_enqueue_discovery_wave", _spy)
    tasks.run_discovery.apply(args=[str(run_id)]).get()

    assert observed == [DiscoveryRunStatus.RUNNING]


# ---------------------------------------------------------------------------
# discovery.collect_device: retries + SNMP fallback
# ---------------------------------------------------------------------------


def test_collect_device_retries_transient_ssh_failure(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.topology = {"10.0.0.1": []}
    fakes.connect_failures = {
        "10.0.0.1": [
            SshTransportError("SSH connect failed for 10.0.0.1:22: TimeoutError"),
        ]
    }
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    result = tasks.collect_device.apply(args=[str(run_id), "10.0.0.1"])

    assert result.state == "SUCCESS"
    payload = result.get()
    assert payload["ok"] is True
    assert fakes.ssh_attempts["10.0.0.1"] == 2  # first transient failure + retry
    devices = _fetch_all(db_url, Device)
    assert [d.mgmt_ip for d in devices] == ["10.0.0.1"]


def test_collect_device_gives_up_after_max_retries(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.ssh_dead = {"10.0.0.1"}
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    result = tasks.collect_device.apply(args=[str(run_id), "10.0.0.1"])

    # Wave 5: after retries exhausted, return ok=False (chord-safe) rather than
    # FAILURE so a discovery wave chord can still complete with partial results.
    assert result.state == "SUCCESS"
    payload = result.get()
    assert payload["ok"] is False
    assert "SshTransportError" in payload["error"]
    # initial attempt + max_retries(2) retries
    assert fakes.ssh_attempts["10.0.0.1"] == 3
    assert tasks.collect_device.max_retries == 2


def test_collect_device_snmp_fallback_when_ssh_fails(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.ssh_dead = {"10.0.0.1"}
    fakes.snmp_alive = {"10.0.0.1"}
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[
            SSH_CRED,
            {
                "name": "lab-snmp",
                "kind": CredentialKind.SNMP_V2C,
                "secret": "public-community",
            },
        ],
    )

    payload = tasks.collect_device.apply(args=[str(run_id), "10.0.0.1"]).get()

    assert payload["ok"] is True
    assert payload["vendor_id"] == VENDOR
    devices = _fetch_all(db_url, Device)
    assert [d.hostname for d in devices] == ["snmp-10.0.0.1"]


def test_collect_device_snmp_not_triggered_when_ssh_connects_but_facts_fail(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    """SNMP must NOT fire when SSH connected successfully but vendor recognition failed.

    The design decision is: SNMP is a *transport* fallback, used only when SSH
    never connects.  If SSH establishes a session (outcome.connected=True) but
    the plugin cannot parse 'show version', the device should be reported as a
    permanent failure rather than falling back to SNMP.
    """
    fakes.fail_facts = {"10.0.0.1"}  # SSH connects; facts are unparseable
    fakes.snmp_alive = {"10.0.0.1"}  # SNMP would succeed — must NOT be called
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[
            SSH_CRED,
            {
                "name": "lab-snmp",
                "kind": CredentialKind.SNMP_V2C,
                "secret": "public-community",
            },
        ],
    )

    result = tasks.collect_device.apply(args=[str(run_id), "10.0.0.1"])

    assert result.state == "SUCCESS"
    payload = result.get()
    # Permanent failure — no retry, no SNMP fallback.
    assert payload["ok"] is False
    # SSH connected, so hostname in snmp_alive must NOT have been used as source.
    assert payload.get("vendor_id") != "snmp-10.0.0.1"
    # SSH transport *did* connect — verify that.
    assert fakes.ssh_attempts.get("10.0.0.1", 0) == 1


def test_collect_device_permanent_failure_returns_not_ok_without_retry(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    fakes.fail_facts = {"10.0.0.1"}  # connects fine, facts never parse
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )

    result = tasks.collect_device.apply(args=[str(run_id), "10.0.0.1"])

    assert result.state == "SUCCESS"
    payload = result.get()
    assert payload["ok"] is False
    assert payload["neighbors"] == []
    assert fakes.ssh_attempts["10.0.0.1"] == 1  # no pointless retries
    # The secret never leaks into the reported error.
    assert "hunter2-secret" not in str(payload)


# ---------------------------------------------------------------------------
# Wave 5 / PR 161 Task C: chord BODY safety net — a raising
# continue_discovery_wave must never strand the run in RUNNING
# ---------------------------------------------------------------------------


def _wave_args(run_id: uuid.UUID) -> list[Any]:
    """Positional args for one seed-wave ``continue_discovery_wave`` call."""
    return [
        [{"ok": True, "target_ip": "10.0.0.1", "neighbors": []}],
        str(run_id),
        0,
        [],
        {"waves": [], "devices_succeeded": 0, "devices_failed": 0},
        {"hop_limit": 0, "allowlist": ["10.0.0.0/24"]},
        ["10.0.0.1"],
        time.monotonic(),
    ]


async def _boom(*args: Any, **kwargs: Any) -> None:
    raise RuntimeError("transient DB failure")


def test_continue_wave_unexpected_error_finalizes_run_failed(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Body raising mid-flight -> run ends FAILED (not RUNNING), error propagates."""
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )
    asyncio.run(tasks._start_run(run_id))  # run row -> RUNNING
    monkeypatch.setattr(tasks, "_record_stats", _boom)

    with pytest.raises(RuntimeError, match="transient DB failure"):
        tasks.continue_discovery_wave(*_wave_args(run_id))

    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.FAILED
    assert run.finished_at is not None
    assert "RuntimeError" in (run.error or "")


def test_continue_wave_guard_preserves_terminal_status(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A body failure after the run finished must not clobber the terminal state."""
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )
    stats = {"waves": [], "devices_succeeded": 1, "devices_failed": 0}
    asyncio.run(tasks._finish_run(run_id, DiscoveryRunStatus.SUCCEEDED, stats, None))
    monkeypatch.setattr(tasks, "_record_stats", _boom)

    with pytest.raises(RuntimeError):
        tasks.continue_discovery_wave(*_wave_args(run_id))

    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.SUCCEEDED
    assert run.error is None


def test_collect_device_fold_reraises_celery_control_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Celery control-flow exceptions must pass through the ok=False fold."""
    from celery.exceptions import Reject

    def _reject(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise Reject("broker back-pressure", requeue=False)

    monkeypatch.setattr(tasks, "_collect_device_inner", _reject)

    with pytest.raises(Reject):
        tasks.collect_device(str(uuid.uuid4()), "10.0.0.1")


# ---------------------------------------------------------------------------
# W3-T0: discovery success-rate metric emitted at the run terminal-state site
# ---------------------------------------------------------------------------


def test_run_increments_discovery_runs_total_succeeded(
    eager_celery: None, fakes: FakeEnv, db_url: str
) -> None:
    """A terminal SUCCEEDED run increments ``netops_discovery_runs_total{status}``."""
    from app.core import metrics

    fakes.topology = {"10.0.0.1": []}
    run_id = _seed_run(
        db_url,
        seeds=["10.0.0.1"],
        hop_limit=0,
        allowlist=["10.0.0.0/24"],
        credentials=[SSH_CRED],
    )
    before = metrics.DISCOVERY_RUNS_TOTAL.labels(status="succeeded")._value.get()  # type: ignore[attr-defined]
    tasks.run_discovery.apply(args=[str(run_id)]).get()
    after = metrics.DISCOVERY_RUNS_TOTAL.labels(status="succeeded")._value.get()  # type: ignore[attr-defined]
    assert after == before + 1
