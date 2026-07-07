"""M2-09 topology sync: derivation glue, the sync task, and the rebuild CLI.

No live Neo4j and no Postgres: the projection target is a ``FakeClient`` that
captures every Cypher statement, and the relational source is a file-backed
aiosqlite database (each task phase opens its own event loop via
``asyncio.run``, so the schema must live in a file, not a per-connection
``:memory:`` DB). The engine + Neo4j seams in
:mod:`app.workers.tasks.topology` are monkeypatched to the fakes.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.engines.topology import rebuild as rebuild_mod
from app.engines.topology.sync import derive_topology, snapshot_lists
from app.models import (
    Base,
    DiscoveryRun,
    DiscoveryRunStatus,
)
from app.models.adc import NormalizedPoolRow, NormalizedVirtualServerRow
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
)
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.models.topology import TopologySnapshot
from app.schemas.normalized import (
    AdcAvailability,
    AdcProtocol,
    DnsRecordType,
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    NormalizedDnsRecord,
    RouteProtocol,
)
from app.workers.tasks import topology as tasks

COLLECTED_AT = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)

DEV1 = UUID("00000000-0000-0000-0000-000000000001")
DEV2 = UUID("00000000-0000-0000-0000-000000000002")
IF1 = UUID("00000000-0000-0000-0000-000000000a01")
IF2 = UUID("00000000-0000-0000-0000-000000000a02")
APP1 = UUID("00000000-0000-0000-0000-000000000f01")


# ---------------------------------------------------------------------------
# Fake Neo4j client (captures every statement)
# ---------------------------------------------------------------------------


class FakeSession:
    def __init__(self, executed: list[tuple[str, dict[str, Any]]], fail: bool) -> None:
        self._executed = executed
        self._fail = fail

    async def run(self, cypher: str, **params: Any) -> None:
        if self._fail:
            raise RuntimeError("neo4j down")
        self._executed.append((cypher, params))

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class FakeClient:
    """Stand-in for Neo4jClient; optionally fails on the first statement."""

    def __init__(self, *, fail: bool = False) -> None:
        self.executed: list[tuple[str, dict[str, Any]]] = []
        self._fail = fail
        self.closed = False

    def session(self, **_kwargs: Any) -> FakeSession:
        return FakeSession(self.executed, self._fail)

    async def close(self) -> None:
        self.closed = True

    @property
    def statements(self) -> list[str]:
        return [cypher for cypher, _ in self.executed]


# ---------------------------------------------------------------------------
# ORM row builders (pure, no session)
# ---------------------------------------------------------------------------


def make_device(hostname: str, mgmt_ip: str, *, device_id: UUID, site: str | None = None) -> Device:
    return Device(
        id=device_id,
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id="cisco_ios",
        model="C9300",
        site=site,
    )


def make_interface(
    device_id: UUID,
    name: str,
    *,
    row_id: UUID,
    ip_address: str | None = None,
    vlan_id: int | None = None,
) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id,
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        name=name,
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        ip_address=ip_address,
        vlan_id=vlan_id,
    )


def make_neighbor(
    device_id: UUID, local_interface: str, neighbor_name: str, *, neighbor_address: str
) -> NormalizedNeighborRow:
    return NormalizedNeighborRow(
        id=uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        protocol=NeighborProtocol.LLDP,
        local_interface=local_interface,
        neighbor_name=neighbor_name,
        neighbor_interface="",
        neighbor_address=neighbor_address,
    )


def make_route(device_id: UUID, prefix: str, *, vrf: str = "") -> NormalizedRouteRow:
    return NormalizedRouteRow(
        id=uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=COLLECTED_AT,
        source_vendor="cisco_ios",
        prefix=prefix,
        protocol=RouteProtocol.STATIC,
        next_hop="10.0.0.254",
        interface="",
        vrf=vrf,
    )


# ---------------------------------------------------------------------------
# Test inventory: two devices, one L2 link, addressed interfaces, one route
# ---------------------------------------------------------------------------


def _devices() -> list[Device]:
    return [
        make_device("core-1", "10.0.0.1", device_id=DEV1, site="hq"),
        make_device("core-2", "10.0.0.2", device_id=DEV2),
    ]


def _interfaces() -> list[NormalizedInterfaceRow]:
    return [
        make_interface(DEV1, "Ethernet1", row_id=IF1, ip_address="10.0.0.1/24", vlan_id=10),
        make_interface(DEV2, "Ethernet2", row_id=IF2, ip_address="10.0.0.2/24"),
    ]


def _neighbors() -> list[NormalizedNeighborRow]:
    return [make_neighbor(DEV1, "Ethernet1", "core-2", neighbor_address="10.0.0.2")]


def _routes() -> list[NormalizedRouteRow]:
    return [make_route(DEV1, "192.168.5.0/24", vrf="prod")]


def _applications() -> list[Application]:
    # MANUAL origin: the W2-T2 derivation pass (sync step 0) lifecycle-owns
    # derived ``f5:*`` applications and diff-replaces automated-source rows,
    # so the seeded fixture rows are user-owned — untouchable by every pass
    # (ADR-0052 §3.3.1/§3.3.5) — and survive into the projection unchanged.
    return [
        Application(
            id=APP1,
            name="payroll",
            origin=ApplicationOrigin.MANUAL,
            origin_ref=None,
            fqdns=["payroll.corp.example.com"],
        )
    ]


def _app_dependencies() -> list[ApplicationDependency]:
    return [
        ApplicationDependency(
            application_id=APP1,
            target_kind=DependencyTargetKind.DEVICE,
            target_ref=str(DEV1),
            source=DependencySource.MANUAL,
            provenance=[{"kind": "user", "ref": "00000000-0000-0000-0000-0000000000aa"}],
            derived_at=COLLECTED_AT,
        ),
        ApplicationDependency(
            application_id=APP1,
            target_kind=DependencyTargetKind.IP_ADDRESS,
            target_ref=str(IF1),
            source=DependencySource.MANUAL,
            provenance=[{"kind": "user", "ref": "00000000-0000-0000-0000-0000000000aa"}],
            derived_at=COLLECTED_AT,
        ),
    ]


# ===========================================================================
# Pure derivation glue
# ===========================================================================


def test_derive_topology_combines_l2_l3_and_applications_into_one_pass() -> None:
    derived = derive_topology(
        _devices(), _interfaces(), _routes(), _neighbors(), _applications(), _app_dependencies()
    )

    # Two devices, two interfaces both derive nodes; the route prefix + the
    # interface subnet derive Subnet nodes.
    assert {n.hostname for n in derived.nodes.devices} == {"core-1", "core-2"}
    assert {n.cidr for n in derived.nodes.subnets} == {"10.0.0.0/24", "192.168.5.0/24"}

    # L2 link resolved (core-1 <-> core-2 via the neighbor row + mgmt_ip).
    assert len(derived.edges.connected_to) == 1
    # L3 edges flow through unchanged from the L3 builder.
    assert len(derived.edges.has_interface) == 2
    assert len(derived.edges.in_subnet) == 2
    assert len(derived.edges.l3_adjacent) == 1  # both interfaces in 10.0.0.0/24
    assert len(derived.edges.routes_to) == 1
    assert derived.l2_report.unresolved_neighbors == 0

    # The REQUIRED application layer (ADR-0052 §5) derives alongside.
    assert [str(n.pg_id) for n in derived.applications.applications] == [str(APP1)]
    assert {(e.target_label, e.target_key) for e in derived.applications.depends_on} == {
        ("Device", str(DEV1)),
        ("IPAddress", str(IF1)),
    }


def test_snapshot_lists_emit_canonical_label_key_and_rel_triples() -> None:
    derived = derive_topology(
        _devices(), _interfaces(), _routes(), _neighbors(), _applications(), _app_dependencies()
    )
    node_list, edge_list = snapshot_lists(derived.nodes, derived.edges, derived.applications)

    # Every node row is [label, key]; the VLAN id is stringified.
    assert ["Device", str(DEV1)] in node_list
    assert ["Vlan", "10"] in node_list
    assert ["Subnet", "192.168.5.0/24"] in node_list
    assert ["Application", str(APP1)] in node_list
    assert all(len(pair) == 2 for pair in node_list)

    # Every edge row is [rel_type, src, dst]; the routes_to edge lands on the
    # route-prefix Subnet key; DEPENDS_ON lands on the target's pg_id key.
    assert all(len(triple) == 3 for triple in edge_list)
    assert ["HAS_INTERFACE", str(DEV1), str(IF1)] in edge_list
    assert ["ROUTES_TO", str(DEV1), "192.168.5.0/24"] in edge_list
    assert ["DEPENDS_ON", str(APP1), str(DEV1)] in edge_list
    assert ["DEPENDS_ON", str(APP1), str(IF1)] in edge_list
    rel_types = {triple[0] for triple in edge_list}
    assert rel_types == {
        "CONNECTED_TO",
        "DEPENDS_ON",
        "HAS_INTERFACE",
        "IN_SUBNET",
        "L3_ADJACENT",
        "ROUTES_TO",
    }


def test_snapshot_lists_on_empty_derivation_are_empty() -> None:
    derived = derive_topology([], [], [], [], [], [])
    node_list, edge_list = snapshot_lists(derived.nodes, derived.edges, derived.applications)
    assert node_list == []
    assert edge_list == []


def test_derive_topology_and_snapshot_lists_require_the_application_inputs() -> None:
    """Optional-kwarg relapse guard (ADR-0052 §5): the application inputs have
    NO defaults, so no derivation/snapshot pass can silently omit the layer."""
    import inspect

    for fn, names in (
        (derive_topology, ("applications", "application_dependencies")),
        (snapshot_lists, ("applications",)),
    ):
        signature = inspect.signature(fn)
        for name in names:
            assert signature.parameters[name].default is inspect.Parameter.empty, (
                f"{fn.__name__}(...{name}=) must be REQUIRED (ADR-0052 §5)"
            )


# ===========================================================================
# Fixtures: file-backed aiosqlite + seam patching
# ===========================================================================


@pytest.fixture()
def db_url(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'topology.sqlite'}"

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())
    monkeypatch.setattr(tasks, "_make_engine", lambda: create_async_engine(url))
    return url


def _seed_inventory(db_url: str, *, with_run: bool = True) -> UUID:
    """Insert two devices + normalized rows and (optionally) a finished run."""

    async def _go() -> UUID:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            session.add_all(_devices())
            session.add_all(_interfaces())
            session.add_all(_neighbors())
            session.add_all(_routes())
            session.add_all(_applications())
            session.add_all(_app_dependencies())
            run_id = uuid4()
            if with_run:
                run = DiscoveryRun(
                    id=run_id,
                    seeds=["10.0.0.1"],
                    hop_limit=1,
                    allowlist=["10.0.0.0/24"],
                    credential_names=["lab-ssh"],
                    status=DiscoveryRunStatus.SUCCEEDED,
                    stats={"devices_succeeded": 2, "devices_failed": 0},
                )
                session.add(run)
            await session.commit()
        await engine.dispose()
        return run_id

    return asyncio.run(_go())


def _fetch_run(db_url: str, run_id: UUID) -> DiscoveryRun:
    async def _go() -> DiscoveryRun:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            run = await session.get(DiscoveryRun, run_id)
            assert run is not None
        await engine.dispose()
        return run

    return asyncio.run(_go())


def _fetch_snapshots(db_url: str) -> list[TopologySnapshot]:
    async def _go() -> list[TopologySnapshot]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(select(TopologySnapshot))).scalars())
        await engine.dispose()
        return rows

    return asyncio.run(_go())


# ===========================================================================
# topology.sync_after_run — happy path
# ===========================================================================


def test_sync_after_run_projects_and_snapshots(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = _seed_inventory(db_url)
    client = FakeClient()
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: client)

    result = tasks.sync_after_run(str(run_id))

    assert result["ok"] is True
    assert result["run_id"] == str(run_id)
    assert result["nodes"] > 0
    assert result["edges"] > 0

    # The projector wrote upserts (UNWIND) and constraints (CREATE CONSTRAINT).
    assert any("UNWIND" in s for s in client.statements)
    assert any("CREATE CONSTRAINT" in s for s in client.statements)

    # The application layer rode the SAME pass (ADR-0052 §5 mandatory wiring):
    # the production loader read the app tables and the projector upserted them.
    assert any("MERGE (n:Application" in s for s in client.statements)
    assert any(":DEPENDS_ON" in s and "UNWIND" in s for s in client.statements)

    # Exactly one snapshot row for the run, with canonical node/edge multisets.
    snaps = _fetch_snapshots(db_url)
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap.run_id == run_id
    assert ["Device", str(DEV1)] in snap.nodes
    assert ["ROUTES_TO", str(DEV1), "192.168.5.0/24"] in snap.edges
    assert ["Application", str(APP1)] in snap.nodes
    assert ["DEPENDS_ON", str(APP1), str(DEV1)] in snap.edges

    # The sync outcome was recorded on the run without changing its status.
    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.SUCCEEDED
    assert run.stats["topology_sync"]["ok"] is True
    assert run.stats["devices_succeeded"] == 2  # pre-existing stats preserved


def test_sync_after_run_is_idempotent_one_snapshot_per_run(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = _seed_inventory(db_url)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: FakeClient())

    tasks.sync_after_run(str(run_id))
    tasks.sync_after_run(str(run_id))

    assert len(_fetch_snapshots(db_url)) == 1


# ===========================================================================
# topology.sync_after_run — projection-failure isolation
# ===========================================================================


def test_sync_after_run_isolates_projection_failure(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = _seed_inventory(db_url)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: FakeClient(fail=True))

    # Must NOT raise: a graph-side failure cannot fail the discovery run.
    result = tasks.sync_after_run(str(run_id))

    assert result["ok"] is False
    assert "neo4j down" in result["error"] or "RuntimeError" in result["error"]

    # No snapshot was written (the pass aborted before commit).
    assert _fetch_snapshots(db_url) == []

    # The run is untouched except for the recorded failure block.
    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.SUCCEEDED
    assert run.stats["topology_sync"]["ok"] is False
    assert run.stats["devices_succeeded"] == 2


def test_sync_after_run_secret_free_on_failure(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = _seed_inventory(db_url)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: FakeClient(fail=True))

    result = tasks.sync_after_run(str(run_id))
    # The error string only carries the exception class + message, no creds.
    assert "password" not in result["error"].lower()
    assert "neo4j_user" not in result["error"].lower()


# ===========================================================================
# Full-rebuild entrypoint
# ===========================================================================


def test_rebuild_wipes_then_projects_and_snapshots(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = _seed_inventory(db_url)
    client = FakeClient()
    # rebuild() builds its own engine + client; patch both factories.
    monkeypatch.setattr(rebuild_mod.db, "create_engine", lambda _s: create_async_engine(db_url))
    monkeypatch.setattr(rebuild_mod, "create_client", lambda _s: client)

    summary = asyncio.run(rebuild_mod.rebuild(run_id))

    assert summary["ok"] is True
    assert summary["run_id"] == str(run_id)
    assert summary["nodes"] > 0

    # full_rebuild wipes (DETACH DELETE), re-asserts constraints, then upserts.
    stmts = client.statements
    assert any("DETACH DELETE" in s for s in stmts)
    assert any("CREATE CONSTRAINT" in s for s in stmts)
    assert any("UNWIND" in s for s in stmts)
    # The application layer is part of the rebuild pass too (ADR-0052 §5/§6.1):
    # rebuilt from the PG tables alone, no re-derivation, no plugin access.
    assert any("MERGE (n:Application" in s for s in stmts)
    assert any(":DEPENDS_ON" in s and "UNWIND" in s for s in stmts)
    # Wipe precedes the first upsert (drop-and-reproject order).
    first_wipe = next(i for i, s in enumerate(stmts) if "DETACH DELETE" in s)
    first_upsert = next(i for i, s in enumerate(stmts) if "UNWIND" in s)
    assert first_wipe < first_upsert

    assert client.closed is True
    snaps = _fetch_snapshots(db_url)
    assert len(snaps) == 1
    assert snaps[0].run_id == run_id


def test_rebuild_without_run_id_skips_snapshot(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_inventory(db_url, with_run=False)
    client = FakeClient()
    monkeypatch.setattr(rebuild_mod.db, "create_engine", lambda _s: create_async_engine(db_url))
    monkeypatch.setattr(rebuild_mod, "create_client", lambda _s: client)

    summary = asyncio.run(rebuild_mod.rebuild(None))

    assert summary["run_id"] is None
    assert any("DETACH DELETE" in s for s in client.statements)
    assert _fetch_snapshots(db_url) == []  # no run -> no snapshot


def test_rebuild_cli_main_parses_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def _fake_rebuild(run_id: UUID | None = None) -> dict[str, Any]:
        captured["run_id"] = run_id
        return {"ok": True}

    monkeypatch.setattr(rebuild_mod, "rebuild", _fake_rebuild)

    rid = uuid4()
    assert rebuild_mod.main(["--run-id", str(rid)]) == 0
    assert captured["run_id"] == rid

    captured.clear()
    assert rebuild_mod.main([]) == 0
    assert captured["run_id"] is None


def test_rebuild_cli_main_returns_nonzero_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 1: main() must return 1 when rebuild() raises, not 0."""

    async def _failing_rebuild(run_id: UUID | None = None) -> dict[str, Any]:
        raise RuntimeError("neo4j down")

    monkeypatch.setattr(rebuild_mod, "rebuild", _failing_rebuild)

    assert rebuild_mod.main([]) == 1


# ===========================================================================
# Neo4j client lifecycle — per-invocation fresh client (Finding 2)
# ===========================================================================


def test_sync_after_run_closes_client_after_successful_projection(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each sync_after_run call must close the client it creates."""
    run_id = _seed_inventory(db_url)
    client = FakeClient()
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: client)

    tasks.sync_after_run(str(run_id))

    assert client.closed is True


def test_sync_after_run_closes_client_after_projection_failure(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Client must be closed even when the projection raises."""
    run_id = _seed_inventory(db_url)
    client = FakeClient(fail=True)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: client)

    result = tasks.sync_after_run(str(run_id))

    assert result["ok"] is False
    assert client.closed is True


def test_sync_after_run_creates_fresh_client_each_invocation(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second task invocation must receive a new client, not a reused one."""
    run_id = _seed_inventory(db_url)
    clients: list[FakeClient] = []

    def _fresh_client() -> FakeClient:
        c = FakeClient()
        clients.append(c)
        return c

    monkeypatch.setattr(tasks, "_neo4j_client", _fresh_client)

    tasks.sync_after_run(str(run_id))
    tasks.sync_after_run(str(run_id))

    assert len(clients) == 2
    assert clients[0] is not clients[1]
    assert clients[0].closed is True
    assert clients[1].closed is True


# ===========================================================================
# W2-T2 — post-discovery-run derivation trigger (ADR-0052 §2/§5, step 0)
# ===========================================================================


def _seed_adc(db_url: str) -> None:
    """Insert one F5 virtual server + pool whose member is IF1's address."""

    async def _go() -> None:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            provenance = {
                "raw_artifact_id": uuid4(),
                "collected_at": COLLECTED_AT,
                "source_vendor": "f5_bigip",
            }
            session.add(
                NormalizedVirtualServerRow(
                    device_id=DEV1,
                    **provenance,
                    name="/Common/portal.corp.example.com",
                    vip_address="192.0.2.10",
                    port=443,
                    protocol=AdcProtocol.TCP,
                    enabled=True,
                    availability=AdcAvailability.AVAILABLE,
                    pool_name="/Common/portal_pool",
                )
            )
            session.add(
                NormalizedPoolRow(
                    device_id=DEV1,
                    **provenance,
                    name="/Common/portal_pool",
                    monitors=[],
                    availability=AdcAvailability.AVAILABLE,
                    members=[
                        {
                            "name": "/Common/core-1:443",
                            "address": "10.0.0.1",  # reconciles to IF1 (IPAddress)
                            "fqdn": None,
                            "port": 443,
                            "vrf": None,
                            "admin_state": "enabled",
                            "availability": "available",
                        }
                    ],
                )
            )
            await session.commit()
        await engine.dispose()

    asyncio.run(_go())


def _fetch_applications(db_url: str) -> list[Application]:
    async def _go() -> list[Application]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(select(Application))).scalars())
        await engine.dispose()
        return rows

    return asyncio.run(_go())


def _fetch_dependencies(db_url: str) -> list[ApplicationDependency]:
    async def _go() -> list[ApplicationDependency]:
        engine = create_async_engine(db_url)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            rows = list((await session.execute(select(ApplicationDependency))).scalars())
        await engine.dispose()
        return rows

    return asyncio.run(_go())


def test_sync_after_run_derives_applications_before_projecting(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The trigger wiring: derivation (step 0) writes the PG rows, then the
    SAME pass projects them — the new node reaches Neo4j without any second
    task, and the derivation never touches the seeded manual rows."""
    run_id = _seed_inventory(db_url)
    _seed_adc(db_url)
    client = FakeClient()
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: client)

    result = tasks.sync_after_run(str(run_id))

    assert result["ok"] is True
    derivation = result["application_derivation"]
    assert derivation["ok"] is True
    assert derivation["dns_pass_ran"] is False  # default seam: no DDI fetch
    assert derivation["planned"]["f5_applications"] == 1
    assert derivation["applied"]["applications_created"] == 1
    assert derivation["applied"]["f5"] == {"inserted": 1, "updated": 0, "deleted": 0}

    apps = _fetch_applications(db_url)
    derived = next(a for a in apps if a.origin is ApplicationOrigin.DERIVED)
    assert derived.origin_ref == f"f5:{DEV1}:/Common/portal.corp.example.com"
    assert derived.fqdns == ["portal.corp.example.com"]  # VS-leaf FQDN seed
    manual = next(a for a in apps if a.id == APP1)
    assert manual.origin is ApplicationOrigin.MANUAL  # untouched

    deps = _fetch_dependencies(db_url)
    f5_rows = [d for d in deps if str(d.source) == "f5"]
    assert [(str(d.application_id), d.target_ref) for d in f5_rows] == [(str(derived.id), str(IF1))]
    manual_rows = [d for d in deps if str(d.source) == "manual"]
    assert len(manual_rows) == 2  # per-source ownership: manual untouched

    # The freshly-derived rows rode the SAME projection pass.
    snaps = _fetch_snapshots(db_url)
    assert ["Application", str(derived.id)] in snaps[0].nodes
    assert ["DEPENDS_ON", str(derived.id), str(IF1)] in snaps[0].edges

    # And the derivation outcome is recorded on the run.
    run = _fetch_run(db_url, run_id)
    assert run.stats["application_derivation"]["ok"] is True
    assert run.stats["topology_sync"]["ok"] is True


def test_sync_after_run_is_idempotent_across_derivation_reruns(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Second run on unchanged inputs: derivation is a no-op (no new rows,
    nothing rewritten) and no duplicate applications appear."""
    run_id = _seed_inventory(db_url)
    _seed_adc(db_url)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: FakeClient())

    tasks.sync_after_run(str(run_id))
    first_apps = {a.id: a.updated_at for a in _fetch_applications(db_url)}

    result = tasks.sync_after_run(str(run_id))
    derivation = result["application_derivation"]
    assert derivation["applied"]["applications_created"] == 0
    assert derivation["applied"]["f5"] == {"inserted": 0, "updated": 0, "deleted": 0}

    second_apps = {a.id: a.updated_at for a in _fetch_applications(db_url)}
    assert second_apps == first_apps  # stable UUIDs, zero updated_at churn


def test_sync_after_run_isolates_derivation_failure_from_projection(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A derivation failure records ok=False in its own block; the projection
    still runs on the previous rows and the discovery run is untouched."""
    run_id = _seed_inventory(db_url)

    def _boom() -> None:
        raise RuntimeError("adc load failed")

    monkeypatch.setattr(tasks, "_fetch_dns_records", _boom)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: FakeClient())

    result = tasks.sync_after_run(str(run_id))

    assert result["ok"] is True  # the projection succeeded
    assert result["application_derivation"]["ok"] is False
    assert "RuntimeError" in result["application_derivation"]["error"]

    run = _fetch_run(db_url, run_id)
    assert run.status is DiscoveryRunStatus.SUCCEEDED
    assert run.stats["application_derivation"]["ok"] is False
    assert run.stats["topology_sync"]["ok"] is True


def test_fetch_dns_records_seam_feeds_source_3(
    db_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the seam returns records, the dns pass runs in the same trigger:
    the seeded manual app's fqdn reconciles through the M5 machinery and a
    ``source='dns'`` row persists (rebuild never needs DDI reachability)."""
    run_id = _seed_inventory(db_url)
    monkeypatch.setattr(tasks, "_neo4j_client", lambda: FakeClient())
    monkeypatch.setattr(
        tasks,
        "_fetch_dns_records",
        lambda: [
            NormalizedDnsRecord(
                device_id=DEV1,
                collected_at=COLLECTED_AT,
                source_vendor="infoblox",
                name="payroll.corp.example.com",
                record_type=DnsRecordType.A,
                value="10.0.0.1",
                zone="corp.example.com",
            )
        ],
    )

    result = tasks.sync_after_run(str(run_id))
    derivation = result["application_derivation"]
    assert derivation["dns_pass_ran"] is True
    assert derivation["applied"]["dns"] == {"inserted": 1, "updated": 0, "deleted": 0}

    deps = _fetch_dependencies(db_url)
    (dns_row,) = [d for d in deps if str(d.source) == "dns"]
    assert dns_row.application_id == APP1
    assert dns_row.target_ref == str(IF1)
    assert dns_row.provenance[0]["kind"] == "dns_record"
