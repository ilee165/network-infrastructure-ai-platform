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
from app.engines.topology.projector import DerivedEdges
from app.engines.topology.sync import derive_topology, snapshot_lists
from app.models import (
    Base,
    DiscoveryRun,
    DiscoveryRunStatus,
)
from app.models.inventory import (
    Device,
    NormalizedInterfaceRow,
    NormalizedNeighborRow,
    NormalizedRouteRow,
)
from app.models.topology import TopologySnapshot
from app.schemas.normalized import (
    InterfaceAdminStatus,
    InterfaceOperStatus,
    NeighborProtocol,
    RouteProtocol,
)
from app.workers.tasks import topology as tasks

COLLECTED_AT = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)

DEV1 = UUID("00000000-0000-0000-0000-000000000001")
DEV2 = UUID("00000000-0000-0000-0000-000000000002")
IF1 = UUID("00000000-0000-0000-0000-000000000a01")
IF2 = UUID("00000000-0000-0000-0000-000000000a02")


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


# ===========================================================================
# Pure derivation glue
# ===========================================================================


def test_derive_topology_combines_l2_and_l3_into_one_edge_set() -> None:
    derived = derive_topology(_devices(), _interfaces(), _routes(), _neighbors())

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


def test_snapshot_lists_emit_canonical_label_key_and_rel_triples() -> None:
    derived = derive_topology(_devices(), _interfaces(), _routes(), _neighbors())
    node_list, edge_list = snapshot_lists(derived.nodes, derived.edges)

    # Every node row is [label, key]; the VLAN id is stringified.
    assert ["Device", str(DEV1)] in node_list
    assert ["Vlan", "10"] in node_list
    assert ["Subnet", "192.168.5.0/24"] in node_list
    assert all(len(pair) == 2 for pair in node_list)

    # Every edge row is [rel_type, src, dst]; the routes_to edge lands on the
    # route-prefix Subnet key.
    assert all(len(triple) == 3 for triple in edge_list)
    assert ["HAS_INTERFACE", str(DEV1), str(IF1)] in edge_list
    assert ["ROUTES_TO", str(DEV1), "192.168.5.0/24"] in edge_list
    rel_types = {triple[0] for triple in edge_list}
    assert rel_types == {
        "CONNECTED_TO",
        "HAS_INTERFACE",
        "IN_SUBNET",
        "L3_ADJACENT",
        "ROUTES_TO",
    }


def test_snapshot_lists_on_empty_derivation_are_empty() -> None:
    node_list, edge_list = snapshot_lists(derive_topology([], [], [], []).nodes, DerivedEdges())
    assert node_list == []
    assert edge_list == []


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

    # Exactly one snapshot row for the run, with canonical node/edge multisets.
    snaps = _fetch_snapshots(db_url)
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap.run_id == run_id
    assert ["Device", str(DEV1)] in snap.nodes
    assert ["ROUTES_TO", str(DEV1), "192.168.5.0/24"] in snap.edges

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
