"""M2-11 exit-criteria integration tests: rebuild isomorphism + traceability.

These two ``@pytest.mark.integration`` tests prove the two load-bearing
ADR-0005 invariants of the Neo4j topology projection against the *live* compose
stack — they are excluded from the unit gate and skip cleanly when either store
is unreachable.

Rebuild isomorphism (MVP §4, the "D5 rebuildable" contract)
-----------------------------------------------------------
Seed Postgres with a small fixed inventory, run the real Postgres -> Neo4j
:func:`app.engines.topology.rebuild.rebuild` path, and export the *live graph*'s
node/edge multisets in canonical snapshot form.  Then ``DETACH DELETE`` every
projected label (simulating total Neo4j volume loss), rebuild a second time, and
export again.  The two multisets must be byte-identical: a drop-and-reproject
reconstructs the graph from the relational source of truth alone.

Traceability spot-check (Neo4j holds nothing absent from Postgres)
------------------------------------------------------------------
After a rebuild, sample the projected ``Device`` / ``Interface`` / ``IPAddress``
nodes and assert every ``pg_id`` resolves to an existing Postgres row.  This is
the contrapositive of the projection contract: the graph is a pure projection,
so no provenance-bearing node may reference a row that does not exist.

Running the integration suite
-----------------------------
Bring up the data stores (host-published ports are commented out by default, so
publish them and set an 8+ char Neo4j password; the image rejects "neo4j")::

    NETOPS_NEO4J_PASSWORD=netops-test \
      docker compose -f deploy/docker/docker-compose.yml up -d postgres neo4j

    export NETOPS_DATABASE_URL=postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops
    export NETOPS_NEO4J_URI=bolt://127.0.0.1:7687
    export NETOPS_NEO4J_PASSWORD=netops-test

    cd backend && python -m pytest -m integration

(The compose ``postgres``/``neo4j`` services need their ``ports:`` lines
uncommented in ``deploy/docker/docker-compose.yml`` to be reachable from the
host.)  Without those env vars / published ports the tests skip themselves.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app import db
from app.core.config import get_settings
from app.engines.topology.projector import PROJECTED_NODE_LABELS
from app.engines.topology.rebuild import rebuild
from app.engines.topology.snapshots import build_snapshot
from app.knowledge.neo4j_client import Neo4jClient
from app.models import Base, DiscoveryRun, DiscoveryRunStatus
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

COLLECTED_AT = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)

# Fixed UUIDs so cleanup can target exactly the rows this module inserts and
# never touch an operator's real inventory in a shared database.
RUN_ID = UUID("00000000-0000-0000-0000-00000000c011")
DEV1 = UUID("00000000-0000-0000-0000-00000000c001")
DEV2 = UUID("00000000-0000-0000-0000-00000000c002")
IF1 = UUID("00000000-0000-0000-0000-00000000c0a1")
IF2 = UUID("00000000-0000-0000-0000-00000000c0a2")
RAW = UUID("00000000-0000-0000-0000-00000000c0ff")

_DEVICE_IDS = (DEV1, DEV2)


# ---------------------------------------------------------------------------
# Postgres inventory fixture (two devices, one L2 link, addressed interfaces,
# a route, and a VRF) — inserted directly via the ORM.
# ---------------------------------------------------------------------------


def _devices() -> list[Device]:
    return [
        Device(
            id=DEV1,
            hostname="core-1",
            mgmt_ip="10.20.0.1",
            vendor_id="cisco_ios",
            model="C9300",
            site="hq",
        ),
        Device(
            id=DEV2,
            hostname="core-2",
            mgmt_ip="10.20.0.2",
            vendor_id="arista_eos",
            model=None,
            site=None,
        ),
    ]


def _interfaces() -> list[NormalizedInterfaceRow]:
    common: dict[str, Any] = {
        "raw_artifact_id": RAW,
        "collected_at": COLLECTED_AT,
        "source_vendor": "cisco_ios",
        "admin_status": InterfaceAdminStatus.UP,
        "oper_status": InterfaceOperStatus.UP,
    }
    return [
        NormalizedInterfaceRow(
            id=IF1,
            device_id=DEV1,
            name="Ethernet1",
            ip_address="10.20.0.1/24",
            vlan_id=10,
            **common,
        ),
        NormalizedInterfaceRow(
            id=IF2,
            device_id=DEV2,
            name="Ethernet2",
            ip_address="10.20.0.2/24",
            vlan_id=10,
            **common,
        ),
    ]


def _routes() -> list[NormalizedRouteRow]:
    return [
        NormalizedRouteRow(
            device_id=DEV1,
            raw_artifact_id=RAW,
            collected_at=COLLECTED_AT,
            source_vendor="cisco_ios",
            prefix="10.30.0.0/24",
            protocol=RouteProtocol.STATIC,
            next_hop="10.20.0.254",
            interface="",
            vrf="prod",
        ),
    ]


def _neighbors() -> list[NormalizedNeighborRow]:
    return [
        NormalizedNeighborRow(
            device_id=DEV1,
            raw_artifact_id=RAW,
            collected_at=COLLECTED_AT,
            source_vendor="cisco_ios",
            protocol=NeighborProtocol.LLDP,
            local_interface="Ethernet1",
            neighbor_name="core-2",
            neighbor_interface="Ethernet2",
            neighbor_address="10.20.0.2",
        ),
    ]


def _discovery_run() -> DiscoveryRun:
    return DiscoveryRun(
        id=RUN_ID,
        status=DiscoveryRunStatus.SUCCEEDED,
        seeds=["10.20.0.1"],
        hop_limit=1,
        allowlist=["10.20.0.0/24"],
        credential_names=[],
    )


# ---------------------------------------------------------------------------
# Live-store reachability + lifecycle helpers
# ---------------------------------------------------------------------------


def _postgres_url() -> str | None:
    url = get_settings().database_url
    return url if url.startswith("postgresql") else None


async def _postgres_reachable(url: str) -> bool:
    engine = create_async_engine(url, poolclass=NullPool, connect_args={"timeout": 3})
    try:
        async with engine.connect():
            return True
    except Exception:
        return False
    finally:
        await engine.dispose()


async def _seed_postgres(sessionmaker: async_sessionmaker[Any]) -> None:
    """Insert the fixed inventory + discovery run (idempotent: deletes first)."""
    await _purge_postgres(sessionmaker)
    async with sessionmaker() as session:
        session.add(_discovery_run())
        for device in _devices():
            session.add(device)
        await session.flush()
        for row in (*_interfaces(), *_routes(), *_neighbors()):
            session.add(row)
        await session.commit()


async def _purge_postgres(sessionmaker: async_sessionmaker[Any]) -> None:
    """Remove only the rows this module owns (keyed by fixed device/run ids)."""
    async with sessionmaker() as session:
        await session.execute(delete(TopologySnapshot).where(TopologySnapshot.run_id == RUN_ID))
        for model in (
            NormalizedInterfaceRow,
            NormalizedRouteRow,
            NormalizedNeighborRow,
        ):
            await session.execute(delete(model).where(model.device_id.in_(_DEVICE_IDS)))
        await session.execute(delete(Device).where(Device.id.in_(_DEVICE_IDS)))
        await session.execute(delete(DiscoveryRun).where(DiscoveryRun.id == RUN_ID))
        await session.commit()


# ---------------------------------------------------------------------------
# Live-graph multiset export (reads the projection back from Neo4j)
# ---------------------------------------------------------------------------


async def _export_graph_multisets(
    client: Neo4jClient,
) -> tuple[list[list[str]], list[list[str]]]:
    """Read the projected subgraph back as canonical ``build_snapshot`` input.

    Nodes are exported as ``[label, key]`` using each label's key property;
    edges as ``[rel_type, src_key, dst_key]`` from the source/target key
    properties.  Reading from the *live graph* (not from the derivation) is what
    makes the isomorphism assertion meaningful: it compares two real rebuilds.
    """
    nodes: list[list[str]] = []
    edges: list[list[str]] = []
    async with client.session() as session:
        # Each projected node carries exactly one natural/surrogate key; pull it
        # via the schema key property so the canonical form matches snapshots.
        result = await session.run(
            "MATCH (n) "
            "WHERE any(l IN labels(n) WHERE l IN $labels) "
            "RETURN [l IN labels(n) WHERE l IN $labels][0] AS label, "
            "       coalesce(n.pg_id, n.cidr, toString(n.vlan_id), n.name) AS key",
            labels=list(PROJECTED_NODE_LABELS),
        )
        async for record in result:
            nodes.append([record["label"], str(record["key"])])

        result = await session.run(
            "MATCH (a)-[r]->(b) "
            "WHERE any(l IN labels(a) WHERE l IN $labels) "
            "  AND any(l IN labels(b) WHERE l IN $labels) "
            "RETURN type(r) AS rel_type, "
            "       coalesce(a.pg_id, a.cidr, toString(a.vlan_id), a.name) AS src, "
            "       coalesce(b.pg_id, b.cidr, toString(b.vlan_id), b.name) AS dst",
            labels=list(PROJECTED_NODE_LABELS),
        )
        async for record in result:
            edges.append([record["rel_type"], str(record["src"]), str(record["dst"])])
    return nodes, edges


async def _destroy_graph(client: Neo4jClient) -> None:
    """DETACH DELETE every projected label — simulates Neo4j volume loss."""
    async with client.session() as session:
        for label in PROJECTED_NODE_LABELS:
            await session.run(f"MATCH (n:{label}) DETACH DELETE n")


# ---------------------------------------------------------------------------
# The two exit-criteria tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_full_rebuild_is_isomorphic_after_total_graph_loss() -> None:
    """Rebuild -> export -> destroy graph -> rebuild -> export: multisets equal.

    Proves the ADR-0005 "Neo4j is rebuildable from Postgres" (D5) contract end
    to end through the real :func:`app.engines.topology.rebuild.rebuild` path.
    """
    url = _postgres_url()
    if url is None or not await _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    settings = get_settings()
    client = Neo4jClient(settings)
    if not await client.health_check():
        await client.close()
        pytest.skip("Neo4j unreachable at NETOPS_NEO4J_URI; skipping integration test")

    engine = db.create_engine(settings)
    sessionmaker = db.create_sessionmaker(engine)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _seed_postgres(sessionmaker)

        # First rebuild: Postgres -> Neo4j, then read the live graph back.
        await rebuild(run_id=RUN_ID)
        nodes_a, edges_a = await _export_graph_multisets(client)
        snapshot_a = build_snapshot(nodes_a, edges_a)

        # Sanity: the graph is non-empty (otherwise equality is vacuous).
        assert snapshot_a["nodes"], "first rebuild projected no nodes"
        assert snapshot_a["edges"], "first rebuild projected no edges"

        # Simulate total Neo4j volume loss, then rebuild from Postgres alone.
        await _destroy_graph(client)
        empty_nodes, empty_edges = await _export_graph_multisets(client)
        assert empty_nodes == [] and empty_edges == [], "graph not actually destroyed"

        await rebuild(run_id=RUN_ID)
        nodes_b, edges_b = await _export_graph_multisets(client)
        snapshot_b = build_snapshot(nodes_b, edges_b)

        # Isomorphism: the two rebuilds yield byte-identical canonical multisets.
        assert snapshot_b == snapshot_a
    finally:
        await _destroy_graph(client)
        await _purge_postgres(sessionmaker)
        await client.close()
        await engine.dispose()


@pytest.mark.integration
async def test_every_projected_pg_id_resolves_to_a_postgres_row() -> None:
    """Traceability: every Device/Interface/IPAddress pg_id exists in Postgres.

    Neo4j is a pure projection (ADR-0005), so it must contain nothing absent
    from the relational source of truth.  We sample the provenance-bearing node
    labels and assert each ``pg_id`` resolves to a live Postgres row.
    """
    url = _postgres_url()
    if url is None or not await _postgres_reachable(url):
        pytest.skip("PostgreSQL unreachable at NETOPS_DATABASE_URL; skipping integration test")

    settings = get_settings()
    client = Neo4jClient(settings)
    if not await client.health_check():
        await client.close()
        pytest.skip("Neo4j unreachable at NETOPS_NEO4J_URI; skipping integration test")

    engine = db.create_engine(settings)
    sessionmaker = db.create_sessionmaker(engine)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _seed_postgres(sessionmaker)
        await rebuild(run_id=RUN_ID)

        # Collect pg_id from each provenance-bearing label straight off the graph.
        async with client.session() as session:
            device_ids = await _pg_ids(session, "Device")
            interface_ids = await _pg_ids(session, "Interface")
            ip_ids = await _pg_ids(session, "IPAddress")

        assert device_ids, "rebuild projected no Device nodes"
        assert interface_ids, "rebuild projected no Interface nodes"
        assert ip_ids, "rebuild projected no IPAddress nodes"

        # Device.pg_id -> devices.id; Interface/IPAddress.pg_id -> interfaces.id.
        async with sessionmaker() as session:
            for pg_id in device_ids:
                row = await session.get(Device, UUID(pg_id))
                assert row is not None, f"Device pg_id {pg_id} absent from Postgres"
            for pg_id in interface_ids | ip_ids:
                row = await session.get(NormalizedInterfaceRow, UUID(pg_id))
                assert row is not None, f"Interface/IPAddress pg_id {pg_id} absent from Postgres"
    finally:
        await _destroy_graph(client)
        await _purge_postgres(sessionmaker)
        await client.close()
        await engine.dispose()


async def _pg_ids(session: Any, label: str) -> set[str]:
    result = await session.run(f"MATCH (n:{label}) RETURN n.pg_id AS pg_id")
    return {record["pg_id"] async for record in result}
