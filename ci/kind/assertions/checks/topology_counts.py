"""Topology count helper for the W4-T4 Neo4j destroy-and-rebuild drill.

G-REL §317 (ADR-0005 D5 / §3, ADR-0030 §1, ADR-0047 §2/§3): Neo4j is a PURE
projection of Postgres — the system of record (ADR-0004/0005 D5). It holds NO
un-rebuildable state, so DR is a full RE-PROJECTION from Postgres, never a graph
dump/restore. This module gives the drill (neo4j-rebuild.sh) three faithful,
REAL-store primitives it drives via ``kubectl exec`` on the backend-image probe
pod inside the reduced-scale HA kind cluster:

  * ``seed``        — insert a small, FIXED reduced-scale inventory (2 devices,
                      addressed interfaces, one L2 link, a route, a VRF) into
                      Postgres via the ORM, keyed by fixed drill UUIDs so the
                      cleanup targets exactly these rows and never an operator's
                      real inventory. This is the topology the drill projects,
                      destroys, and rebuilds.
  * ``pg-source``   — compute the node/edge counts the projection MUST have,
                      derived from POSTGRES ALONE via the real
                      ``app.engines.topology`` derivation (``derive_topology`` ->
                      ``snapshot_lists``). This is the SOURCE-OF-RECORD count
                      (D5): what a complete re-projection is obligated to produce.
                      It touches Neo4j not at all.
  * ``neo4j-graph`` — count the LIVE projected graph in Neo4j (scoped to
                      ``PROJECTED_NODE_LABELS`` / ``PROJECTED_REL_TYPES`` — exactly
                      the set the projector writes). After a destroy + auto-rebuild
                      this is what the graph actually holds.

The drill's completeness assertion is ``neo4j-graph == pg-source`` (a partial
rebuild produces FEWER nodes/edges than Postgres mandates -> mismatch -> RED),
and its RTO assertion is that the rebuild wall-clock is <= the measured
topology-RTO. Both are meaningful ONLY against real Postgres + real Neo4j (there
is NO SQLite path — ADR-0047 §5): SQLite has no graph projection and would hide
the very rebuild-from-relational-source semantics this drill exists to prove.

Each subcommand prints ONE structured line the shell parses:
  ``DRILL neo4j_rebuild <sub> nodes=<n> edges=<n> result=PASS|FAIL``
and exits non-zero on any error (fail closed). The counts are the source of
truth the drill compares; the line shape mirrors the P1 seeded-dry-run harness
(topology_rebuild/) the W5-T5 collector already parses.

Run (inside the probe pod; PYTHONPATH carries the app package):
  python -m topology_counts seed
  python -m topology_counts pg-source
  python -m topology_counts neo4j-graph
  python -m topology_counts purge
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

# The FIXED reduced-scale drill inventory (ADR-0047 §1 — reduced scale is STATED).
# Fixed UUIDs so ``seed``/``purge`` target exactly these rows and never touch an
# operator's real inventory in a shared database (mirrors the M2-11 integration
# fixture, backend/tests/engines/topology/test_rebuild_exit_criteria.py).
_COLLECTED_AT = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
_RUN_ID = UUID("00000000-0000-0000-0000-0000000d4d11")
_DEV1 = UUID("00000000-0000-0000-0000-0000000d4d01")
_DEV2 = UUID("00000000-0000-0000-0000-0000000d4d02")
_IF1 = UUID("00000000-0000-0000-0000-0000000d4da1")
_IF2 = UUID("00000000-0000-0000-0000-0000000d4da2")
_RAW = UUID("00000000-0000-0000-0000-0000000d4dff")
_DEVICE_IDS = (_DEV1, _DEV2)

_TAG = "DRILL neo4j_rebuild"


def _emit(sub: str, *, nodes: int, edges: int, ok: bool = True) -> None:
    """Print the one structured line the shell drill parses (the count contract)."""
    result = "PASS" if ok else "FAIL"
    print(f"{_TAG} {sub} nodes={nodes} edges={edges} result={result}", flush=True)


# ---------------------------------------------------------------------------
# Seed / purge — the fixed reduced-scale inventory in Postgres (the SOURCE).
# ---------------------------------------------------------------------------


def _devices() -> list[Any]:
    from app.models.inventory import Device  # noqa: PLC0415

    return [
        Device(
            id=_DEV1,
            hostname="drill-core-1",
            mgmt_ip="10.77.0.1",
            vendor_id="cisco_ios",
            model="C9300",
            site="drill-hq",
        ),
        Device(
            id=_DEV2,
            hostname="drill-core-2",
            mgmt_ip="10.77.0.2",
            vendor_id="arista_eos",
            model=None,
            site=None,
        ),
    ]


def _interfaces() -> list[Any]:
    from app.models.inventory import NormalizedInterfaceRow  # noqa: PLC0415
    from app.schemas.normalized import (  # noqa: PLC0415
        InterfaceAdminStatus,
        InterfaceOperStatus,
    )

    common: dict[str, Any] = {
        "raw_artifact_id": _RAW,
        "collected_at": _COLLECTED_AT,
        "source_vendor": "cisco_ios",
        "admin_status": InterfaceAdminStatus.UP,
        "oper_status": InterfaceOperStatus.UP,
    }
    return [
        NormalizedInterfaceRow(
            id=_IF1,
            device_id=_DEV1,
            name="Ethernet1",
            ip_address="10.77.0.1/24",
            vlan_id=77,
            **common,
        ),
        NormalizedInterfaceRow(
            id=_IF2,
            device_id=_DEV2,
            name="Ethernet2",
            ip_address="10.77.0.2/24",
            vlan_id=77,
            **common,
        ),
    ]


def _routes() -> list[Any]:
    from app.models.inventory import NormalizedRouteRow  # noqa: PLC0415
    from app.schemas.normalized import RouteProtocol  # noqa: PLC0415

    return [
        NormalizedRouteRow(
            device_id=_DEV1,
            raw_artifact_id=_RAW,
            collected_at=_COLLECTED_AT,
            source_vendor="cisco_ios",
            prefix="10.88.0.0/24",
            protocol=RouteProtocol.STATIC,
            next_hop="10.77.0.254",
            interface="",
            vrf="drill-prod",
        ),
    ]


def _neighbors() -> list[Any]:
    from app.models.inventory import NormalizedNeighborRow  # noqa: PLC0415
    from app.schemas.normalized import NeighborProtocol  # noqa: PLC0415

    return [
        NormalizedNeighborRow(
            device_id=_DEV1,
            raw_artifact_id=_RAW,
            collected_at=_COLLECTED_AT,
            source_vendor="cisco_ios",
            protocol=NeighborProtocol.LLDP,
            local_interface="Ethernet1",
            neighbor_name="drill-core-2",
            neighbor_interface="Ethernet2",
            neighbor_address="10.77.0.2",
        ),
    ]


def _discovery_run() -> Any:
    from app.models import DiscoveryRun, DiscoveryRunStatus  # noqa: PLC0415

    return DiscoveryRun(
        id=_RUN_ID,
        status=DiscoveryRunStatus.SUCCEEDED,
        seeds=["10.77.0.1"],
        hop_limit=1,
        allowlist=["10.77.0.0/24"],
        credential_names=[],
    )


async def _purge(sessionmaker: Any) -> None:
    """Remove ONLY the rows this drill owns (keyed by fixed drill ids)."""
    from sqlalchemy import delete  # noqa: PLC0415

    from app.models import DiscoveryRun  # noqa: PLC0415
    from app.models.inventory import (  # noqa: PLC0415
        Device,
        NormalizedInterfaceRow,
        NormalizedNeighborRow,
        NormalizedRouteRow,
    )
    from app.models.topology import TopologySnapshot  # noqa: PLC0415

    async with sessionmaker() as session:
        await session.execute(delete(TopologySnapshot).where(TopologySnapshot.run_id == _RUN_ID))
        for model in (NormalizedInterfaceRow, NormalizedRouteRow, NormalizedNeighborRow):
            await session.execute(delete(model).where(model.device_id.in_(_DEVICE_IDS)))
        await session.execute(delete(Device).where(Device.id.in_(_DEVICE_IDS)))
        await session.execute(delete(DiscoveryRun).where(DiscoveryRun.id == _RUN_ID))
        await session.commit()


async def _sessionmaker() -> tuple[Any, Any]:
    """Build a Postgres engine + sessionmaker from the app settings (real PG)."""
    from app import db  # noqa: PLC0415
    from app.core.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    url = settings.database_url
    # ADR-0047 §5: there is NO SQLite path. The rebuild-from-relational-source
    # semantics this drill proves do not exist on SQLite (no graph projection).
    if not url.startswith("postgresql"):
        raise RuntimeError(
            "topology_counts requires real PostgreSQL (ADR-0047 §5) — "
            f"database_url is not a postgresql URL: {url.split('://', 1)[0]}://…"
        )
    engine = db.create_engine(settings)
    return engine, db.create_sessionmaker(engine)


async def _cmd_seed() -> int:
    engine, sm = await _sessionmaker()
    try:
        await _purge(sm)  # idempotent: re-seeding replaces the prior drill rows.
        async with sm() as session:
            session.add(_discovery_run())
            for device in _devices():
                session.add(device)
            await session.flush()
            for row in (*_interfaces(), *_routes(), *_neighbors()):
                session.add(row)
            await session.commit()
    finally:
        await engine.dispose()
    # Report the source-of-record counts the seed implies (a convenience echo).
    nodes, edges = await _pg_source_counts()
    _emit("seed", nodes=nodes, edges=edges, ok=(nodes > 0 and edges > 0))
    return 0 if (nodes > 0 and edges > 0) else 1


async def _cmd_purge() -> int:
    engine, sm = await _sessionmaker()
    try:
        await _purge(sm)
    finally:
        await engine.dispose()
    _emit("purge", nodes=0, edges=0, ok=True)
    return 0


# ---------------------------------------------------------------------------
# pg-source — node/edge counts derived from POSTGRES ALONE (the D5 source count).
# ---------------------------------------------------------------------------


async def _pg_source_counts() -> tuple[int, int]:
    """Counts a COMPLETE re-projection must produce, derived from Postgres only.

    Uses the SAME derivation the real rebuild uses (``derive_topology`` ->
    ``snapshot_lists``, the path ``app.engines.topology.rebuild.rebuild`` runs),
    so the number is exactly what a faithful re-projection is obligated to write.
    Touches Neo4j not at all — this is the system-of-record obligation (D5).
    """
    from sqlalchemy import select  # noqa: PLC0415

    from app.engines.topology.sync import derive_topology, snapshot_lists  # noqa: PLC0415
    from app.models.inventory import (  # noqa: PLC0415
        Device,
        NormalizedInterfaceRow,
        NormalizedNeighborRow,
        NormalizedRouteRow,
    )

    engine, sm = await _sessionmaker()
    try:
        async with sm() as session:
            devices = list((await session.execute(select(Device))).scalars())
            interfaces = list((await session.execute(select(NormalizedInterfaceRow))).scalars())
            routes = list((await session.execute(select(NormalizedRouteRow))).scalars())
            neighbors = list((await session.execute(select(NormalizedNeighborRow))).scalars())
    finally:
        await engine.dispose()
    derived = derive_topology(devices, interfaces, routes, neighbors)
    node_list, edge_list = snapshot_lists(derived.nodes, derived.edges)
    return len(node_list), len(edge_list)


async def _cmd_pg_source() -> int:
    nodes, edges = await _pg_source_counts()
    # A source count of zero means there is nothing to project — the drill would
    # be vacuous (0 == 0 always passes). Fail so a mis-seeded run is caught.
    _emit("pg-source", nodes=nodes, edges=edges, ok=(nodes > 0 and edges > 0))
    return 0 if (nodes > 0 and edges > 0) else 1


# ---------------------------------------------------------------------------
# neo4j-graph — count the LIVE projected graph (what the rebuild actually wrote).
# ---------------------------------------------------------------------------


async def _neo4j_graph_counts() -> tuple[int, int]:
    """Count projected nodes + edges in the LIVE Neo4j graph (scoped to the
    projector's label / rel-type set, so the number is directly comparable to
    ``pg-source``). A destroyed-then-partially-rebuilt graph reads FEWER than the
    Postgres source mandates."""
    from app.core.config import get_settings  # noqa: PLC0415
    from app.engines.topology.projector import (  # noqa: PLC0415
        PROJECTED_NODE_LABELS,
        PROJECTED_REL_TYPES,
    )
    from app.knowledge.neo4j_client import create_client  # noqa: PLC0415

    client = create_client(get_settings())
    labels = list(PROJECTED_NODE_LABELS)
    rel_types = list(PROJECTED_REL_TYPES)

    async def _read(tx: Any) -> tuple[int, int]:
        node_res = await tx.run(
            "MATCH (n) WHERE any(l IN labels(n) WHERE l IN $labels) RETURN count(n) AS c",
            labels=labels,
        )
        node_rec = await node_res.single()
        edge_res = await tx.run(
            "MATCH ()-[r]->() WHERE type(r) IN $rel_types RETURN count(r) AS c",
            rel_types=rel_types,
        )
        edge_rec = await edge_res.single()
        n = int(node_rec["c"]) if node_rec is not None else 0
        e = int(edge_rec["c"]) if edge_rec is not None else 0
        return n, e

    try:
        return await client.execute_read(_read)
    finally:
        await client.close()


async def _cmd_neo4j_graph() -> int:
    nodes, edges = await _neo4j_graph_counts()
    # The shell compares this against pg-source; ok here just means the read
    # succeeded. Zero is a VALID observation (an un-rebuilt / destroyed graph) —
    # the shell's compare turns a 0-vs-N mismatch RED (the negative-control bite).
    _emit("neo4j-graph", nodes=nodes, edges=edges, ok=True)
    return 0


_COMMANDS = {
    "seed": _cmd_seed,
    "purge": _cmd_purge,
    "pg-source": _cmd_pg_source,
    "neo4j-graph": _cmd_neo4j_graph,
}


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="topology_counts")
    parser.add_argument("command", choices=sorted(_COMMANDS))
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return asyncio.run(_COMMANDS[args.command]())
    except Exception as exc:  # fail closed — a broken count is never a pass.
        print(
            f"{_TAG} {args.command} ERROR={type(exc).__name__}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover - module execution shim
    raise SystemExit(main())
