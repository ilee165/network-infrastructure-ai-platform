"""M2-07 topology snapshots: determinism, canonical form, upsert-by-run.

All tests run on an in-memory aiosqlite session (no real Postgres, no Neo4j).
The snapshot model and helper functions must:

- produce a deterministic JSON blob from any node/edge input regardless of
  input ordering,
- map the canonical multiset form ([label, key] pairs / [type, src, dst]
  triples) exactly,
- upsert idempotently — same run_id -> same row; second upsert with
  changed data replaces the content.
"""

from __future__ import annotations

import json

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.engines.topology.snapshots import build_snapshot, upsert_snapshot
from app.models import Base, DiscoveryRun

# ---------------------------------------------------------------------------
# In-memory SQLite session (mirrors the discovery persistence test pattern)
# ---------------------------------------------------------------------------

_ENGINE = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
_SessionLocal = sessionmaker(_ENGINE, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture()
async def session() -> AsyncSession:  # type: ignore[override]
    async with _ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with _SessionLocal() as s:
        yield s
    async with _ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture()
async def run(session: AsyncSession) -> DiscoveryRun:
    """A minimal DiscoveryRun row for FK binding."""
    dr = DiscoveryRun(
        seeds=["10.0.0.1"],
        hop_limit=2,
        allowlist=[],
        credential_names=[],
        stats={},
    )
    session.add(dr)
    await session.flush()
    return dr


# ---------------------------------------------------------------------------
# Canonical form helpers
# ---------------------------------------------------------------------------


def _node(label: str, key: str) -> list[str]:
    return [label, key]


def _edge(rel_type: str, src: str, dst: str) -> list[str]:
    return [rel_type, src, dst]


# ---------------------------------------------------------------------------
# build_snapshot — pure function tests (no DB required)
# ---------------------------------------------------------------------------


class TestBuildSnapshotDeterminism:
    """Same logical input -> byte-identical JSON regardless of input order."""

    _NODES_A = [
        _node("Device", "uuid-aaa"),
        _node("Interface", "uuid-bbb"),
        _node("Subnet", "10.0.0.0/24"),
    ]
    _NODES_B = [
        _node("Interface", "uuid-bbb"),
        _node("Subnet", "10.0.0.0/24"),
        _node("Device", "uuid-aaa"),
    ]
    _EDGES_A = [
        _edge("HAS_INTERFACE", "uuid-aaa", "uuid-bbb"),
        _edge("IN_SUBNET", "uuid-bbb", "10.0.0.0/24"),
    ]
    _EDGES_B = [
        _edge("IN_SUBNET", "uuid-bbb", "10.0.0.0/24"),
        _edge("HAS_INTERFACE", "uuid-aaa", "uuid-bbb"),
    ]

    def test_node_order_irrelevant(self) -> None:
        s1 = build_snapshot(self._NODES_A, self._EDGES_A)
        s2 = build_snapshot(self._NODES_B, self._EDGES_A)
        assert s1["nodes"] == s2["nodes"]

    def test_edge_order_irrelevant(self) -> None:
        s1 = build_snapshot(self._NODES_A, self._EDGES_A)
        s2 = build_snapshot(self._NODES_A, self._EDGES_B)
        assert s1["edges"] == s2["edges"]

    def test_fully_shuffled_identical(self) -> None:
        s1 = build_snapshot(self._NODES_A, self._EDGES_A)
        s2 = build_snapshot(self._NODES_B, self._EDGES_B)
        assert s1 == s2

    def test_json_serialisable(self) -> None:
        snap = build_snapshot(self._NODES_A, self._EDGES_A)
        # Must not raise
        roundtripped = json.loads(json.dumps(snap))
        assert roundtripped == snap


class TestBuildSnapshotCanonicalForm:
    """Nodes are [label, key] pairs; edges are [type, src, dst] triples."""

    def test_nodes_are_label_key_pairs(self) -> None:
        snap = build_snapshot([_node("Device", "id-1")], [])
        assert snap["nodes"] == [["Device", "id-1"]]

    def test_edges_are_type_src_dst_triples(self) -> None:
        snap = build_snapshot([], [_edge("HAS_INTERFACE", "src", "dst")])
        assert snap["edges"] == [["HAS_INTERFACE", "src", "dst"]]

    def test_empty_inputs_produce_empty_lists(self) -> None:
        snap = build_snapshot([], [])
        assert snap == {"nodes": [], "edges": []}

    def test_nodes_sorted_label_then_key(self) -> None:
        nodes = [
            _node("Subnet", "192.168.0.0/24"),
            _node("Device", "z-uuid"),
            _node("Device", "a-uuid"),
            _node("Interface", "i-uuid"),
        ]
        snap = build_snapshot(nodes, [])
        # Alphabetical by label first, then key within label
        labels_keys = [(n[0], n[1]) for n in snap["nodes"]]
        assert labels_keys == sorted(labels_keys)

    def test_edges_sorted_type_src_dst(self) -> None:
        edges = [
            _edge("ROUTES_TO", "dev-b", "10.0.0.0/8"),
            _edge("HAS_INTERFACE", "dev-a", "if-1"),
            _edge("HAS_INTERFACE", "dev-a", "if-2"),
        ]
        snap = build_snapshot([], edges)
        triples = [(e[0], e[1], e[2]) for e in snap["edges"]]
        assert triples == sorted(triples)

    def test_duplicate_nodes_deduplicated(self) -> None:
        nodes = [
            _node("Device", "same"),
            _node("Device", "same"),
        ]
        snap = build_snapshot(nodes, [])
        assert snap["nodes"] == [["Device", "same"]]

    def test_duplicate_edges_deduplicated(self) -> None:
        edges = [
            _edge("HAS_INTERFACE", "dev", "iface"),
            _edge("HAS_INTERFACE", "dev", "iface"),
        ]
        snap = build_snapshot([], edges)
        assert snap["edges"] == [["HAS_INTERFACE", "dev", "iface"]]


# ---------------------------------------------------------------------------
# upsert_snapshot — persistence tests (require DB session)
# ---------------------------------------------------------------------------


class TestUpsertSnapshot:
    """upsert_snapshot writes / updates the row keyed by run_id."""

    @pytest.mark.asyncio
    async def test_inserts_new_row(self, session: AsyncSession, run: DiscoveryRun) -> None:
        nodes = [_node("Device", "d1")]
        edges = [_edge("HAS_INTERFACE", "d1", "i1")]
        snap_data = build_snapshot(nodes, edges)

        row = await upsert_snapshot(session, run_id=run.id, nodes=nodes, edges=edges)
        assert row.run_id == run.id
        assert row.nodes == snap_data["nodes"]
        assert row.edges == snap_data["edges"]

    @pytest.mark.asyncio
    async def test_second_call_updates_in_place(
        self, session: AsyncSession, run: DiscoveryRun
    ) -> None:
        nodes_v1 = [_node("Device", "d1")]
        edges_v1: list[list[str]] = []
        row_v1 = await upsert_snapshot(session, run_id=run.id, nodes=nodes_v1, edges=edges_v1)
        original_id = row_v1.id

        nodes_v2 = [_node("Device", "d1"), _node("Interface", "i1")]
        edges_v2 = [_edge("HAS_INTERFACE", "d1", "i1")]
        row_v2 = await upsert_snapshot(session, run_id=run.id, nodes=nodes_v2, edges=edges_v2)

        # Same PK — not a second row
        assert row_v2.id == original_id
        # Content updated
        assert len(row_v2.nodes) == 2
        assert len(row_v2.edges) == 1

    @pytest.mark.asyncio
    async def test_different_runs_produce_different_rows(self, session: AsyncSession) -> None:
        run_a = DiscoveryRun(seeds=[], hop_limit=1, allowlist=[], credential_names=[], stats={})
        run_b = DiscoveryRun(seeds=[], hop_limit=1, allowlist=[], credential_names=[], stats={})
        session.add_all([run_a, run_b])
        await session.flush()

        nodes = [_node("Device", "d1")]
        edges: list[list[str]] = []
        row_a = await upsert_snapshot(session, run_id=run_a.id, nodes=nodes, edges=edges)
        row_b = await upsert_snapshot(session, run_id=run_b.id, nodes=nodes, edges=edges)

        assert row_a.id != row_b.id
        assert row_a.run_id == run_a.id
        assert row_b.run_id == run_b.id

    @pytest.mark.asyncio
    async def test_upsert_is_idempotent(self, session: AsyncSession, run: DiscoveryRun) -> None:
        """Calling upsert twice with identical data must not change the row."""
        nodes = [_node("Device", "d1")]
        edges = [_edge("HAS_INTERFACE", "d1", "i1")]

        row_1 = await upsert_snapshot(session, run_id=run.id, nodes=nodes, edges=edges)
        row_2 = await upsert_snapshot(session, run_id=run.id, nodes=nodes, edges=edges)

        assert row_1.id == row_2.id
        assert row_1.nodes == row_2.nodes
        assert row_1.edges == row_2.edges

    @pytest.mark.asyncio
    async def test_row_has_timestamps(self, session: AsyncSession, run: DiscoveryRun) -> None:
        row = await upsert_snapshot(session, run_id=run.id, nodes=[], edges=[])
        assert row.created_at is not None
        assert row.updated_at is not None
        # Must be tz-aware (UTC)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None
