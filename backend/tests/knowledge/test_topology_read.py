"""Unit tests for the read-side topology queries (:mod:`app.knowledge.topology_read`).

Focus: :func:`fetch_neighborhood` (audit Wave 5, ARCH_DEBT #7) — subgraph
membership, depth bounds, layer filtering, the isolated-center and
unknown-device edges.  No Neo4j: the fake transaction mirrors the two Cypher
statements the production worker issues (center-device lookup + variable-length
edge collection) with the same semantics — an edge is on some undirected path
of length ``<= depth`` from the center iff its nearer endpoint is within
``depth - 1`` hops — so the worker's dedup / center-inclusion / coercion logic
is under test rather than stubbed out.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from app.knowledge.schema import (
    NODE_KEY_PROPERTY,
    REL_CONNECTED_TO,
    REL_ROUTES_TO,
)
from app.knowledge.topology_read import (
    MAX_NEIGHBORHOOD_DEPTH,
    fetch_neighborhood,
)

PROJECTED_AT = "2026-07-04T10:00:00+00:00"
EARLIER = "2026-07-04T09:00:00+00:00"


# ---------------------------------------------------------------------------
# Fake Neo4j transaction with variable-length-path semantics
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return self._gen()

    async def _gen(self) -> AsyncIterator[dict[str, Any]]:
        for record in self._records:
            yield record


def _node_key(label: str, props: dict[str, Any]) -> Any:
    return props.get(NODE_KEY_PROPERTY[label])


class _FakeTx:
    """Mirrors the two statements :func:`_read_neighborhood` runs.

    ``standalone_nodes`` covers projected nodes with no edges at all (an
    isolated device exists in the graph but appears in no edge record).
    """

    def __init__(
        self,
        records: list[dict[str, Any]],
        standalone_nodes: list[tuple[str, dict[str, Any]]] | None = None,
    ) -> None:
        self._records = records
        self._standalone = standalone_nodes or []

    async def run(self, cypher: str, **params: Any) -> _FakeResult:
        if "RETURN labels(d) AS labels" in cypher:
            return _FakeResult(self._device_lookup(params["device"]))
        if "relationships(p)" in cypher:
            return _FakeResult(self._neighborhood_edges(cypher, params["device"]))
        raise AssertionError(f"unexpected cypher: {cypher}")

    def _all_device_nodes(self) -> list[dict[str, Any]]:
        nodes: dict[Any, dict[str, Any]] = {}
        for label, props in self._standalone:
            if label == "Device":
                nodes[_node_key(label, props)] = props
        for rec in self._records:
            for labels, props in (
                (rec["a_labels"], rec["a_props"]),
                (rec["b_labels"], rec["b_props"]),
            ):
                if "Device" in labels:
                    nodes[_node_key("Device", props)] = props
        return [{"key": key, "props": props} for key, props in nodes.items()]

    def _device_lookup(self, device: str) -> list[dict[str, Any]]:
        return [
            {"labels": ["Device"], "props": entry["props"]}
            for entry in self._all_device_nodes()
            if entry["key"] == device
        ]

    def _neighborhood_edges(self, cypher: str, device: str) -> list[dict[str, Any]]:
        # Parse the validated literals out of the pattern the worker built.
        match = re.search(r"\[:([A-Z0-9_|]+)\*1\.\.(\d+)\]", cypher)
        assert match is not None, cypher
        selected = set(match.group(1).split("|"))
        depth = int(match.group(2))

        # Undirected BFS distances over the layer-filtered edge set.
        survivors = [rec for rec in self._records if rec["rel_type"] in selected]
        adjacency: dict[Any, set[Any]] = {}
        for rec in survivors:
            a = _node_key(rec["a_labels"][0], rec["a_props"])
            b = _node_key(rec["b_labels"][0], rec["b_props"])
            adjacency.setdefault(a, set()).add(b)
            adjacency.setdefault(b, set()).add(a)
        dist: dict[Any, int] = {device: 0}
        queue: deque[Any] = deque([device])
        while queue:
            here = queue.popleft()
            for neighbor in adjacency.get(here, ()):
                if neighbor not in dist:
                    dist[neighbor] = dist[here] + 1
                    queue.append(neighbor)

        # A relationship lies on a path of length <= depth from the center iff
        # its nearer endpoint is strictly within the radius.
        out: list[dict[str, Any]] = []
        for rec in survivors:
            a = _node_key(rec["a_labels"][0], rec["a_props"])
            b = _node_key(rec["b_labels"][0], rec["b_props"])
            nearer = min(dist.get(a, depth + 1), dist.get(b, depth + 1))
            if nearer <= depth - 1:
                out.append(rec)
        return out


class FakeKnowledgeClient:
    def __init__(
        self,
        records: list[dict[str, Any]],
        standalone_nodes: list[tuple[str, dict[str, Any]]] | None = None,
    ) -> None:
        self._tx = _FakeTx(records, standalone_nodes)

    async def execute_read(self, work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await work(self._tx, *args, **kwargs)


# ---------------------------------------------------------------------------
# Seed graph: a 4-device chain plus a subnet spur
#
#   dev-a --CONNECTED_TO-- dev-b --CONNECTED_TO-- dev-c --CONNECTED_TO-- dev-d
#                            |
#                        ROUTES_TO
#                            |
#                        10.0.0.0/24
# ---------------------------------------------------------------------------


def _dev(pg_id: str, hostname: str, stamp: str = PROJECTED_AT) -> dict[str, Any]:
    return {"pg_id": pg_id, "hostname": hostname, "site": "nyc", "last_projected_at": stamp}


def _edge(
    rel_type: str,
    a_label: str,
    a_props: dict[str, Any],
    b_label: str,
    b_props: dict[str, Any],
) -> dict[str, Any]:
    return {
        "a_labels": [a_label],
        "a_props": a_props,
        "b_labels": [b_label],
        "b_props": b_props,
        "rel_type": rel_type,
        "rel_props": {"last_projected_at": PROJECTED_AT},
    }


def _chain_records() -> list[dict[str, Any]]:
    dev_a = _dev("dev-a", "sw-01", stamp=EARLIER)
    dev_b = _dev("dev-b", "sw-02")
    dev_c = _dev("dev-c", "sw-03")
    dev_d = _dev("dev-d", "sw-04")
    subnet = {"cidr": "10.0.0.0/24", "last_projected_at": PROJECTED_AT}
    return [
        _edge(REL_CONNECTED_TO, "Device", dev_a, "Device", dev_b),
        _edge(REL_CONNECTED_TO, "Device", dev_b, "Device", dev_c),
        _edge(REL_CONNECTED_TO, "Device", dev_c, "Device", dev_d),
        _edge(REL_ROUTES_TO, "Device", dev_b, "Subnet", subnet),
    ]


@pytest.fixture()
def client() -> FakeKnowledgeClient:
    return FakeKnowledgeClient(_chain_records())


# ---------------------------------------------------------------------------
# fetch_neighborhood
# ---------------------------------------------------------------------------


class TestFetchNeighborhood:
    async def test_depth_1_returns_direct_neighbors_only(self, client: FakeKnowledgeClient) -> None:
        graph = await fetch_neighborhood(client, device="dev-a", depth=1, layer="all")
        assert graph is not None
        assert {n["key"] for n in graph["nodes"]} == {"dev-a", "dev-b"}
        assert len(graph["edges"]) == 1
        assert graph["edges"][0]["type"] == REL_CONNECTED_TO

    async def test_depth_2_reaches_two_hops_and_the_spur(self, client: FakeKnowledgeClient) -> None:
        graph = await fetch_neighborhood(client, device="dev-a", depth=2, layer="all")
        assert graph is not None
        # dev-c and the subnet are both 2 hops out; dev-d (3 hops) is excluded.
        assert {n["key"] for n in graph["nodes"]} == {"dev-a", "dev-b", "dev-c", "10.0.0.0/24"}
        assert len(graph["edges"]) == 3

    async def test_depth_bound_excludes_beyond_radius(self, client: FakeKnowledgeClient) -> None:
        graph = await fetch_neighborhood(client, device="dev-a", depth=3, layer="all")
        assert graph is not None
        assert {n["key"] for n in graph["nodes"]} == {
            "dev-a",
            "dev-b",
            "dev-c",
            "dev-d",
            "10.0.0.0/24",
        }

    async def test_traversal_is_undirected(self, client: FakeKnowledgeClient) -> None:
        # dev-d is only the *target* of directed edges; walking from it must
        # still reach backwards up the chain.
        graph = await fetch_neighborhood(client, device="dev-d", depth=1, layer="all")
        assert graph is not None
        assert {n["key"] for n in graph["nodes"]} == {"dev-c", "dev-d"}

    async def test_layer_filters_relationship_families(self, client: FakeKnowledgeClient) -> None:
        graph = await fetch_neighborhood(client, device="dev-b", depth=1, layer="l3")
        assert graph is not None
        # Only the ROUTES_TO spur survives the l3 layer; CONNECTED_TO is l2.
        assert {n["key"] for n in graph["nodes"]} == {"dev-b", "10.0.0.0/24"}
        assert {e["type"] for e in graph["edges"]} == {REL_ROUTES_TO}

    async def test_isolated_device_returns_center_only(self) -> None:
        isolated = FakeKnowledgeClient(
            _chain_records(),
            standalone_nodes=[("Device", _dev("dev-x", "lonely-sw"))],
        )
        graph = await fetch_neighborhood(isolated, device="dev-x", depth=2, layer="all")
        assert graph is not None
        assert [n["key"] for n in graph["nodes"]] == ["dev-x"]
        assert graph["edges"] == []
        assert graph["projected_at"] == PROJECTED_AT

    async def test_unknown_device_returns_none(self, client: FakeKnowledgeClient) -> None:
        assert await fetch_neighborhood(client, device="no-such", depth=2, layer="all") is None

    async def test_projected_at_is_most_recent_stamp(self, client: FakeKnowledgeClient) -> None:
        graph = await fetch_neighborhood(client, device="dev-a", depth=1, layer="all")
        assert graph is not None
        # dev-a carries the EARLIER stamp; dev-b's newer one wins.
        assert graph["projected_at"] == PROJECTED_AT

    @pytest.mark.parametrize("depth", [0, -1, MAX_NEIGHBORHOOD_DEPTH + 1])
    async def test_out_of_range_depth_is_rejected(
        self, client: FakeKnowledgeClient, depth: int
    ) -> None:
        with pytest.raises(ValueError, match="depth must be between"):
            await fetch_neighborhood(client, device="dev-a", depth=depth, layer="all")
