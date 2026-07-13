"""Tests for the topology API (M2-10): graph read + snapshot diff.

Runs entirely in-process over the shared ``tests/api/conftest.py`` fixtures —
no Postgres, Neo4j, Docker, or network.  The Neo4j read path is exercised
through a fake knowledge client (:class:`FakeKnowledgeClient`) injected via
``app.api.deps.get_knowledge_client``; the diff path reads real
``topology_snapshots`` rows from the in-memory aiosqlite session.

The fake mirrors :meth:`Neo4jClient.execute_read`: it invokes the read worker
with a fake transaction whose ``run`` yields the seeded edge records that
survive the same ``site`` / ``vrf`` / relationship-type filters the production
Cypher applies, so the worker's node-dedup / projected_at / coercion logic is
under test rather than stubbed out.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.knowledge.schema import (
    NODE_KEY_PROPERTY,
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_ZONE,
    REL_RESOLVES_TO,
    REL_ROUTES_TO,
)
from app.knowledge.topology_read import _DNS_REL_TYPES
from app.models import DiscoveryRun, TopologySnapshot

PROJECTED_AT = "2026-06-12T22:00:00+00:00"
EARLIER_PROJECTED_AT = "2026-06-12T21:00:00+00:00"


# ---------------------------------------------------------------------------
# Fake Neo4j knowledge client
# ---------------------------------------------------------------------------


class _FakeResult:
    """Async-iterable over a fixed list of record dicts (mirrors driver result)."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return self._gen()

    async def _gen(self) -> AsyncIterator[dict[str, Any]]:
        for record in self._records:
            yield record


class _FakeTx:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    async def run(self, cypher: str, **params: Any) -> _FakeResult:
        # Dispatch on the statement shape the read workers build: the
        # neighborhood reader's center-device lookup and variable-length edge
        # collection, or the full-graph edge match.
        if "RETURN labels(d) AS labels" in cypher:
            return _FakeResult(self._device_lookup(params["device"]))
        if "relationships(p)" in cypher:
            return _FakeResult(self._neighborhood_edges(cypher, params["device"]))
        # Parse the selected relationship types out of the type pattern the
        # worker built, then apply the same site/vrf predicates the Cypher does.
        rel_segment = cypher.split("[r:", 1)[1].split("]", 1)[0]
        selected = set(rel_segment.split("|"))
        site = params.get("site")
        vrf = params.get("vrf")
        out: list[dict[str, Any]] = []
        for rec in self._records:
            if rec["rel_type"] not in selected:
                continue
            if (
                site is not None
                and rec["rel_type"] not in _DNS_REL_TYPES
                and not (rec["a_props"].get("site") == site or rec["b_props"].get("site") == site)
            ):
                continue
            if (
                vrf is not None
                and rec["rel_type"] == REL_ROUTES_TO
                and rec["rel_props"].get("vrf") != vrf
            ):
                continue
            out.append(rec)
        if "count(DISTINCT n)" in cypher:
            # The cap pre-check: same filters, only the distinct-node count.
            identities = {
                (labels[0], props.get(NODE_KEY_PROPERTY[labels[0]]))
                for rec in out
                for labels, props in (
                    (rec["a_labels"], rec["a_props"]),
                    (rec["b_labels"], rec["b_props"]),
                )
            }
            return _FakeResult([{"node_count": len(identities)}])
        if "max(n.last_projected_at)" in cypher:
            # The ETag watermark: same filters, only the max projection stamp.
            stamps = [
                stamp
                for rec in out
                for props in (rec["a_props"], rec["b_props"])
                if (stamp := props.get("last_projected_at")) is not None
            ]
            return _FakeResult([{"projected_at": max(stamps) if stamps else None}])
        return _FakeResult(out)

    def _device_lookup(self, device: str) -> list[dict[str, Any]]:
        for rec in self._records:
            for labels, props in (
                (rec["a_labels"], rec["a_props"]),
                (rec["b_labels"], rec["b_props"]),
            ):
                if "Device" in labels and props.get("pg_id") == device:
                    return [{"labels": ["Device"], "props": props}]
        return []

    def _neighborhood_edges(self, cypher: str, device: str) -> list[dict[str, Any]]:
        # Mirror variable-length path semantics: parse the validated literals
        # (rel types + depth) out of the pattern, BFS undirected over the
        # layer-filtered edges, and keep a relationship iff its nearer endpoint
        # is strictly within the radius.
        import re
        from collections import deque

        match = re.search(r"\[:([A-Z0-9_|]+)\*1\.\.(\d+)\]", cypher)
        assert match is not None, cypher
        selected = set(match.group(1).split("|"))
        depth = int(match.group(2))

        def _key(labels: list[str], props: dict[str, Any]) -> Any:
            if "Device" in labels or "Interface" in labels or "IPAddress" in labels:
                return props.get("pg_id")
            return (
                props.get("cidr")
                or props.get("fqdn")
                or props.get("record_key")
                or props.get("name")
            )

        survivors = [rec for rec in self._records if rec["rel_type"] in selected]
        adjacency: dict[Any, set[Any]] = {}
        for rec in survivors:
            a = _key(rec["a_labels"], rec["a_props"])
            b = _key(rec["b_labels"], rec["b_props"])
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
        out = []
        for rec in survivors:
            a = _key(rec["a_labels"], rec["a_props"])
            b = _key(rec["b_labels"], rec["b_props"])
            if min(dist.get(a, depth + 1), dist.get(b, depth + 1)) <= depth - 1:
                out.append(rec)
        return out


class FakeKnowledgeClient:
    """Stand-in for :class:`app.knowledge.Neo4jClient` (read path only)."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    async def execute_read(self, work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await work(_FakeTx(self._records), *args, **kwargs)


def _edge_record(
    *,
    rel_type: str,
    a_label: str,
    a_props: dict[str, Any],
    b_label: str,
    b_props: dict[str, Any],
    rel_props: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "a_labels": [a_label],
        "a_props": a_props,
        "b_labels": [b_label],
        "b_props": b_props,
        "rel_type": rel_type,
        "rel_props": rel_props or {"last_projected_at": PROJECTED_AT},
    }


def _seed_records() -> list[dict[str, Any]]:
    """A small projected graph spanning two sites, L2 and L3 edges."""

    def _dev(pg_id: str, hostname: str, site: str, stamp: str) -> dict[str, Any]:
        return {"pg_id": pg_id, "hostname": hostname, "site": site, "last_projected_at": stamp}

    dev_a = _dev("dev-a", "core-sw-01", "nyc", PROJECTED_AT)
    dev_b = _dev("dev-b", "edge-rt-01", "nyc", EARLIER_PROJECTED_AT)
    dev_c = _dev("dev-c", "lon-sw-01", "lon", PROJECTED_AT)
    subnet = {"cidr": "10.0.0.0/24", "last_projected_at": PROJECTED_AT}
    # DNS-dependency layer (M5 task #13): one zone, one record resolving to a
    # known IPAddress node (reconciled against the L3 projection).
    zone = {"fqdn": "corp.example.com", "last_projected_at": PROJECTED_AT}
    record = {
        "record_key": "www.corp.example.com|a|10.0.0.9",
        "name": "www.corp.example.com",
        "record_type": "a",
        "value": "10.0.0.9",
        "zone": "corp.example.com",
        "last_projected_at": PROJECTED_AT,
    }
    ipaddr = {"pg_id": "if-1", "address": "10.0.0.9", "last_projected_at": PROJECTED_AT}
    return [
        _edge_record(
            rel_type=REL_CONNECTED_TO,
            a_label="Device",
            a_props=dev_a,
            b_label="Device",
            b_props=dev_b,
            rel_props={"protocols": ["lldp"], "last_projected_at": PROJECTED_AT},
        ),
        _edge_record(
            rel_type=REL_CONNECTED_TO,
            a_label="Device",
            a_props=dev_c,
            b_label="Device",
            b_props=dev_a,
            rel_props={"protocols": ["cdp"], "last_projected_at": PROJECTED_AT},
        ),
        _edge_record(
            rel_type=REL_ROUTES_TO,
            a_label="Device",
            a_props=dev_a,
            b_label="Subnet",
            b_props=subnet,
            rel_props={"vrf": "blue", "protocol": "ospf", "last_projected_at": PROJECTED_AT},
        ),
        _edge_record(
            rel_type=REL_IN_ZONE,
            a_label="DnsZone",
            a_props=zone,
            b_label="DnsRecord",
            b_props=record,
            rel_props={"last_projected_at": PROJECTED_AT},
        ),
        _edge_record(
            rel_type=REL_RESOLVES_TO,
            a_label="DnsRecord",
            a_props=record,
            b_label="IPAddress",
            b_props=ipaddr,
            rel_props={"value": "10.0.0.9", "last_projected_at": PROJECTED_AT},
        ),
    ]


@pytest.fixture()
def graph_records() -> list[dict[str, Any]]:
    return _seed_records()


@pytest.fixture()
def fake_client(graph_records: list[dict[str, Any]]) -> FakeKnowledgeClient:
    return FakeKnowledgeClient(graph_records)


@pytest.fixture()
def app_with_graph(app: FastAPI, fake_client: FakeKnowledgeClient) -> FastAPI:
    """The shared API app with the Neo4j client dependency overridden."""
    app.dependency_overrides[deps.get_knowledge_client] = lambda: fake_client
    return app


@pytest.fixture()
async def graph_client(app_with_graph: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app_with_graph)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


# ---------------------------------------------------------------------------
# Postgres snapshot helpers (diff endpoint)
# ---------------------------------------------------------------------------


def _make_run() -> DiscoveryRun:
    return DiscoveryRun(
        seeds=["192.0.2.10"],
        hop_limit=1,
        allowlist=["192.0.2.0/24"],
        credential_names=["lab-ssh"],
        created_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
        updated_at=datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
    )


async def _seed_snapshot(
    session: AsyncSession,
    *,
    run_id: uuid.UUID,
    nodes: list[list[str]],
    edges: list[list[str]],
) -> None:
    session.add(TopologySnapshot(run_id=run_id, nodes=nodes, edges=edges))
    await session.flush()


# ---------------------------------------------------------------------------
# GET /topology/graph
# ---------------------------------------------------------------------------


class TestGraph:
    async def test_all_layers_returns_nodes_edges_and_projected_at(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get("/api/v1/topology/graph", headers=auth_headers("viewer"))
        assert response.status_code == 200, response.text
        body = response.json()
        # Three devices + one subnet (L2/L3) plus the DNS-layer zone/record/ip.
        labels = sorted(n["label"] for n in body["nodes"])
        assert labels == [
            "Device",
            "Device",
            "Device",
            "DnsRecord",
            "DnsZone",
            "IPAddress",
            "Subnet",
        ]
        keys = {n["key"] for n in body["nodes"]}
        assert keys == {
            "dev-a",
            "dev-b",
            "dev-c",
            "10.0.0.0/24",
            "corp.example.com",
            "www.corp.example.com|a|10.0.0.9",
            "if-1",
        }
        # 2 CONNECTED_TO + 1 ROUTES_TO + 1 IN_ZONE + 1 RESOLVES_TO.
        assert len(body["edges"]) == 5
        # projected_at is the MOST RECENT stamp across nodes (dev-b is older).
        assert body["projected_at"] == PROJECTED_AT

    async def test_if_none_match_hit_returns_304_with_no_body(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """A matching ``If-None-Match`` poll is answered 304 from the watermark.

        Wave 5 server-side ETag half: the 304 must carry the same ``ETag`` /
        ``Cache-Control`` pair as the 200 it validates, with an empty body —
        the graph itself is never materialized.
        """
        first = await graph_client.get("/api/v1/topology/graph", headers=auth_headers("viewer"))
        assert first.status_code == 200, first.text
        etag = first.headers["ETag"]
        assert etag.startswith('W/"')
        assert first.headers["Cache-Control"] == "private, max-age=5"

        second = await graph_client.get(
            "/api/v1/topology/graph",
            headers={**auth_headers("viewer"), "If-None-Match": etag},
        )
        assert second.status_code == 304, second.text
        assert second.headers["ETag"] == etag
        assert second.headers["Cache-Control"] == "private, max-age=5"
        assert second.content == b""

    async def test_if_none_match_miss_returns_full_body(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """A stale validator falls through to the normal 200 + fresh ETag."""
        response = await graph_client.get(
            "/api/v1/topology/graph",
            headers={**auth_headers("viewer"), "If-None-Match": 'W/"deadbeefdeadbeef"'},
        )
        assert response.status_code == 200, response.text
        assert response.json()["projected_at"] == PROJECTED_AT
        assert response.headers["ETag"].startswith('W/"')

    async def test_etag_is_scoped_to_query_params(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """An ETag minted for one param set never 304s a different one."""
        full = await graph_client.get("/api/v1/topology/graph", headers=auth_headers("viewer"))
        assert full.status_code == 200, full.text
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "l2"},
            headers={**auth_headers("viewer"), "If-None-Match": full.headers["ETag"]},
        )
        assert response.status_code == 200, response.text
        assert response.headers["ETag"] != full.headers["ETag"]

    async def test_empty_graph_poll_never_304s_and_has_no_etag(
        self,
        app: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """An empty subgraph has no watermark: no ETag is minted, never a 304."""
        app.dependency_overrides[deps.get_knowledge_client] = lambda: FakeKnowledgeClient([])
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
            response = await c.get(
                "/api/v1/topology/graph",
                headers={**auth_headers("viewer"), "If-None-Match": 'W/"deadbeefdeadbeef"'},
            )
        assert response.status_code == 200, response.text
        assert response.json()["nodes"] == []
        assert "ETag" not in response.headers

    async def test_layer_l2_returns_only_connected_to(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "l2"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert {e["type"] for e in body["edges"]} == {REL_CONNECTED_TO}
        assert "Subnet" not in {n["label"] for n in body["nodes"]}

    async def test_layer_l3_excludes_connected_to(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "l3"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert {e["type"] for e in body["edges"]} == {REL_ROUTES_TO}

    async def test_layer_dns_returns_only_dns_dependency_edges(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "dns"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert {e["type"] for e in body["edges"]} == {REL_IN_ZONE, REL_RESOLVES_TO}
        labels = sorted(n["label"] for n in body["nodes"])
        assert labels == ["DnsRecord", "DnsZone", "IPAddress"]
        # No L2/L3 leakage into the DNS layer.
        assert "Device" not in labels
        assert "Subnet" not in labels

    async def test_layer_dns_resolves_to_edge_targets_reconciled_ipaddress(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "dns"},
            headers=auth_headers("viewer"),
        )
        body = response.json()
        resolves = [e for e in body["edges"] if e["type"] == REL_RESOLVES_TO]
        assert len(resolves) == 1
        edge = resolves[0]
        # The record key resolves onto the IPAddress projected node (if-1).
        assert edge["source"] == "www.corp.example.com|a|10.0.0.9"
        assert edge["target"] == "if-1"
        assert edge["properties"]["value"] == "10.0.0.9"

    async def test_layer_dns_with_site_still_returns_dns_edges(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """layer=dns combined with a non-null site must NOT silently drop DNS edges.

        DnsZone / DnsRecord / IPAddress nodes carry no .site property; the site
        predicate must be bypassed for the DNS relationship family so that the
        full DNS layer is returned regardless of which site is requested.
        """
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "dns", "site": "nyc"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # Both DNS edges must survive — site filter must not silently empty them.
        assert {e["type"] for e in body["edges"]} == {REL_IN_ZONE, REL_RESOLVES_TO}
        labels = sorted(n["label"] for n in body["nodes"])
        assert labels == ["DnsRecord", "DnsZone", "IPAddress"]

    async def test_layer_dns_with_unknown_site_still_returns_dns_edges(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """Even a site that matches no Device must not drop DNS-layer edges."""
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "dns", "site": "nonexistent-site"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert {e["type"] for e in body["edges"]} == {REL_IN_ZONE, REL_RESOLVES_TO}

    async def test_site_filter_scopes_subgraph(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"site": "lon"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # L2/L3 edges: only the lon<->nyc CONNECTED_TO edge touches site=lon.
        # DNS edges (IN_ZONE, RESOLVES_TO) always pass through — DnsZone /
        # DnsRecord / IPAddress nodes carry no .site property, so the site
        # predicate is bypassed for the DNS relationship family.
        l2l3_edges = [e for e in body["edges"] if e["type"] not in {REL_IN_ZONE, REL_RESOLVES_TO}]
        dns_edges = [e for e in body["edges"] if e["type"] in {REL_IN_ZONE, REL_RESOLVES_TO}]
        assert len(l2l3_edges) == 1
        assert l2l3_edges[0]["type"] == REL_CONNECTED_TO
        assert len(dns_edges) == 2
        assert {n["key"] for n in body["nodes"] if n["label"] == "Device"} == {"dev-c", "dev-a"}

    async def test_vrf_filter_scopes_routes(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "l3", "vrf": "red"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # The only ROUTES_TO edge is in vrf 'blue' — 'red' yields an empty graph.
        assert body["edges"] == []
        assert body["nodes"] == []
        assert body["projected_at"] is None

    async def test_empty_graph_projected_at_is_null(
        self,
        app: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        app.dependency_overrides[deps.get_knowledge_client] = lambda: FakeKnowledgeClient([])
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
            response = await c.get("/api/v1/topology/graph", headers=auth_headers("viewer"))
        assert response.status_code == 200
        body = response.json()
        assert body == {"nodes": [], "edges": [], "projected_at": None}

    async def test_invalid_layer_is_422(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph",
            params={"layer": "l7"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 422

    async def test_unauthenticated_is_401(self, graph_client: httpx.AsyncClient) -> None:
        response = await graph_client.get("/api/v1/topology/graph")
        assert response.status_code == 401

    async def test_inactive_user_is_401(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph", headers=auth_headers("inactive")
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /topology/graph — topology_max_nodes cap (audit Wave 5)
# ---------------------------------------------------------------------------


class TestGraphCap:
    """The seeded graph has 7 distinct nodes (3 devices, subnet, zone, record, ip)."""

    async def _get(
        self,
        app: FastAPI,
        headers: dict[str, str],
        path: str = "/api/v1/topology/graph",
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
            return await c.get(path, params=params, headers=headers)

    async def test_over_cap_graph_is_413_problem_never_truncated(
        self,
        app_with_graph: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        app_with_graph.state.settings.topology_max_nodes = 3
        response = await self._get(app_with_graph, auth_headers("viewer"))
        assert response.status_code == 413, response.text
        assert response.headers["content-type"].startswith("application/problem+json")
        body = response.json()
        assert body["type"] == "urn:netops:error:graph-too-large"
        # The detail carries the count, the limit, and the scoped alternatives.
        assert "7 nodes" in body["detail"]
        assert "3-node" in body["detail"]
        assert "neighborhood" in body["detail"]

    async def test_under_cap_graph_is_unchanged_200(
        self,
        app_with_graph: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        app_with_graph.state.settings.topology_max_nodes = 7
        response = await self._get(app_with_graph, auth_headers("viewer"))
        assert response.status_code == 200, response.text
        assert len(response.json()["nodes"]) == 7

    async def test_zero_disables_the_guard(
        self,
        app_with_graph: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        app_with_graph.state.settings.topology_max_nodes = 0
        response = await self._get(app_with_graph, auth_headers("viewer"))
        assert response.status_code == 200, response.text
        assert len(response.json()["nodes"]) == 7

    async def test_site_scoped_read_is_also_guarded(
        self,
        app_with_graph: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        # site=lon still spans 5 nodes (dev-a/dev-c + the site-exempt DNS
        # island); an over-cap scoped read must refuse too, not stream.
        app_with_graph.state.settings.topology_max_nodes = 4
        response = await self._get(app_with_graph, auth_headers("viewer"), params={"site": "lon"})
        assert response.status_code == 413, response.text

    async def test_stale_count_cannot_leak_an_over_cap_200(
        self,
        app: FastAPI,
        graph_records: list[dict[str, Any]],
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        """The pre-check races a concurrent projection (read-committed Neo4j).

        Simulate the graph growing between the count and the read: the count
        statement reports under-cap, but the read materializes 7 nodes.  The
        post-fetch guard must still refuse with a 413 — an over-cap 200 is
        never a legal response.
        """

        class StaleCountClient(FakeKnowledgeClient):
            async def execute_read(
                self, work: Callable[..., Any], *args: Any, **kwargs: Any
            ) -> Any:
                if getattr(work, "__name__", "") == "_count_graph_nodes":
                    return 0
                return await super().execute_read(work, *args, **kwargs)

        app.dependency_overrides[deps.get_knowledge_client] = lambda: StaleCountClient(
            graph_records
        )
        app.state.settings.topology_max_nodes = 3
        response = await self._get(app, auth_headers("viewer"))
        assert response.status_code == 413, response.text
        assert "7 nodes" in response.json()["detail"]

    async def test_neighborhood_is_exempt_from_the_cap(
        self,
        app_with_graph: FastAPI,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        # Depth-bounded by construction — usable even under an aggressive cap.
        app_with_graph.state.settings.topology_max_nodes = 1
        response = await self._get(
            app_with_graph,
            auth_headers("viewer"),
            path="/api/v1/topology/graph/neighborhood",
            params={"device": "dev-b", "depth": 1},
        )
        assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# GET /topology/graph/neighborhood
# ---------------------------------------------------------------------------


class TestNeighborhood:
    async def test_depth_1_returns_direct_neighbors_only(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            params={"device": "dev-b", "depth": 1},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert {n["key"] for n in body["nodes"]} == {"dev-a", "dev-b"}
        assert len(body["edges"]) == 1
        assert body["edges"][0]["type"] == REL_CONNECTED_TO
        assert body["projected_at"] == PROJECTED_AT

    async def test_depth_2_expands_the_radius(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            params={"device": "dev-b", "depth": 2},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        # Two hops from dev-b: dev-a (1), then dev-c and the subnet (2).  The
        # DNS island is disconnected from the device chain and must not appear.
        assert {n["key"] for n in body["nodes"]} == {"dev-a", "dev-b", "dev-c", "10.0.0.0/24"}
        assert len(body["edges"]) == 3

    async def test_layer_filters_the_walk(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            params={"device": "dev-a", "depth": 1, "layer": "l2"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert {e["type"] for e in body["edges"]} == {REL_CONNECTED_TO}
        assert "Subnet" not in {n["label"] for n in body["nodes"]}

    async def test_default_depth_is_2(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            params={"device": "dev-b"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        assert {n["key"] for n in response.json()["nodes"]} == {
            "dev-a",
            "dev-b",
            "dev-c",
            "10.0.0.0/24",
        }

    async def test_unknown_device_is_404_problem(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            params={"device": "no-such-device"},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/problem+json")

    @pytest.mark.parametrize("depth", [0, 6, -1])
    async def test_out_of_range_depth_is_422(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        depth: int,
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            params={"device": "dev-a", "depth": depth},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 422

    async def test_missing_device_param_is_422(
        self,
        graph_client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood",
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 422

    async def test_unauthenticated_is_401(self, graph_client: httpx.AsyncClient) -> None:
        response = await graph_client.get(
            "/api/v1/topology/graph/neighborhood", params={"device": "dev-a"}
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# GET /topology/diff
# ---------------------------------------------------------------------------


class TestDiff:
    async def test_diff_of_two_runs(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        from_run = _make_run()
        to_run = _make_run()
        session.add_all([from_run, to_run])
        await session.flush()
        await _seed_snapshot(
            session,
            run_id=from_run.id,
            nodes=[["Device", "dev-a"], ["Device", "dev-b"]],
            edges=[[REL_HAS_INTERFACE, "dev-a", "if-1"]],
        )
        await _seed_snapshot(
            session,
            run_id=to_run.id,
            nodes=[["Device", "dev-a"], ["Device", "dev-c"]],
            edges=[[REL_HAS_INTERFACE, "dev-a", "if-2"]],
        )
        await session.commit()

        response = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(from_run.id), "to_run": str(to_run.id)},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["from_run"] == str(from_run.id)
        assert body["to_run"] == str(to_run.id)
        diff = body["diff"]
        assert diff["nodes_added"] == [["Device", "dev-c"]]
        assert diff["nodes_removed"] == [["Device", "dev-b"]]
        assert diff["edges_added"] == [[REL_HAS_INTERFACE, "dev-a", "if-2"]]
        assert diff["edges_removed"] == [[REL_HAS_INTERFACE, "dev-a", "if-1"]]

    async def test_identical_snapshots_yield_empty_diff(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        from_run = _make_run()
        to_run = _make_run()
        session.add_all([from_run, to_run])
        await session.flush()
        nodes = [["Device", "dev-a"]]
        edges: list[list[str]] = []
        await _seed_snapshot(session, run_id=from_run.id, nodes=nodes, edges=edges)
        await _seed_snapshot(session, run_id=to_run.id, nodes=nodes, edges=edges)
        await session.commit()

        response = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(from_run.id), "to_run": str(to_run.id)},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 200
        diff = response.json()["diff"]
        assert diff == {
            "nodes_added": [],
            "nodes_removed": [],
            "edges_added": [],
            "edges_removed": [],
        }

    async def test_missing_from_snapshot_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        to_run = _make_run()
        session.add(to_run)
        await session.flush()
        await _seed_snapshot(session, run_id=to_run.id, nodes=[], edges=[])
        await session.commit()

        response = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(uuid.uuid4()), "to_run": str(to_run.id)},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/problem+json")

    async def test_missing_to_snapshot_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        from_run = _make_run()
        session.add(from_run)
        await session.flush()
        await _seed_snapshot(session, run_id=from_run.id, nodes=[], edges=[])
        await session.commit()

        response = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(from_run.id), "to_run": str(uuid.uuid4())},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 404

    async def test_invalid_run_id_is_422(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": "not-a-uuid", "to_run": str(uuid.uuid4())},
            headers=auth_headers("viewer"),
        )
        assert response.status_code == 422

    async def test_missing_params_is_422(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        response = await client.get("/api/v1/topology/diff", headers=auth_headers("viewer"))
        assert response.status_code == 422

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        response = await client.get(
            "/api/v1/topology/diff",
            params={"from_run": str(uuid.uuid4()), "to_run": str(uuid.uuid4())},
        )
        assert response.status_code == 401
