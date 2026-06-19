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
    REL_CONNECTED_TO,
    REL_HAS_INTERFACE,
    REL_IN_ZONE,
    REL_RESOLVES_TO,
    REL_ROUTES_TO,
)
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
            if site is not None and not (
                rec["a_props"].get("site") == site or rec["b_props"].get("site") == site
            ):
                continue
            if (
                vrf is not None
                and rec["rel_type"] == REL_ROUTES_TO
                and rec["rel_props"].get("vrf") != vrf
            ):
                continue
            out.append(rec)
        return _FakeResult(out)


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
        # Only the lon<->nyc CONNECTED_TO edge touches site=lon.
        assert len(body["edges"]) == 1
        assert {n["key"] for n in body["nodes"]} == {"dev-c", "dev-a"}

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
