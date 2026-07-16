"""Tests for app.engines.topology.projector — the Postgres -> Neo4j writer.

Unit tests run without a live Neo4j: a ``FakeClient`` captures every Cypher
statement and its parameters so the upsert set, the stale sweep, and the
rebuild order can be asserted exactly.

One ``@pytest.mark.integration`` test exercises the real thing against the
compose Neo4j (``docker compose -f deploy/docker/docker-compose.yml up -d
neo4j``); it skips itself when the graph is unreachable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from app.engines.topology.applications import (
    ApplicationNode,
    DependsOnEdge,
    DerivedApplications,
)
from app.engines.topology.dns import (
    DerivedDns,
    DnsRecordNode,
    DnsZoneNode,
    InZoneEdge,
    ResolvesToEdge,
)
from app.engines.topology.edges import (
    ConnectedToEdge,
    EdgeEndpoint,
    HasInterfaceEdge,
    InSubnetEdge,
    L3AdjacentEdge,
    RoutesToEdge,
)
from app.engines.topology.nodes import (
    DerivedNodes,
    DeviceNode,
    InterfaceNode,
    IPAddressNode,
    SiteNode,
    SubnetNode,
    VlanNode,
    VrfNode,
)
from app.engines.topology.projector import (
    PROJECTED_NODE_LABELS,
    PROJECTED_REL_TYPES,
    DerivedEdges,
    full_rebuild,
    project,
)

PROJECTED_AT = datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC)

DEV1 = UUID("00000000-0000-0000-0000-000000000001")
DEV2 = UUID("00000000-0000-0000-0000-000000000002")
IF1 = UUID("00000000-0000-0000-0000-000000000a01")
IF2 = UUID("00000000-0000-0000-0000-000000000a02")
APP1 = UUID("00000000-0000-0000-0000-000000000f01")

#: The REQUIRED application component with nothing derived — a legitimate
#: empty derivation (no rows in Postgres), NOT an omitted layer (ADR-0052 §5).
EMPTY_APPS = DerivedApplications()


# ---------------------------------------------------------------------------
# Fake client capturing Cypher + params
# ---------------------------------------------------------------------------


class FakeSession:
    """Records every (cypher, params) pair passed via run()."""

    def __init__(self, executed: list[tuple[str, dict[str, Any]]]) -> None:
        self._executed = executed

    async def run(self, cypher: str, **params: Any) -> None:
        self._executed.append((cypher, params))

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class FakeClient:
    """Minimal stand-in for Neo4jClient; captures every statement issued."""

    def __init__(self) -> None:
        self.executed: list[tuple[str, dict[str, Any]]] = []

    def session(self) -> FakeSession:  # called as async context manager
        return FakeSession(self.executed)

    @property
    def statements(self) -> list[str]:
        return [cypher for cypher, _ in self.executed]


# ---------------------------------------------------------------------------
# Small derivation fixture (typed records, no ORM / DB involved)
# ---------------------------------------------------------------------------


def small_nodes() -> DerivedNodes:
    return DerivedNodes(
        devices=(
            DeviceNode(
                pg_id=DEV1,
                hostname="core-1",
                mgmt_ip="10.0.0.1",
                vendor_id="cisco_ios",
                model="C9300",
                site="hq",
            ),
            DeviceNode(
                pg_id=DEV2,
                hostname="core-2",
                mgmt_ip="10.0.0.2",
                vendor_id="arista_eos",
                model=None,
                site=None,
            ),
        ),
        interfaces=(
            InterfaceNode(
                pg_id=IF1,
                name="Ethernet1",
                admin_status="up",
                oper_status="up",
                mac_address=None,
                ip_address="10.0.0.1/24",
            ),
            InterfaceNode(
                pg_id=IF2,
                name="Ethernet2",
                admin_status="up",
                oper_status="down",
                mac_address="aa:bb:cc:dd:ee:ff",
                ip_address=None,
            ),
        ),
        ip_addresses=(IPAddressNode(pg_id=IF1, address="10.0.0.1"),),
        subnets=(SubnetNode(cidr="10.0.0.0/24"),),
        vlans=(VlanNode(vlan_id=10),),
        vrfs=(VrfNode(name="prod"),),
        sites=(SiteNode(name="hq"),),
    )


def small_edges() -> DerivedEdges:
    return DerivedEdges(
        connected_to=(
            ConnectedToEdge(
                a=EdgeEndpoint(label="Interface", key=str(IF1)),
                b=EdgeEndpoint(label="Interface", key=str(IF2)),
                protocols=("lldp",),
                interface_a="Ethernet1",
                interface_b="Ethernet2",
            ),
            ConnectedToEdge(
                a=EdgeEndpoint(label="Device", key=str(DEV1)),
                b=EdgeEndpoint(label="Interface", key=str(IF2)),
                protocols=("cdp", "lldp"),
                interface_a="Ethernet9",
                interface_b="Ethernet2",
            ),
        ),
        has_interface=(
            HasInterfaceEdge(device_pg_id=str(DEV1), interface_pg_id=str(IF1)),
            HasInterfaceEdge(device_pg_id=str(DEV2), interface_pg_id=str(IF2)),
        ),
        in_subnet=(InSubnetEdge(interface_pg_id=str(IF1), cidr="10.0.0.0/24"),),
        l3_adjacent=(
            L3AdjacentEdge(
                device_a_pg_id=str(DEV1),
                device_b_pg_id=str(DEV2),
                cidrs=("10.0.0.0/24",),
            ),
        ),
        routes_to=(
            RoutesToEdge(
                device_pg_id=str(DEV1),
                cidr="10.0.0.0/24",
                protocol="static",
                next_hop="10.0.0.254",
                vrf="prod",
            ),
        ),
    )


def _upserts(client: FakeClient) -> list[tuple[str, dict[str, Any]]]:
    return [(c, p) for c, p in client.executed if "UNWIND" in c]


def _sweeps(client: FakeClient) -> list[tuple[str, dict[str, Any]]]:
    return [(c, p) for c, p in client.executed if "DELETE" in c]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_projected_label_and_rel_constants_cover_the_m2_subset_plus_dns_plus_app() -> None:
    assert set(PROJECTED_NODE_LABELS) == {
        "Device",
        "Interface",
        "IPAddress",
        "Vlan",
        "Subnet",
        "VRF",
        "Site",
        # M5 task #13 DNS-dependency layer.
        "DnsZone",
        "DnsRecord",
        # P4 W2 application-dependency layer (ADR-0052 §5).
        "Application",
    }
    assert set(PROJECTED_REL_TYPES) == {
        "CONNECTED_TO",
        "HAS_INTERFACE",
        "IN_SUBNET",
        "L3_ADJACENT",
        "ROUTES_TO",
        # M5 task #13 DNS-dependency layer.
        "IN_ZONE",
        "RESOLVES_TO",
        # P4 W2 application-dependency layer (ADR-0052 §5).
        "DEPENDS_ON",
    }


# ---------------------------------------------------------------------------
# project() — validation
# ---------------------------------------------------------------------------


async def test_project_rejects_naive_projected_at() -> None:
    client = FakeClient()
    naive = datetime(2026, 6, 12, 12, 0, 0)  # noqa: DTZ001 — naive on purpose
    with pytest.raises(ValueError, match="timezone-aware"):
        await project(client, small_nodes(), small_edges(), naive, applications=EMPTY_APPS)
    assert client.executed == []


async def test_project_rejects_non_positive_batch_size() -> None:
    client = FakeClient()
    with pytest.raises(ValueError, match="batch_size"):
        await project(
            client,
            small_nodes(),
            small_edges(),
            PROJECTED_AT,
            applications=EMPTY_APPS,
            batch_size=0,
        )
    assert client.executed == []


# ---------------------------------------------------------------------------
# project() — node upserts
# ---------------------------------------------------------------------------


async def test_project_merges_every_label_by_its_key_property() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)

    statements = " \n".join(c for c, _ in _upserts(client))
    assert "MERGE (n:Device {pg_id: row.key})" in statements
    assert "MERGE (n:Interface {pg_id: row.key})" in statements
    assert "MERGE (n:IPAddress {pg_id: row.key})" in statements
    assert "MERGE (n:Vlan {vlan_id: row.key})" in statements
    assert "MERGE (n:Subnet {cidr: row.key})" in statements
    assert "MERGE (n:VRF {name: row.key})" in statements
    assert "MERGE (n:Site {name: row.key})" in statements


async def test_project_node_rows_carry_key_and_full_prop_map() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)

    device_upserts = [(c, p) for c, p in _upserts(client) if "(n:Device" in c]
    assert len(device_upserts) == 1
    cypher, params = device_upserts[0]
    # SET n = row.props replaces the whole property map (drops stale props).
    assert "SET n = row.props" in cypher
    rows = params["rows"]
    assert [row["key"] for row in rows] == [str(DEV1), str(DEV2)]
    first = rows[0]["props"]
    assert first["pg_id"] == str(DEV1)
    assert first["hostname"] == "core-1"
    assert first["site"] == "hq"
    assert first["last_projected_at"] == PROJECTED_AT


async def test_project_vlan_key_is_the_integer_vlan_id() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    vlan_upserts = [(c, p) for c, p in _upserts(client) if "(n:Vlan" in c]
    assert len(vlan_upserts) == 1
    assert vlan_upserts[0][1]["rows"][0]["key"] == 10


async def test_project_skips_upsert_statements_for_empty_node_sets() -> None:
    client = FakeClient()
    nodes = DerivedNodes(devices=small_nodes().devices)  # everything else empty
    await project(client, nodes, DerivedEdges(), PROJECTED_AT, applications=EMPTY_APPS)
    upsert_statements = [c for c, _ in _upserts(client)]
    assert len(upsert_statements) == 1
    assert "(n:Device" in upsert_statements[0]


# ---------------------------------------------------------------------------
# project() — edge upserts
# ---------------------------------------------------------------------------


async def test_project_edges_match_endpoints_and_merge_relationship() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    statements = [c for c, _ in _upserts(client)]

    has_interface = [c for c in statements if ":HAS_INTERFACE" in c]
    assert len(has_interface) == 1
    cypher = has_interface[0]
    # Endpoints are MATCHed (never created) by their schema key properties.
    assert "MATCH (a:Device {pg_id: row.a_key})" in cypher
    assert "MATCH (b:Interface {pg_id: row.b_key})" in cypher
    assert "MERGE (a)-[r:HAS_INTERFACE]->(b)" in cypher
    assert "SET r = row.props" in cypher

    in_subnet = [c for c in statements if ":IN_SUBNET" in c]
    assert len(in_subnet) == 1
    assert "MATCH (b:Subnet {cidr: row.b_key})" in in_subnet[0]

    routes_to = [c for c in statements if ":ROUTES_TO" in c]
    assert len(routes_to) == 1
    assert "MATCH (a:Device {pg_id: row.a_key})" in routes_to[0]
    assert "MATCH (b:Subnet {cidr: row.b_key})" in routes_to[0]


async def test_project_groups_connected_to_by_endpoint_label_pair() -> None:
    """Mixed Device/Interface endpoints need one statement per label pair."""
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    connected = [(c, p) for c, p in _upserts(client) if ":CONNECTED_TO" in c]
    assert len(connected) == 2

    by_labels = {
        (c.split("MATCH (a:")[1].split(" ")[0], c.split("MATCH (b:")[1].split(" ")[0]): p
        for c, p in connected
    }
    assert set(by_labels) == {("Device", "Interface"), ("Interface", "Interface")}
    iface_rows = by_labels[("Interface", "Interface")]["rows"]
    assert iface_rows == [
        {
            "a_key": str(IF1),
            "b_key": str(IF2),
            "props": {
                "protocols": ["lldp"],
                "interface_a": "Ethernet1",
                "interface_b": "Ethernet2",
                "last_projected_at": PROJECTED_AT,
            },
        }
    ]


async def test_project_edge_props_carry_last_projected_at() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    for cypher, params in _upserts(client):
        if "MERGE (a)-[r:" not in cypher:
            continue
        for row in params["rows"]:
            assert row["props"]["last_projected_at"] == PROJECTED_AT


async def test_project_routes_to_rows_keep_route_properties() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    routes = [(c, p) for c, p in _upserts(client) if ":ROUTES_TO" in c]
    props = routes[0][1]["rows"][0]["props"]
    assert props["protocol"] == "static"
    assert props["next_hop"] == "10.0.0.254"
    assert props["vrf"] == "prod"


# ---------------------------------------------------------------------------
# project() — stale sweep
# ---------------------------------------------------------------------------


async def test_project_sweeps_every_projected_label_and_rel_type_even_when_empty() -> None:
    """An empty derivation still sweeps every projected label + rel type clean."""
    client = FakeClient()
    await project(client, DerivedNodes(), DerivedEdges(), PROJECTED_AT, applications=EMPTY_APPS)

    assert _upserts(client) == []
    sweeps = _sweeps(client)
    assert len(sweeps) == len(PROJECTED_REL_TYPES) + len(PROJECTED_NODE_LABELS)
    statements = [c for c, _ in sweeps]
    for rel_type in PROJECTED_REL_TYPES:
        assert any(f"[r:{rel_type}]" in c and "DETACH" not in c for c in statements)
    for label in PROJECTED_NODE_LABELS:
        assert any(f"(n:{label})" in c and "DETACH DELETE" in c for c in statements)


async def test_project_sweeps_only_elements_not_stamped_in_this_pass() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    for cypher, params in _sweeps(client):
        assert (
            "WHERE r.last_projected_at IS NULL OR r.last_projected_at <> $projected_at" in (cypher)
            or "WHERE n.last_projected_at IS NULL OR n.last_projected_at <> $projected_at" in cypher
        )
        assert params == {"projected_at": PROJECTED_AT}


async def test_project_runs_all_upserts_before_any_sweep() -> None:
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    statements = client.statements
    last_upsert = max(i for i, c in enumerate(statements) if "UNWIND" in c)
    first_sweep = min(i for i, c in enumerate(statements) if "DELETE" in c)
    assert last_upsert < first_sweep


# ---------------------------------------------------------------------------
# project() — batching
# ---------------------------------------------------------------------------


async def test_project_batches_rows_into_unwind_chunks_not_per_row_calls() -> None:
    client = FakeClient()
    await project(
        client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS, batch_size=1
    )
    device_upserts = [(c, p) for c, p in _upserts(client) if "(n:Device" in c]
    assert len(device_upserts) == 2  # 2 devices, batch_size=1 -> 2 chunks
    assert all(len(p["rows"]) == 1 for _, p in device_upserts)

    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    device_upserts = [(c, p) for c, p in _upserts(client) if "(n:Device" in c]
    assert len(device_upserts) == 1  # default batch size: one round trip
    assert len(device_upserts[0][1]["rows"]) == 2


# ---------------------------------------------------------------------------
# project() — DNS-dependency layer (M5 task #13)
# ---------------------------------------------------------------------------


def small_dns() -> DerivedDns:
    """A zone with one reconciled (IPAddress) and one unreconciled record."""
    return DerivedDns(
        zones=(DnsZoneNode(fqdn="corp.example.com"),),
        records=(
            DnsRecordNode(
                record_key="www.corp.example.com|a|10.0.0.1",
                name="www.corp.example.com",
                record_type="a",
                value="10.0.0.1",
                zone="corp.example.com",
            ),
            DnsRecordNode(
                record_key="ext.corp.example.com|a|203.0.113.7",
                name="ext.corp.example.com",
                record_type="a",
                value="203.0.113.7",
                zone="corp.example.com",
            ),
        ),
        in_zone=(
            InZoneEdge(zone_fqdn="corp.example.com", record_key="www.corp.example.com|a|10.0.0.1"),
            InZoneEdge(
                zone_fqdn="corp.example.com", record_key="ext.corp.example.com|a|203.0.113.7"
            ),
        ),
        resolves_to=(
            ResolvesToEdge(
                record_key="www.corp.example.com|a|10.0.0.1",
                value="10.0.0.1",
                reconciled=True,
                target_label="IPAddress",
                target_key=str(IF1),
            ),
            ResolvesToEdge(
                record_key="ext.corp.example.com|a|203.0.113.7",
                value="203.0.113.7",
                reconciled=False,
            ),
        ),
    )


async def test_project_merges_dns_zone_and_record_by_their_key_properties() -> None:
    client = FakeClient()
    await project(
        client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS, dns=small_dns()
    )
    statements = " \n".join(c for c, _ in _upserts(client))
    assert "MERGE (n:DnsZone {fqdn: row.key})" in statements
    assert "MERGE (n:DnsRecord {record_key: row.key})" in statements

    record_upserts = [(c, p) for c, p in _upserts(client) if "(n:DnsRecord" in c]
    assert len(record_upserts) == 1
    rows = record_upserts[0][1]["rows"]
    assert [r["key"] for r in rows] == [
        "www.corp.example.com|a|10.0.0.1",
        "ext.corp.example.com|a|203.0.113.7",
    ]
    assert rows[0]["props"]["zone"] == "corp.example.com"
    assert rows[0]["props"]["last_projected_at"] == PROJECTED_AT


async def test_project_in_zone_edges_link_dnszone_to_dnsrecord() -> None:
    client = FakeClient()
    await project(
        client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS, dns=small_dns()
    )
    in_zone = [c for c, _ in _upserts(client) if ":IN_ZONE" in c]
    assert len(in_zone) == 1
    cypher = in_zone[0]
    assert "MATCH (a:DnsZone {fqdn: row.a_key})" in cypher
    assert "MATCH (b:DnsRecord {record_key: row.b_key})" in cypher
    assert "MERGE (a)-[r:IN_ZONE]->(b)" in cypher


async def test_project_resolves_to_targets_reconciled_node_and_carries_value() -> None:
    client = FakeClient()
    await project(
        client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS, dns=small_dns()
    )
    resolves = [(c, p) for c, p in _upserts(client) if ":RESOLVES_TO" in c]
    # Only the reconciled (IPAddress) record yields an edge; the unreconciled one
    # carries no RESOLVES_TO edge (no phantom-node endpoint).
    assert len(resolves) == 1
    cypher, params = resolves[0]
    assert "MATCH (a:DnsRecord {record_key: row.a_key})" in cypher
    assert "MATCH (b:IPAddress {pg_id: row.b_key})" in cypher
    assert "MERGE (a)-[r:RESOLVES_TO]->(b)" in cypher
    rows = params["rows"]
    assert rows == [
        {
            "a_key": "www.corp.example.com|a|10.0.0.1",
            "b_key": str(IF1),
            "props": {"value": "10.0.0.1", "last_projected_at": PROJECTED_AT},
        }
    ]


async def test_project_without_dns_sweeps_dns_layer_and_emits_no_dns_upserts() -> None:
    client = FakeClient()
    await project(
        client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS
    )  # dns=None
    upserts = [c for c, _ in _upserts(client)]
    assert not any("DnsZone" in c or "DnsRecord" in c for c in upserts)
    assert not any(":IN_ZONE" in c or ":RESOLVES_TO" in c for c in upserts)
    # The DNS labels/rel types are still swept (an absent derivation deletes them).
    sweeps = [c for c, _ in _sweeps(client)]
    assert any("(n:DnsZone)" in c and "DETACH DELETE" in c for c in sweeps)
    assert any("(n:DnsRecord)" in c and "DETACH DELETE" in c for c in sweeps)
    assert any("[r:IN_ZONE]" in c for c in sweeps)
    assert any("[r:RESOLVES_TO]" in c for c in sweeps)


# ---------------------------------------------------------------------------
# project() — application-dependency layer (P4 W2, ADR-0052 §3.2/§5)
# ---------------------------------------------------------------------------


def small_applications() -> DerivedApplications:
    """One application with a union DEPENDS_ON edge to a Device and one to an IP."""
    return DerivedApplications(
        applications=(
            ApplicationNode(
                pg_id=APP1,
                name="payroll",
                description="payroll service",
                origin="derived",
                owner="platform-team",
                fqdns=("payroll.corp.example.com",),
            ),
        ),
        depends_on=(
            DependsOnEdge(
                application_pg_id=str(APP1),
                target_label="Device",
                target_key=str(DEV1),
                sources=("f5", "manual"),
                derived_at=PROJECTED_AT,
                provenance=("f5:virtual_server:vs-1", "manual:user:u-1"),
            ),
            DependsOnEdge(
                application_pg_id=str(APP1),
                target_label="IPAddress",
                target_key=str(IF1),
                sources=("dns",),
                derived_at=PROJECTED_AT,
                provenance=("dns:record:www.corp.example.com|a|10.0.0.1",),
            ),
        ),
    )


async def test_project_merges_application_by_pg_id_with_full_prop_map() -> None:
    client = FakeClient()
    await project(
        client,
        small_nodes(),
        small_edges(),
        PROJECTED_AT,
        applications=small_applications(),
    )
    app_upserts = [(c, p) for c, p in _upserts(client) if "(n:Application" in c]
    assert len(app_upserts) == 1
    cypher, params = app_upserts[0]
    assert "MERGE (n:Application {pg_id: row.key})" in cypher
    assert "SET n = row.props" in cypher
    rows = params["rows"]
    assert [row["key"] for row in rows] == [str(APP1)]
    props = rows[0]["props"]
    assert props["name"] == "payroll"
    assert props["origin"] == "derived"
    assert props["owner"] == "platform-team"
    # fqdns projects as a Neo4j array of primitives (list, not tuple).
    assert props["fqdns"] == ["payroll.corp.example.com"]
    assert props["last_projected_at"] == PROJECTED_AT


async def test_project_depends_on_groups_per_target_label_and_matches_endpoints() -> None:
    """One UNWIND per (Application, target-label) pair; endpoints MATCH-ed only."""
    client = FakeClient()
    await project(
        client,
        small_nodes(),
        small_edges(),
        PROJECTED_AT,
        applications=small_applications(),
    )
    depends = [(c, p) for c, p in _upserts(client) if ":DEPENDS_ON" in c]
    assert len(depends) == 2  # one group per target label (Device, IPAddress)
    by_target = {c.split("MATCH (b:")[1].split(" ")[0]: (c, p) for c, p in depends}
    assert set(by_target) == {"Device", "IPAddress"}

    device_cypher, device_params = by_target["Device"]
    assert "MATCH (a:Application {pg_id: row.a_key})" in device_cypher
    assert "MATCH (b:Device {pg_id: row.b_key})" in device_cypher
    assert "MERGE (a)-[r:DEPENDS_ON]->(b)" in device_cypher
    assert "SET r = row.props" in device_cypher
    # No CREATE of endpoints anywhere: an unprojected target emits no edge.
    assert "CREATE" not in device_cypher

    # Union-edge properties per ADR-0052 §3.2.
    rows = device_params["rows"]
    assert rows == [
        {
            "a_key": str(APP1),
            "b_key": str(DEV1),
            "props": {
                "sources": ["f5", "manual"],
                "derived_at": PROJECTED_AT,
                "provenance": ["f5:virtual_server:vs-1", "manual:user:u-1"],
                "last_projected_at": PROJECTED_AT,
            },
        }
    ]


async def test_project_with_empty_applications_sweeps_app_layer_clean() -> None:
    """An empty (but REQUIRED) application derivation sweeps the layer like any
    other empty derivation — unstamped Application/DEPENDS_ON elements are
    deleted (stale-sweep convergence, ADR-0052 §5/§6)."""
    client = FakeClient()
    await project(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    upserts = [c for c, _ in _upserts(client)]
    assert not any("(n:Application" in c for c in upserts)
    assert not any(":DEPENDS_ON" in c for c in upserts)
    sweeps = [c for c, _ in _sweeps(client)]
    assert any("(n:Application)" in c and "DETACH DELETE" in c for c in sweeps)
    assert any("[r:DEPENDS_ON]" in c for c in sweeps)


def test_project_and_full_rebuild_require_the_application_component() -> None:
    """Optional-kwarg relapse guard (ADR-0052 §5): ``applications`` has NO
    default on either entry point — a caller that omits it cannot run a pass
    (the ``dns=`` deletion hazard must not recur)."""
    import inspect

    for fn in (project, full_rebuild):
        param = inspect.signature(fn).parameters["applications"]
        assert param.default is inspect.Parameter.empty, fn.__name__
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, fn.__name__


# ---------------------------------------------------------------------------
# full_rebuild()
# ---------------------------------------------------------------------------


async def test_full_rebuild_wipes_then_constrains_then_projects() -> None:
    client = FakeClient()
    await full_rebuild(client, small_nodes(), small_edges(), PROJECTED_AT, applications=EMPTY_APPS)
    statements = client.statements

    wipes = [i for i, c in enumerate(statements) if "DETACH DELETE" in c and "WHERE" not in c]
    constraints = [i for i, c in enumerate(statements) if "CREATE CONSTRAINT" in c]
    projections = [i for i, c in enumerate(statements) if "UNWIND" in c]

    assert len(wipes) == len(PROJECTED_NODE_LABELS)
    assert len(constraints) == len(PROJECTED_NODE_LABELS)
    assert projections, "full_rebuild must end with a projection pass"
    assert max(wipes) < min(constraints) < min(projections)


async def test_full_rebuild_wipe_is_scoped_to_projected_labels_only() -> None:
    client = FakeClient()
    await full_rebuild(
        client, DerivedNodes(), DerivedEdges(), PROJECTED_AT, applications=EMPTY_APPS
    )
    wipes = [c for c in client.statements if "DETACH DELETE" in c and "WHERE" not in c]
    # Wave 5: batched CALL {} IN TRANSACTIONS wipe (perf #18 / M5).
    assert sorted(wipes) == sorted(
        f"MATCH (n:{label}) CALL {{ WITH n DETACH DELETE n }} IN TRANSACTIONS OF 1000 ROWS"
        for label in PROJECTED_NODE_LABELS
    )


# ---------------------------------------------------------------------------
# Integration: live compose Neo4j
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.neo4j
async def test_live_project_then_mutate_then_incremental_sync() -> None:
    """project -> mutate derivation -> project again: graph converges.

    Requires the compose Neo4j with its bolt port reachable from the host
    (``docker compose -f deploy/docker/docker-compose.yml up -d neo4j``) and
    ``NETOPS_NEO4J_URI`` / ``NETOPS_NEO4J_PASSWORD`` pointing at it; skips
    itself otherwise.
    """
    from app.core.config import get_settings
    from app.knowledge.neo4j_client import Neo4jClient

    client = Neo4jClient(get_settings())
    if not await client.health_check():
        await client.close()
        pytest.skip("Neo4j unreachable at NETOPS_NEO4J_URI; skipping integration test")

    async def single_value(cypher: str, **params: Any) -> Any:
        async with client.session() as session:
            result = await session.run(cypher, **params)
            record = await result.single()
            return None if record is None else record[0]

    try:
        # A non-projected label must survive every sweep untouched.
        async with client.session() as session:
            await session.run("MERGE (s:NetopsM2ProjectorSentinel {name: 'keep-me'})")

        t1 = datetime.now(tz=UTC)
        await full_rebuild(client, small_nodes(), small_edges(), t1, applications=EMPTY_APPS)

        assert await single_value("MATCH (n:Device) RETURN count(n)") == 2
        assert await single_value("MATCH (n:Interface) RETURN count(n)") == 2
        assert await single_value("MATCH ()-[r:CONNECTED_TO]->() RETURN count(r)") == 2
        assert await single_value("MATCH ()-[r:HAS_INTERFACE]->() RETURN count(r)") == 2
        assert await single_value("MATCH ()-[r:ROUTES_TO]->() RETURN count(r)") == 1
        assert (
            await single_value(
                "MATCH (n:Device {pg_id: $pg_id}) RETURN n.last_projected_at = $t",
                pg_id=str(DEV1),
                t=t1,
            )
            is True
        )

        # Mutate: DEV2 / IF2 disappear from the derivation; a new device shows up.
        dev3 = UUID("00000000-0000-0000-0000-000000000003")
        nodes_b = DerivedNodes(
            devices=(
                small_nodes().devices[0],
                DeviceNode(
                    pg_id=dev3,
                    hostname="edge-3",
                    mgmt_ip="10.0.0.3",
                    vendor_id=None,
                    model=None,
                    site="hq",
                ),
            ),
            interfaces=(small_nodes().interfaces[0],),
            ip_addresses=small_nodes().ip_addresses,
            subnets=small_nodes().subnets,
            sites=small_nodes().sites,
        )
        edges_b = DerivedEdges(
            has_interface=(HasInterfaceEdge(device_pg_id=str(DEV1), interface_pg_id=str(IF1)),),
            in_subnet=small_edges().in_subnet,
        )
        t2 = t1 + timedelta(seconds=5)
        await project(client, nodes_b, edges_b, t2, applications=EMPTY_APPS)

        # Stale elements are gone; survivors and newcomers are stamped with t2.
        assert await single_value("MATCH (n:Device) RETURN count(n)") == 2
        assert (
            await single_value("MATCH (n:Device {pg_id: $pg_id}) RETURN count(n)", pg_id=str(DEV2))
            == 0
        )
        assert (
            await single_value("MATCH (n:Device {pg_id: $pg_id}) RETURN count(n)", pg_id=str(dev3))
            == 1
        )
        assert await single_value("MATCH (n:Interface) RETURN count(n)") == 1
        assert await single_value("MATCH (n:Vlan) RETURN count(n)") == 0
        assert await single_value("MATCH (n:VRF) RETURN count(n)") == 0
        assert await single_value("MATCH ()-[r:CONNECTED_TO]->() RETURN count(r)") == 0
        assert await single_value("MATCH ()-[r:L3_ADJACENT]->() RETURN count(r)") == 0
        assert await single_value("MATCH ()-[r:ROUTES_TO]->() RETURN count(r)") == 0
        assert await single_value("MATCH ()-[r:HAS_INTERFACE]->() RETURN count(r)") == 1
        assert (
            await single_value(
                "MATCH (n:Device {pg_id: $pg_id}) RETURN n.last_projected_at = $t",
                pg_id=str(DEV1),
                t=t2,
            )
            is True
        )
        # The sweep never touches labels outside the projection.
        assert await single_value("MATCH (s:NetopsM2ProjectorSentinel) RETURN count(s)") == 1
    finally:
        async with client.session() as session:
            for label in PROJECTED_NODE_LABELS:
                await session.run(f"MATCH (n:{label}) DETACH DELETE n")
            await session.run("MATCH (s:NetopsM2ProjectorSentinel) DETACH DELETE s")
        await client.close()
