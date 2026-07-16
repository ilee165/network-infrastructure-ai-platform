"""Unit tests for the application-impact read surface (P4 W2-T4).

Covers the ``app`` topology layer (rider P4) and :func:`fetch_impact` — the
bounded "what depends on X" / "what does A depend on" read (rider P5/P6). Most
tests run with no Neo4j: a fake transaction answers the two scoped ``MATCH``
statements ``_read_impact`` issues (the dependents expansion + the
Application-only dependencies read), so the reader's provenance-carrying,
direction-aware, JSON-safe folding logic is under test rather than stubbed
out. The ``@pytest.mark.integration`` section at the bottom (rider
2026-07-07-1540) proves the IPAddress-co-key join against a real compose
Neo4j; it skips itself when the graph is unreachable.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.engines.topology.projector import full_rebuild
from app.engines.topology.sync import derive_topology
from app.knowledge.schema import (
    LABEL_APPLICATION,
    LABEL_DEVICE,
    LABEL_IPADDRESS,
    LABEL_SUBNET,
    REL_DEPENDS_ON,
)
from app.knowledge.topology_read import (
    LAYER_ALL,
    LAYER_APP,
    LAYERS,
    MAX_NEIGHBORHOOD_DEPTH,
    fetch_impact,
    rel_types_for_layer,
)
from app.models.applications import (
    Application,
    ApplicationDependency,
    ApplicationOrigin,
    DependencySource,
    DependencyTargetKind,
)
from app.models.inventory import Device, NormalizedInterfaceRow
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus

PROJECTED_AT = "2026-07-04T10:00:00+00:00"
EARLIER = "2026-07-04T09:00:00+00:00"

# ---------------------------------------------------------------------------
# P4 — the ``app`` layer
# ---------------------------------------------------------------------------


class TestLayerApp:
    def test_layer_app_maps_to_depends_on_rel_types(self) -> None:
        assert rel_types_for_layer(LAYER_APP) == (REL_DEPENDS_ON,)

    def test_layer_all_includes_depends_on_edges(self) -> None:
        assert LAYER_APP in LAYERS
        assert REL_DEPENDS_ON in rel_types_for_layer(LAYER_ALL)

    def test_unknown_layer_still_rejected(self) -> None:
        # ``rel_types_for_layer`` falls back to the ALL union for anything
        # unrecognised, but the API's ``LAYERS`` membership (and the query-param
        # pattern) is the gate — an unknown layer is not an accepted value.
        assert "bogus" not in LAYERS
        assert set(LAYERS) == {"l2", "l3", "dns", "app", "all"}


# ---------------------------------------------------------------------------
# Fake Neo4j client mirroring the two statements ``_read_impact`` issues
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return self._gen()

    async def _gen(self) -> AsyncIterator[dict[str, Any]]:
        for record in self._records:
            yield record


class _FakeImpactTx:
    """Answers the dependents query (``app_labels`` in RETURN) with *dependents*
    and the Application-only dependencies query with *dependencies*, recording
    every Cypher string so tests can assert the traversal is depth-bounded and
    walks the physical relationship families."""

    def __init__(
        self,
        *,
        dependents: list[dict[str, Any]] | None = None,
        dependencies: list[dict[str, Any]] | None = None,
    ) -> None:
        self._dependents = dependents or []
        self._dependencies = dependencies or []
        self.cyphers: list[str] = []

    async def run(self, cypher: str, **_params: Any) -> _FakeResult:
        self.cyphers.append(cypher)
        if "app_labels" in cypher:
            return _FakeResult(self._dependents)
        if REL_DEPENDS_ON in cypher:
            return _FakeResult(self._dependencies)
        raise AssertionError(f"unexpected cypher: {cypher}")


class _FakeClient:
    def __init__(self, tx: _FakeImpactTx) -> None:
        self._tx = tx

    async def execute_read(self, fn: Any, **kwargs: Any) -> Any:
        return await fn(self._tx, **kwargs)


def _edge_props(
    *,
    sources: list[str],
    provenance: list[str],
    derived_at: Any = PROJECTED_AT,
    projected_at: Any = PROJECTED_AT,
) -> dict[str, Any]:
    return {
        "sources": sources,
        "provenance": provenance,
        "derived_at": derived_at,
        "last_projected_at": projected_at,
    }


def _dependent_record(
    *,
    app_key: str,
    target_label: str,
    target_key: str,
    edge_props: dict[str, Any] | None = None,
    app_projected_at: Any = PROJECTED_AT,
) -> dict[str, Any]:
    return {
        "app_labels": [LABEL_APPLICATION],
        "app_props": {
            "pg_id": app_key,
            "name": f"app-{app_key}",
            "last_projected_at": app_projected_at,
        },
        "target_labels": [target_label],
        "target_props": {_key_prop(target_label): target_key},
        "rel_props": edge_props or _edge_props(sources=["manual"], provenance=["manual:user:u1"]),
    }


def _dependency_record(
    *,
    target_label: str,
    target_key: str,
    edge_props: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "target_labels": [target_label],
        "target_props": {_key_prop(target_label): target_key},
        "rel_props": edge_props
        or _edge_props(sources=["f5"], provenance=["f5:adc_vs:/Common/vs_x"]),
    }


def _key_prop(label: str) -> str:
    return {
        LABEL_DEVICE: "pg_id",
        LABEL_IPADDRESS: "pg_id",
        LABEL_SUBNET: "cidr",
        LABEL_APPLICATION: "pg_id",
    }[label]


# ---------------------------------------------------------------------------
# P5 — dependents direction ("what depends on X")
# ---------------------------------------------------------------------------


class TestFetchImpactDependents:
    async def test_fetch_impact_returns_direct_dependents_of_device_target(self) -> None:
        tx = _FakeImpactTx(
            dependents=[
                _dependent_record(app_key="a1", target_label=LABEL_DEVICE, target_key="dev-1")
            ]
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_DEVICE, target_key="dev-1", depth=2
        )
        assert [d["application"]["key"] for d in result["dependents"]] == ["a1"]
        assert result["dependents"][0]["target"]["key"] == "dev-1"
        # A device target has no "what it depends on" direction.
        assert result["dependencies"] == []

    async def test_fetch_impact_reaches_indirect_dependents_through_physical_chain(self) -> None:
        # Querying a Device returns an app whose DEPENDS_ON edge lands on a
        # *second* physically-reachable node (e.g. an L3-adjacent device) — the
        # indirect-impact contract.  NB: the endpoint here is a Device, not an
        # IPAddress: IPAddress nodes carry no physical edge, so an IP-bound
        # dependency is reached only when the IPAddress is the direct target,
        # not transitively from a Device/Subnet target (topology_read._read_impact
        # known limitation).  This fake tx cannot model graph reachability, so the
        # assertions below verify only what is verifiable at unit level: the
        # emitted traversal is depth-bounded and walks the physical families.
        tx = _FakeImpactTx(
            dependents=[
                _dependent_record(app_key="a2", target_label=LABEL_DEVICE, target_key="dev-2")
            ]
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_DEVICE, target_key="dev-1", depth=3
        )
        assert [d["application"]["key"] for d in result["dependents"]] == ["a2"]
        # The dependents traversal is depth-bounded and walks the physical
        # relationship families (never DEPENDS_ON as a physical hop).
        dependents_cypher = next(c for c in tx.cyphers if "app_labels" in c)
        assert "*0..3" in dependents_cypher
        assert "HAS_INTERFACE" in dependents_cypher and "IN_SUBNET" in dependents_cypher
        assert "DEPENDS_ON" not in dependents_cypher.split("WITH DISTINCT n")[0]

    async def test_dependents_cypher_includes_ipaddress_interface_pg_id_join(self) -> None:
        # P4 W2-T4 gap fix (rider 2026-07-07-1540): the dependents traversal
        # must co-key-join every physically-reached Interface to its projected
        # IPAddress (same pg_id) before the DEPENDS_ON match, so a shared-key
        # IP-bound dependency (e.g. an F5 VIP) is reachable transitively from a
        # Device/Subnet/Interface target, not only when IPAddress is the target.
        tx = _FakeImpactTx(dependents=[])
        await fetch_impact(_FakeClient(tx), target_label=LABEL_DEVICE, target_key="dev-1", depth=2)
        dependents_cypher = next(c for c in tx.cyphers if "app_labels" in c)
        assert f"OPTIONAL MATCH (ip:{LABEL_IPADDRESS})" in dependents_cypher
        assert "ip.pg_id = n.pg_id" in dependents_cypher
        assert "n2" in dependents_cypher
        assert f"[r:{REL_DEPENDS_ON}]->(n2)" in dependents_cypher

    async def test_fetch_impact_depth_bounded_by_max_neighborhood_depth(self) -> None:
        client = _FakeClient(_FakeImpactTx())
        with pytest.raises(ValueError):
            await fetch_impact(
                client,
                target_label=LABEL_DEVICE,
                target_key="d",
                depth=MAX_NEIGHBORHOOD_DEPTH + 1,
            )
        with pytest.raises(ValueError):
            await fetch_impact(client, target_label=LABEL_DEVICE, target_key="d", depth=0)

    async def test_fetch_impact_rejects_unknown_target_label(self) -> None:
        client = _FakeClient(_FakeImpactTx())
        with pytest.raises(ValueError):
            await fetch_impact(client, target_label="Bogus", target_key="x", depth=2)

    async def test_fetch_impact_empty_graph_returns_empty_result_not_error(self) -> None:
        result = await fetch_impact(
            _FakeClient(_FakeImpactTx(dependents=[], dependencies=[])),
            target_label=LABEL_DEVICE,
            target_key="absent",
            depth=2,
        )
        assert result["dependents"] == []
        assert result["dependencies"] == []
        assert result["projected_at"] is None
        assert result["depth_used"] == 2


# ---------------------------------------------------------------------------
# P6 — reverse direction + provenance contract
# ---------------------------------------------------------------------------


class TestFetchImpactApplicationTargetAndProvenance:
    async def test_fetch_impact_application_target_returns_both_directions(self) -> None:
        tx = _FakeImpactTx(
            dependents=[],
            dependencies=[_dependency_record(target_label=LABEL_DEVICE, target_key="dev-7")],
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_APPLICATION, target_key="app-1", depth=2
        )
        assert "dependents" in result and "dependencies" in result
        assert [d["target"]["key"] for d in result["dependencies"]] == ["dev-7"]
        # Both direction queries are issued for an Application entry point.
        assert any("app_labels" in c for c in tx.cyphers)
        assert sum(1 for c in tx.cyphers if REL_DEPENDS_ON in c and "app_labels" not in c) == 1

    async def test_fetch_impact_every_edge_carries_sources_and_provenance_summary(self) -> None:
        tx = _FakeImpactTx(
            dependents=[
                _dependent_record(
                    app_key="a1",
                    target_label=LABEL_DEVICE,
                    target_key="dev-1",
                    edge_props=_edge_props(sources=["f5", "manual"], provenance=["f5:adc_vs:x"]),
                )
            ],
            dependencies=[],
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_DEVICE, target_key="dev-1", depth=2
        )
        for entry in result["dependents"]:
            assert entry["sources"], "every impact edge must cite its source(s)"
            assert entry["provenance"], "every impact edge must carry a provenance summary"
            assert entry["derived_at"] is not None

    async def test_fetch_impact_result_carries_projected_at_watermark(self) -> None:
        tx = _FakeImpactTx(
            dependents=[
                _dependent_record(
                    app_key="old",
                    target_label=LABEL_DEVICE,
                    target_key="dev-1",
                    edge_props=_edge_props(
                        sources=["manual"], provenance=["manual:user:u"], projected_at=EARLIER
                    ),
                    app_projected_at=EARLIER,
                ),
                _dependent_record(
                    app_key="new",
                    target_label=LABEL_DEVICE,
                    target_key="dev-2",
                    edge_props=_edge_props(
                        sources=["manual"], provenance=["manual:user:u"], projected_at=PROJECTED_AT
                    ),
                    app_projected_at=PROJECTED_AT,
                ),
            ]
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_DEVICE, target_key="dev-1", depth=2
        )
        assert result["projected_at"] == PROJECTED_AT

    async def test_fetch_impact_results_json_safe_for_api_serialization(self) -> None:
        # Driver-typed temporals (datetime) must be coerced to ISO strings so the
        # API layer can serialize the result without importing driver types.
        dt = datetime(2026, 7, 4, 10, 0, 0, tzinfo=UTC)
        tx = _FakeImpactTx(
            dependents=[
                _dependent_record(
                    app_key="a1",
                    target_label=LABEL_DEVICE,
                    target_key="dev-1",
                    edge_props=_edge_props(
                        sources=["manual"],
                        provenance=["manual:user:u"],
                        derived_at=dt,
                        projected_at=dt,
                    ),
                    app_projected_at=dt,
                )
            ]
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_DEVICE, target_key="dev-1", depth=2
        )
        # No raise => no datetime / driver types leaked into the result.
        json.dumps(result)
        assert isinstance(result["dependents"][0]["derived_at"], str)


# ---------------------------------------------------------------------------
# Integration: live compose Neo4j (rider 2026-07-07-1540, P1-P6)
#
# Proves the IPAddress-Interface co-key join against a REAL Neo4j: an
# IP-bound Application dependency (the F5-VIP shape) surfaces transitively
# from a Device/Subnet target, not only when IPAddress is the direct target.
# Requires ``docker compose -f deploy/docker/docker-compose.yml --env-file
# .env up -d neo4j`` reachable via NETOPS_NEO4J_URI; skips itself otherwise
# (mirrors test_projector.py's live-Neo4j convention).
# ---------------------------------------------------------------------------

LIVE_COLLECTED_AT = datetime(2026, 7, 7, 12, 0, tzinfo=UTC)


async def _skip_if_unreachable() -> Any:
    from app.core.config import get_settings
    from app.knowledge.neo4j_client import Neo4jClient

    client = Neo4jClient(get_settings())
    if not await client.health_check():
        await client.close()
        pytest.skip("Neo4j unreachable at NETOPS_NEO4J_URI; skipping integration test")
    return client


def _live_device(hostname: str, mgmt_ip: str, *, device_id: UUID | None = None) -> Device:
    return Device(
        id=device_id or uuid4(),
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id="f5_bigip",
        model=None,
        site=None,
    )


def _live_interface(
    device_id: UUID, name: str, *, row_id: UUID | None = None, ip_address: str | None = None
) -> NormalizedInterfaceRow:
    return NormalizedInterfaceRow(
        id=row_id or uuid4(),
        device_id=device_id,
        raw_artifact_id=uuid4(),
        collected_at=LIVE_COLLECTED_AT,
        source_vendor="f5_bigip",
        name=name,
        admin_status=InterfaceAdminStatus.UP,
        oper_status=InterfaceOperStatus.UP,
        mac_address=None,
        ip_address=ip_address,
        vlan_id=None,
    )


def _live_application(app_id: UUID, name: str) -> Application:
    return Application(
        id=app_id,
        name=name,
        origin=ApplicationOrigin.DERIVED,
        origin_ref=f"f5:test:{name}",
        fqdns=[],
        description=None,
        owner=None,
    )


def _live_ip_dependency(app_id: UUID, ip_pg_id: UUID) -> ApplicationDependency:
    """An F5-VIP-shaped dependency: Application -> the winning interface's IPAddress."""
    return ApplicationDependency(
        application_id=app_id,
        target_kind=DependencyTargetKind.IP_ADDRESS,
        target_ref=str(ip_pg_id),
        source=DependencySource.F5,
        provenance=[{"kind": "virtual_server", "ref": "/Common/vs_impact_test"}],
        derived_at=LIVE_COLLECTED_AT,
    )


async def _seed_single_device_ip_dependency(client: Any) -> dict[str, Any]:
    """One Device, one addressed Interface, one Application DEPENDS_ON its
    IPAddress — via REAL derivation (derive_topology) + full_rebuild, not
    hand-built graph rows. Single interface per address => it IS the winner,
    so IPAddress.pg_id == this interface's own pg_id (rider's co-key premise).
    """
    device = _live_device("f5-lb-1", "10.50.0.1")
    interface = _live_interface(device.id, "1.1", ip_address="10.50.10.5/24")
    app = _live_application(uuid4(), "impact-test-app")
    dep = _live_ip_dependency(app.id, interface.id)
    topo = derive_topology([device], [interface], [], [], [app], [dep])
    await full_rebuild(
        client, topo.nodes, topo.edges, LIVE_COLLECTED_AT, applications=topo.applications
    )
    return {
        "device_id": device.id,
        "interface_id": interface.id,
        "app_id": app.id,
        "subnet_cidr": "10.50.10.0/24",
    }


async def _seed_cross_device_shared_address(client: Any) -> dict[str, Any]:
    """Two devices whose interfaces share ONE address (=> an automatic
    L3_ADJACENT edge, since sharing an address means sharing its /24). The
    LOWER-pg_id interface (the dedup winner IPAddress.pg_id resolves to) is
    forced onto ``device_b`` — 2 physical hops from ``device_a`` (L3_ADJACENT
    then HAS_INTERFACE) — so P5 (depth=2, reachable) and P6 (depth=1, the
    winner is one hop out of bounds) share this one seed shape.
    """
    device_a = _live_device("f5-lb-a", "10.60.0.2")
    device_b = _live_device("f5-lb-b", "10.60.0.3")
    lower_id, higher_id = sorted((uuid4(), uuid4()))
    iface_a = _live_interface(device_a.id, "1.1", row_id=higher_id, ip_address="10.60.20.9/24")
    iface_b = _live_interface(device_b.id, "1.1", row_id=lower_id, ip_address="10.60.20.9/24")
    app = _live_application(uuid4(), "impact-shared-addr-app")
    dep = _live_ip_dependency(app.id, lower_id)  # the winning (lower-pg_id) interface
    topo = derive_topology([device_a, device_b], [iface_a, iface_b], [], [], [app], [dep])
    await full_rebuild(
        client, topo.nodes, topo.edges, LIVE_COLLECTED_AT, applications=topo.applications
    )
    return {"device_a_id": device_a.id, "device_b_id": device_b.id, "app_id": app.id}


@pytest.mark.integration
@pytest.mark.neo4j
class TestLiveImpactIpReach:
    async def test_live_seed_helper_produces_interface_and_ipaddress_sharing_pg_id(self) -> None:
        client = await _skip_if_unreachable()
        try:
            seed = await _seed_single_device_ip_dependency(client)
            async with client.session() as session:
                iface_result = await session.run(
                    "MATCH (i:Interface {pg_id: $pg_id}) RETURN i.pg_id AS pg_id",
                    pg_id=str(seed["interface_id"]),
                )
                iface_record = await iface_result.single()
                ip_result = await session.run(
                    "MATCH (ip:IPAddress {pg_id: $pg_id}) RETURN ip.pg_id AS pg_id",
                    pg_id=str(seed["interface_id"]),
                )
                ip_record = await ip_result.single()
            assert iface_record is not None
            assert ip_record is not None
            assert iface_record["pg_id"] == ip_record["pg_id"] == str(seed["interface_id"])
        finally:
            await client.close()

    async def test_live_neo4j_integration_test_skips_cleanly_without_reachable_service(
        self,
    ) -> None:
        from app.core.config import get_settings
        from app.knowledge.neo4j_client import Neo4jClient

        unreachable = get_settings().model_copy(update={"neo4j_uri": "bolt://127.0.0.1:1"})
        client = Neo4jClient(unreachable, max_attempts=1, backoff_base_seconds=0.01)
        with pytest.raises(pytest.skip.Exception):
            if not await client.health_check():
                await client.close()
                pytest.skip("Neo4j unreachable; skipping integration test")

    async def test_live_impact_device_target_reaches_f5_vip_dependent_through_shared_interface_key(
        self,
    ) -> None:
        client = await _skip_if_unreachable()
        try:
            seed = await _seed_single_device_ip_dependency(client)
            result = await fetch_impact(
                client, target_label=LABEL_DEVICE, target_key=str(seed["device_id"]), depth=2
            )
            assert [d["application"]["key"] for d in result["dependents"]] == [str(seed["app_id"])]
        finally:
            await client.close()

    async def test_live_impact_subnet_target_reaches_f5_vip_dependent_through_shared_interface_key(
        self,
    ) -> None:
        client = await _skip_if_unreachable()
        try:
            seed = await _seed_single_device_ip_dependency(client)
            result = await fetch_impact(
                client, target_label=LABEL_SUBNET, target_key=seed["subnet_cidr"], depth=2
            )
            assert [d["application"]["key"] for d in result["dependents"]] == [str(seed["app_id"])]
        finally:
            await client.close()

    async def test_live_impact_shared_addr_winner_on_other_reachable_device_surfaces_dependent(
        self,
    ) -> None:
        client = await _skip_if_unreachable()
        try:
            seed = await _seed_cross_device_shared_address(client)
            result = await fetch_impact(
                client, target_label=LABEL_DEVICE, target_key=str(seed["device_a_id"]), depth=2
            )
            assert [d["application"]["key"] for d in result["dependents"]] == [str(seed["app_id"])]
        finally:
            await client.close()

    async def test_live_impact_shared_addr_winner_on_unreachable_device_no_dependent(
        self,
    ) -> None:
        client = await _skip_if_unreachable()
        try:
            seed = await _seed_cross_device_shared_address(client)
            # depth=1: device_a -L3_ADJACENT-> device_b is reachable, but
            # device_b's own Interface (the winner) is a 2nd hop out of bounds.
            result = await fetch_impact(
                client, target_label=LABEL_DEVICE, target_key=str(seed["device_a_id"]), depth=1
            )
            assert result["dependents"] == []
        finally:
            await client.close()
