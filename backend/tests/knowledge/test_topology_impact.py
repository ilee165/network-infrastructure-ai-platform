"""Unit tests for the application-impact read surface (P4 W2-T4).

Covers the ``app`` topology layer (rider P4) and :func:`fetch_impact` — the
bounded "what depends on X" / "what does A depend on" read (rider P5/P6). No
Neo4j: a fake transaction answers the two scoped ``MATCH`` statements
``_read_impact`` issues (the dependents expansion + the Application-only
dependencies read), so the reader's provenance-carrying, direction-aware,
JSON-safe folding logic is under test rather than stubbed out.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest

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

    async def test_fetch_impact_reaches_indirect_impact_through_physical_chain(self) -> None:
        # Querying a Subnet returns an app whose DEPENDS_ON edge lands on an
        # IPAddress inside that subnet — reached by expanding the target's
        # physical neighborhood.
        tx = _FakeImpactTx(
            dependents=[
                _dependent_record(app_key="a2", target_label=LABEL_IPADDRESS, target_key="ip-9")
            ]
        )
        result = await fetch_impact(
            _FakeClient(tx), target_label=LABEL_SUBNET, target_key="10.0.0.0/24", depth=3
        )
        assert [d["application"]["key"] for d in result["dependents"]] == ["a2"]
        # The dependents traversal is depth-bounded and walks the physical
        # relationship families (never DEPENDS_ON as a physical hop).
        dependents_cypher = next(c for c in tx.cyphers if "app_labels" in c)
        assert "*0..3" in dependents_cypher
        assert "HAS_INTERFACE" in dependents_cypher and "IN_SUBNET" in dependents_cypher

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
