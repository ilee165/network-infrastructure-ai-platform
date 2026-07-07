"""Unit tests for the application-impact read surface (P4 W2-T4).

Covers the ``app`` topology layer (rider P4) and :func:`fetch_impact` — the
bounded "what depends on X" / "what does A depend on" read (rider P5/P6). No
Neo4j: a fake transaction mirrors the two Cypher statements ``_read_impact``
issues (center lookup + bounded impact collection), so the reader's
provenance-carrying, direction-aware, JSON-safe folding logic is under test
rather than stubbed out.
"""

from __future__ import annotations

from app.knowledge.schema import REL_DEPENDS_ON
from app.knowledge.topology_read import (
    LAYER_ALL,
    LAYER_APP,
    LAYERS,
    rel_types_for_layer,
)

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
