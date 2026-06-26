"""Composition-root tests (M3-14): the default registry + supervisor wiring.

Offline and deterministic: a scripted fake chat model stands in for the LLM, so
no network is touched. After P2 W3-T2 the default registry must hold exactly the
ten core agents — the Master Architect supervisor plus the NINE routable
specialists (consultant, discovery, troubleshooting, configuration,
documentation, automation, ddi, packet_analysis, security) — and the supervisor
compiled from it must route over those nine specialists without routing to the
Master Architect itself.
"""

from __future__ import annotations

from app.agents import build_default_registry, build_default_supervisor
from app.agents.framework.supervisor import SUPERVISOR_NAME
from tests.agents.conftest import scripted_model

ROUTABLE_SPECIALISTS = {
    "consultant",
    "discovery",
    "troubleshooting",
    "configuration",
    "documentation",
    "automation",
    "ddi",
    "packet_analysis",
    "security",
}
EXPECTED_AGENTS = {SUPERVISOR_NAME, *ROUTABLE_SPECIALISTS}


class TestDefaultRegistry:
    def test_registry_contains_exactly_the_ten_core_agents(self) -> None:
        registry = build_default_registry()
        assert set(registry.names()) == EXPECTED_AGENTS
        assert len(registry) == 10

    def test_master_architect_is_registered(self) -> None:
        registry = build_default_registry()
        assert SUPERVISOR_NAME in registry
        assert registry.get(SUPERVISOR_NAME).name == SUPERVISOR_NAME

    def test_every_registered_agent_is_valid(self) -> None:
        # register() already validates, but assert the definitions explicitly so
        # a future bad declaration is caught here, not only at import time.
        for agent in build_default_registry().list():
            agent.validate_definition()

    def test_factory_returns_independent_registries(self) -> None:
        first = build_default_registry()
        second = build_default_registry()
        assert first is not second
        assert first.get(SUPERVISOR_NAME) is not second.get(SUPERVISOR_NAME)


class TestDefaultSupervisor:
    def test_supervisor_routes_over_specialists_not_itself(self) -> None:
        graph = build_default_supervisor(scripted_model([]))
        nodes = set(graph.get_graph().nodes)
        # The nine specialists are routable nodes; the supervisor is not a node
        # it can route to (it IS the router).
        assert nodes >= ROUTABLE_SPECIALISTS
        assert SUPERVISOR_NAME not in nodes
        assert {"route", "synthesize"} <= nodes

    def test_supervisor_accepts_an_explicit_registry(self) -> None:
        registry = build_default_registry()
        graph = build_default_supervisor(scripted_model([]), registry)
        assert "troubleshooting" in set(graph.get_graph().nodes)

    def test_all_specialists_are_reachable_router_nodes(self) -> None:
        # Each of the nine routable specialists must be a node the supervisor can
        # route to (P2 W3-T2 adds the security agent to the M5 eight).
        graph = build_default_supervisor(scripted_model([]))
        nodes = set(graph.get_graph().nodes)
        for specialist in ROUTABLE_SPECIALISTS:
            assert specialist in nodes, f"{specialist} is not a routable supervisor node"
