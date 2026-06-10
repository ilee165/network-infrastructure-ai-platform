"""Tests for the specialist registry (app/agents/framework/registry.py)."""

from __future__ import annotations

import pytest

from app.agents.framework.base import AgentDefinitionError
from app.agents.framework.registry import AgentRegistry
from app.core.errors import ConflictError, NotFoundError
from tests.agents.conftest import SpecialistFactory


class TestAgentRegistry:
    def test_register_and_get_round_trip(self, specialist_factory: SpecialistFactory) -> None:
        registry = AgentRegistry()
        agent = specialist_factory("troubleshooting")
        assert registry.register(agent) is agent
        assert registry.get("troubleshooting") is agent
        assert "troubleshooting" in registry
        assert len(registry) == 1

    def test_register_duplicate_name_raises_conflict(
        self, specialist_factory: SpecialistFactory
    ) -> None:
        registry = AgentRegistry()
        registry.register(specialist_factory("ddi"))
        with pytest.raises(ConflictError):
            registry.register(specialist_factory("ddi"))

    def test_get_unknown_agent_raises_not_found(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(NotFoundError):
            registry.get("automation")

    def test_register_validates_the_definition(self, specialist_factory: SpecialistFactory) -> None:
        registry = AgentRegistry()
        with pytest.raises(AgentDefinitionError):
            registry.register(specialist_factory("Not A Valid Name"))
        assert len(registry) == 0

    def test_list_and_names_are_sorted(self, specialist_factory: SpecialistFactory) -> None:
        registry = AgentRegistry()
        registry.register(specialist_factory("troubleshooting"))
        registry.register(specialist_factory("discovery"))
        registry.register(specialist_factory("packet_analysis"))
        assert registry.names() == ["discovery", "packet_analysis", "troubleshooting"]
        assert [a.name for a in registry.list()] == registry.names()
