"""Tests for the specialist base class and its default ReAct graph
(app/agents/framework/base.py)."""

from __future__ import annotations

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool

from app.agents.framework.base import AgentDefinitionError
from app.agents.framework.tools import NetOpsTool, ToolClassification, netops_tool
from tests.agents.conftest import RecordingAuditSink, SpecialistFactory, scripted_model


def _count_tool(sink: RecordingAuditSink) -> NetOpsTool:
    @netops_tool(classification=ToolClassification.READ_ONLY, audit_sink=sink)
    async def get_device_count() -> str:
        """Count managed devices."""
        return "42 devices"

    return get_device_count


class TestBuildGraph:
    async def test_default_graph_runs_a_react_loop(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        agent = specialist_factory("discovery", tools=[_count_tool(audit_sink)])
        llm = scripted_model(
            [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "get_device_count", "args": {}, "id": "call-1"}],
                ),
                AIMessage(content="There are 42 managed devices."),
            ]
        )
        graph = agent.build_graph(llm)
        result = await graph.ainvoke({"messages": [HumanMessage(content="how many devices?")]})

        tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
        assert len(tool_messages) == 1
        assert tool_messages[0].content == "42 devices"
        assert result["messages"][-1].content == "There are 42 managed devices."
        # The classified tool ran through the audit pipeline inside the graph.
        assert audit_sink.events[-1].tool_name == "get_device_count"
        assert audit_sink.events[-1].outcome == "success"

    async def test_toolless_agent_answers_in_a_single_turn(
        self, specialist_factory: SpecialistFactory
    ) -> None:
        agent = specialist_factory("consultant", tools=())
        # The plain fake model raises NotImplementedError from bind_tools, so
        # this also proves the framework skips binding for tool-less agents.
        llm = GenericFakeChatModel(
            messages=iter([AIMessage(content="Please clarify the maintenance window.")])
        )
        graph = agent.build_graph(llm)
        result = await graph.ainvoke({"messages": [HumanMessage(content="change the firewall")]})
        assert result["messages"][-1].content == "Please clarify the maintenance window."


class TestValidateDefinition:
    def test_rejects_non_snake_case_name(self, specialist_factory: SpecialistFactory) -> None:
        agent = specialist_factory("Discovery Agent")
        with pytest.raises(AgentDefinitionError):
            agent.validate_definition()

    def test_rejects_empty_description(self, specialist_factory: SpecialistFactory) -> None:
        agent = specialist_factory("discovery", description="   ")
        with pytest.raises(AgentDefinitionError):
            agent.validate_definition()

    def test_rejects_empty_system_prompt(self, specialist_factory: SpecialistFactory) -> None:
        agent = specialist_factory("discovery", system_prompt="")
        with pytest.raises(AgentDefinitionError):
            agent.validate_definition()

    def test_rejects_unclassified_tools(self, specialist_factory: SpecialistFactory) -> None:
        async def plain() -> str:
            """A plain LangChain tool without classification."""
            return "data"

        unclassified = StructuredTool.from_function(coroutine=plain, name="plain")
        agent = specialist_factory("discovery", tools=[unclassified])  # type: ignore[list-item]
        with pytest.raises(AgentDefinitionError, match="NetOpsTool"):
            agent.validate_definition()

    def test_accepts_a_valid_definition(
        self, specialist_factory: SpecialistFactory, audit_sink: RecordingAuditSink
    ) -> None:
        agent = specialist_factory("discovery", tools=[_count_tool(audit_sink)])
        agent.validate_definition()  # must not raise
