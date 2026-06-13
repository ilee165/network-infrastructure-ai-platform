"""Tests for the Consultant Agent (M3-11).

Two mandatory behaviours:

1. Interactive path — ambiguous input yields a clarifying-question message
   (the agent asks the user, rather than acting).
2. Autonomous path — the agent records the question plus recommended default
   into a structured QUESTIONS.md entry, then proceeds on the default answer.

Both are exercised fully offline with ScriptedChatModel; no network or
filesystem access to the real docs/consultant/QUESTIONS.md is performed.
The autonomous path receives a temporary file path via a seam (the agent
accepts an optional ``questions_path`` override).
"""

from __future__ import annotations

import re
from pathlib import Path

from langchain_core.messages import AIMessage, HumanMessage

from app.agents.consultant.agent import ConsultantAgent
from app.agents.framework.registry import AgentRegistry
from tests.agents.conftest import scripted_model

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(questions_path: Path | None = None) -> ConsultantAgent:
    """Return a ConsultantAgent, optionally overriding the QUESTIONS.md path."""
    return ConsultantAgent(questions_path=questions_path)


# ---------------------------------------------------------------------------
# Identity / framework contract
# ---------------------------------------------------------------------------


class TestConsultantIdentity:
    def test_name_is_consultant(self) -> None:
        agent = _make_agent()
        assert agent.name == "consultant"

    def test_description_is_non_empty_and_supervisor_oriented(self) -> None:
        agent = _make_agent()
        desc = agent.description
        assert desc.strip(), "description must not be empty"
        # Should contain language about ambiguous / clarification — so the
        # supervisor routes to it correctly.
        assert any(
            word in desc.lower() for word in ("ambiguous", "clarif", "unclear", "question")
        ), f"description does not mention ambiguity or clarification: {desc!r}"

    def test_system_prompt_is_non_empty(self) -> None:
        agent = _make_agent()
        assert agent.system_prompt.strip()

    def test_no_engine_tools(self) -> None:
        """Consultant is a pure-reasoning agent — no NetOpsTools."""
        agent = _make_agent()
        assert list(agent.tools) == []

    def test_validate_definition_passes(self) -> None:
        """The framework contract is satisfied; validate_definition() does not raise."""
        agent = _make_agent()
        agent.validate_definition()  # must not raise

    def test_registers_with_framework_registry(self) -> None:
        agent = _make_agent()
        registry = AgentRegistry()
        registry.register(agent)
        assert "consultant" in registry
        assert registry.get("consultant") is agent


# ---------------------------------------------------------------------------
# Interactive path — clarifying question
# ---------------------------------------------------------------------------


class TestInteractivePath:
    """Ambiguous input → the agent produces a clarifying-question reply."""

    async def test_ambiguous_input_yields_clarifying_question(self) -> None:
        """The compiled graph returns a clarifying question when intent is vague."""
        clarifying_reply = "Which device or service are you asking about, and what is the symptom?"
        llm = scripted_model([AIMessage(content=clarifying_reply)])
        agent = _make_agent()
        graph = agent.build_graph(llm)

        result = await graph.ainvoke({"messages": [HumanMessage(content="fix the network")]})
        last_message = result["messages"][-1]
        assert clarifying_reply in last_message.content

    async def test_clarifying_question_contains_question_mark(self) -> None:
        """Consultant replies should be question-like (sanity check on scripted output)."""
        clarifying_reply = "Can you describe the problem in more detail?"
        llm = scripted_model([AIMessage(content=clarifying_reply)])
        agent = _make_agent()
        graph = agent.build_graph(llm)

        result = await graph.ainvoke({"messages": [HumanMessage(content="something is broken")]})
        last = result["messages"][-1]
        assert "?" in last.content

    async def test_graph_compiles_with_correct_name(self) -> None:
        """The compiled subgraph should be named 'consultant'."""
        llm = scripted_model([AIMessage(content="What do you need help with?")])
        agent = _make_agent()
        graph = agent.build_graph(llm)
        # LangGraph compiled graphs expose their name
        assert graph.name == "consultant"


# ---------------------------------------------------------------------------
# Autonomous path — QUESTIONS.md entry
# ---------------------------------------------------------------------------


class TestAutonomousPath:
    """In autonomous mode the agent appends a structured entry to QUESTIONS.md
    and proceeds on the recommended default."""

    async def test_autonomous_run_appends_questions_entry(self, tmp_path: Path) -> None:
        """Calling record_question() appends a well-formed entry to the file."""
        questions_file = tmp_path / "QUESTIONS.md"
        agent = _make_agent(questions_path=questions_file)

        question = "Which environment should be targeted: production or staging?"
        default = "staging (safer; production requires explicit opt-in)"

        await agent.record_question(question=question, recommended_default=default)

        assert questions_file.exists(), "QUESTIONS.md file must be created"
        content = questions_file.read_text(encoding="utf-8")
        assert question in content
        assert default in content

    async def test_autonomous_entry_has_structured_fields(self, tmp_path: Path) -> None:
        """Entry must carry Question, Recommended Default, and a date stamp."""
        questions_file = tmp_path / "QUESTIONS.md"
        agent = _make_agent(questions_path=questions_file)

        await agent.record_question(
            question="What is the BGP AS number for the lab?",
            recommended_default="AS 65000",
        )

        content = questions_file.read_text(encoding="utf-8")
        # Structural fields expected in the entry
        assert "Question" in content or "question" in content.lower()
        assert "Recommended Default" in content or "recommended" in content.lower()
        # A date-like token must appear (YYYY-MM-DD pattern)
        assert re.search(r"\d{4}-\d{2}-\d{2}", content), "entry must contain a date stamp"

    async def test_autonomous_multiple_entries_accumulate(self, tmp_path: Path) -> None:
        """Successive calls append; they do not overwrite prior entries."""
        questions_file = tmp_path / "QUESTIONS.md"
        agent = _make_agent(questions_path=questions_file)

        await agent.record_question(
            question="First question?",
            recommended_default="Default A",
        )
        await agent.record_question(
            question="Second question?",
            recommended_default="Default B",
        )

        content = questions_file.read_text(encoding="utf-8")
        assert "First question?" in content
        assert "Default A" in content
        assert "Second question?" in content
        assert "Default B" in content

    async def test_autonomous_creates_parent_dirs(self, tmp_path: Path) -> None:
        """record_question() creates missing parent directories."""
        nested = tmp_path / "a" / "b" / "QUESTIONS.md"
        agent = _make_agent(questions_path=nested)

        await agent.record_question(
            question="Does the directory exist?",
            recommended_default="yes",
        )

        assert nested.exists()

    async def test_autonomous_proceeds_on_default(self, tmp_path: Path) -> None:
        """After recording, the method returns the recommended default so the
        caller can proceed without blocking."""
        questions_file = tmp_path / "QUESTIONS.md"
        agent = _make_agent(questions_path=questions_file)

        returned = await agent.record_question(
            question="Which VLAN should be used?",
            recommended_default="VLAN 100",
        )

        assert returned == "VLAN 100"
