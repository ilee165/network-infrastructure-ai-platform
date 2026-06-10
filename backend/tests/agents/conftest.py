"""Shared fixtures and fakes for the agent-framework tests.

Everything here is deterministic and offline: a scripted chat model standing
in for the LLM, a recording audit sink, and a test-only approving gate
(production code deliberately ships no allow-all gate — CLAUDE.md: human
approval for changes).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.runnables import Runnable

from app.agents.framework.approval import ApprovalDecision, ApprovalRequest
from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool, ToolAuditEvent


class ScriptedChatModel(GenericFakeChatModel):
    """A scripted fake chat model that tolerates tool binding.

    ``GenericFakeChatModel`` replays a fixed message script but raises
    ``NotImplementedError`` from ``bind_tools``; the framework binds declared
    tools onto the model, so the fake accepts (and ignores) the binding.
    """

    def bind_tools(self, tools: Any, **kwargs: Any) -> Runnable[Any, Any]:
        """Return self unchanged — the script already contains any tool calls."""
        return self


def scripted_model(replies: Iterable[AIMessage]) -> BaseChatModel:
    """Build a :class:`ScriptedChatModel` replaying *replies* in order."""
    return ScriptedChatModel(messages=iter(replies))


class RecordingAuditSink:
    """AuditSink test double that retains every event in order."""

    def __init__(self) -> None:
        self.events: list[ToolAuditEvent] = []

    async def record(self, event: ToolAuditEvent) -> None:
        self.events.append(event)


class ApproveAllGate:
    """Test-only gate that approves everything.

    Exists exclusively for tests: production ships only
    :class:`~app.agents.framework.approval.DenyAllGate` until the M5
    ChangeRequest workflow.
    """

    async def authorize(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            approved=True,
            reason="approved by test gate",
            change_request_id="cr-test-0001",
        )


class _StubSpecialist(BaseSpecialistAgent):
    """Closure-configured specialist used to exercise registry/supervisor."""

    def __init__(
        self,
        name: str,
        description: str,
        system_prompt: str,
        tools: Sequence[NetOpsTool],
    ) -> None:
        self._name = name
        self._description = description
        self._system_prompt = system_prompt
        self._tools = list(tools)

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def system_prompt(self) -> str:
        return self._system_prompt

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        return self._tools


SpecialistFactory = Callable[..., BaseSpecialistAgent]


@pytest.fixture()
def specialist_factory() -> SpecialistFactory:
    """Factory building minimal valid specialists with overridable fields."""

    def make(
        name: str,
        *,
        description: str | None = None,
        system_prompt: str = "You are a test specialist agent.",
        tools: Sequence[NetOpsTool] = (),
    ) -> BaseSpecialistAgent:
        return _StubSpecialist(
            name=name,
            description=description if description is not None else f"Handles {name} requests.",
            system_prompt=system_prompt,
            tools=tools,
        )

    return make


@pytest.fixture()
def audit_sink() -> RecordingAuditSink:
    """A fresh recording audit sink."""
    return RecordingAuditSink()
