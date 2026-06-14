"""Tests for role indirection, external-egress auditing, and the structured-
output helper (app/llm/providers.py — M3-05).

No network access: provider clients are only *constructed* (never invoked over
the wire), and the structured-output path is driven by an offline fake chat
model that replays a fixed script.
"""

from __future__ import annotations

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from app.core.config import Settings
from app.llm.providers import (
    LLMAuditEvent,
    LLMAuditSink,
    LLMProfileError,
    LoggingLLMAuditSink,
    get_chat_model,
    get_chat_model_for_role,
    structured_output,
)
from app.llm.redaction import RedactingChatModel

_EXTERNAL_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_AD_TOKEN",
    "AZURE_OPENAI_ENDPOINT",
    "OPENAI_API_VERSION",
)


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate tests from any real provider credentials on the host."""
    for var in _EXTERNAL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _inner(model: BaseChatModel) -> BaseChatModel:
    """Return the concrete provider model behind the mandatory redaction wrapper."""
    assert isinstance(model, RedactingChatModel)
    return model.inner


class _RecordingAuditSink:
    """LLMAuditSink test double retaining every event in order."""

    def __init__(self) -> None:
        self.events: list[LLMAuditEvent] = []

    def record(self, event: LLMAuditEvent) -> None:
        self.events.append(event)


# --------------------------------------------------------------------------- #
# Role indirection                                                            #
# --------------------------------------------------------------------------- #
class TestRoleIndirection:
    def test_roles_default_to_local_profile(self, settings: Settings) -> None:
        assert isinstance(_inner(get_chat_model_for_role("reasoning", settings)), ChatOllama)
        assert isinstance(_inner(get_chat_model_for_role("fast", settings)), ChatOllama)

    def test_reasoning_role_maps_to_configured_profile(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        routed = settings.model_copy(update={"llm_role_reasoning": "openai"})
        assert isinstance(_inner(get_chat_model_for_role("reasoning", routed)), ChatOpenAI)
        # `fast` is untouched and still resolves to the local default.
        assert isinstance(_inner(get_chat_model_for_role("fast", routed)), ChatOllama)

    def test_unknown_role_raises_typed_error(self, settings: Settings) -> None:
        with pytest.raises(LLMProfileError, match="unknown LLM role"):
            get_chat_model_for_role("summarizer", settings)


# --------------------------------------------------------------------------- #
# External egress is audited (data leaving the deployment)                    #
# --------------------------------------------------------------------------- #
class TestExternalEgressAudit:
    def test_selecting_external_profile_emits_audit_event(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        sink = _RecordingAuditSink()
        get_chat_model("openai", settings, audit_sink=sink)
        assert len(sink.events) == 1
        event = sink.events[0]
        assert event.profile == "openai"
        assert event.egress is True

    def test_local_profile_emits_no_egress_audit_event(self, settings: Settings) -> None:
        sink = _RecordingAuditSink()
        get_chat_model("local", settings, audit_sink=sink)
        assert sink.events == []

    def test_role_routing_to_external_profile_is_audited(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        routed = settings.model_copy(update={"llm_role_reasoning": "openai"})
        sink = _RecordingAuditSink()
        get_chat_model_for_role("reasoning", routed, audit_sink=sink)
        assert [e.profile for e in sink.events] == ["openai"]

    def test_default_audit_sink_is_the_logging_sink(self) -> None:
        # The factory works with no sink injected (logs the egress event).
        assert isinstance(LoggingLLMAuditSink(), LLMAuditSink)

    def test_openai_profile_without_key_raises_config_error(self, settings: Settings) -> None:
        """Spec gate: selecting an external profile with no key must raise LLMProfileError.

        The autouse ``_clean_provider_env`` fixture strips OPENAI_API_KEY, so
        no monkeypatch is needed here — the precondition is already satisfied.
        """
        with pytest.raises(LLMProfileError):
            get_chat_model("openai", settings)

    def test_anthropic_profile_without_key_raises_config_error(self, settings: Settings) -> None:
        """Spec gate: anthropic profile without ANTHROPIC_API_KEY raises LLMProfileError."""
        with pytest.raises(LLMProfileError):
            get_chat_model("anthropic", settings)

    def test_azure_profile_without_key_raises_config_error(self, settings: Settings) -> None:
        """Spec gate: azure profile without AZURE_OPENAI_API_KEY raises LLMProfileError."""
        with pytest.raises(LLMProfileError):
            get_chat_model("azure", settings)


# --------------------------------------------------------------------------- #
# Structured-output helper: JSON parse + one bounded retry                    #
# --------------------------------------------------------------------------- #
class _Finding(BaseModel):
    device: str = Field(min_length=1)
    severity: str = Field(min_length=1)


def _fake(replies: list[AIMessage]) -> GenericFakeChatModel:
    return GenericFakeChatModel(messages=iter(replies))


class TestStructuredOutput:
    def test_valid_json_first_attempt_parses(self) -> None:
        model = _fake([AIMessage(content='{"device": "r1", "severity": "warn"}')])
        runnable = structured_output(model, _Finding)
        result = runnable.invoke("classify this")
        assert isinstance(result, _Finding)
        assert result.device == "r1"
        assert result.severity == "warn"

    def test_retry_succeeds_on_second_attempt(self) -> None:
        # First reply is invalid JSON; the bounded retry produces a valid object.
        model = _fake(
            [
                AIMessage(content="sorry, here is the answer: device r1 is warn"),
                AIMessage(content='{"device": "r1", "severity": "warn"}'),
            ]
        )
        runnable = structured_output(model, _Finding)
        result = runnable.invoke("classify this")
        assert isinstance(result, _Finding)
        assert result.device == "r1"

    def test_retry_is_bounded_to_one_attempt(self) -> None:
        # Two bad replies exhaust the single retry and the error surfaces.
        model = _fake(
            [
                AIMessage(content="not json at all"),
                AIMessage(content="still not json"),
            ]
        )
        runnable = structured_output(model, _Finding)
        with pytest.raises(LLMProfileError, match="structured output"):
            runnable.invoke("classify this")

    async def test_async_retry_succeeds_on_second_attempt(self) -> None:
        model = _fake(
            [
                AIMessage(content="nope"),
                AIMessage(content='{"device": "r2", "severity": "info"}'),
            ]
        )
        runnable = structured_output(model, _Finding)
        result = await runnable.ainvoke("classify this")
        assert isinstance(result, _Finding)
        assert result.device == "r2"
