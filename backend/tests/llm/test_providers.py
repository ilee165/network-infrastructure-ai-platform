"""Tests for the chat-model provider factory (app/llm/providers.py).

No network access: tests only construct provider client objects; external
profiles get fake credentials via monkeypatched environment variables.
"""

from __future__ import annotations

import pytest
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_ollama import ChatOllama
from langchain_openai import AzureChatOpenAI, ChatOpenAI

from app.core.config import Settings
from app.llm.providers import DEFAULT_MODELS, KNOWN_PROFILES, LLMProfileError, get_chat_model
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
    """Return the concrete provider model behind the mandatory redaction wrapper.

    ``get_chat_model`` always wraps its result in a ``RedactingChatModel`` (A9);
    these provider-identity assertions inspect the wrapped ``inner`` model.
    """
    assert isinstance(model, RedactingChatModel)
    return model.inner


class TestProfileSelection:
    def test_local_profile_returns_chat_ollama_pointed_at_settings(
        self, settings: Settings
    ) -> None:
        inner = _inner(get_chat_model("local", settings))
        assert isinstance(inner, ChatOllama)
        assert inner.base_url == settings.ollama_base_url
        assert inner.model == DEFAULT_MODELS["local"]

    def test_profile_defaults_to_settings_llm_profile(self, settings: Settings) -> None:
        assert settings.llm_profile == "local"
        assert isinstance(_inner(get_chat_model(settings=settings)), ChatOllama)

    def test_model_name_override(self, settings: Settings) -> None:
        inner = _inner(get_chat_model("local", settings, model="qwen2.5:7b"))
        assert isinstance(inner, ChatOllama)
        assert inner.model == "qwen2.5:7b"

    def test_anthropic_profile(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        assert isinstance(_inner(get_chat_model("anthropic", settings)), ChatAnthropic)

    def test_openai_profile(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        assert isinstance(_inner(get_chat_model("openai", settings)), ChatOpenAI)

    def test_azure_profile(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://unit-test.openai.azure.example")
        monkeypatch.setenv("OPENAI_API_VERSION", "2024-06-01")
        assert isinstance(_inner(get_chat_model("azure", settings)), AzureChatOpenAI)

    def test_every_known_profile_yields_a_base_chat_model(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://unit-test.openai.azure.example")
        monkeypatch.setenv("OPENAI_API_VERSION", "2024-06-01")
        for profile in KNOWN_PROFILES:
            assert isinstance(get_chat_model(profile, settings), BaseChatModel)


class TestErrors:
    def test_unknown_profile_raises_typed_error(self, settings: Settings) -> None:
        with pytest.raises(LLMProfileError, match="unknown LLM profile"):
            get_chat_model("bedrock", settings)

    def test_missing_external_credentials_raise_typed_error(self, settings: Settings) -> None:
        # _clean_provider_env removed all credentials: the OpenAI client
        # rejects construction, which must surface as the platform error.
        with pytest.raises(LLMProfileError, match="failed to construct"):
            get_chat_model("openai", settings)
