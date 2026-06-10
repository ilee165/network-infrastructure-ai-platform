"""Chat-model provider factory (ADR-0009 Decision 2).

Maps a profile name — ``local`` (Ollama, default), ``anthropic``, ``openai``,
``azure`` — to a configured ``BaseChatModel``. Provider packages are imported
lazily inside the factory, so importing this module performs no provider
setup and never touches the network; constructing a model only builds a
client object (the first request opens the connection).

Secure-by-default egress (ADR-0009 Decision 3): external providers activate
only when their credentials are explicitly present in the environment
(``ANTHROPIC_API_KEY``, ``OPENAI_API_KEY``, ``AZURE_OPENAI_API_KEY`` +
``AZURE_OPENAI_ENDPOINT``); with no configuration the platform runs purely
local. Selecting an external profile is logged — M3 escalates this to an
``audit_log`` entry (ADR-0011), and M3 also adds role indirection
(``reasoning``/``fast``) and the mandatory prompt-redaction pipeline.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from langchain_core.language_models import BaseChatModel

from app.core.config import Settings, get_settings
from app.core.errors import NetOpsError
from app.core.logging import get_logger

_logger = get_logger(__name__)

#: The four profiles fixed by ADR-0009 / D9.
KNOWN_PROFILES: Final[tuple[str, ...]] = ("local", "anthropic", "openai", "azure")

#: Default model per profile when the caller does not name one. PROPOSED
#: defaults (ADR-0009 names profiles, not models); operators override via the
#: ``model`` argument. For ``azure`` the value is the *deployment* name.
DEFAULT_MODELS: Final[Mapping[str, str]] = {
    "local": "llama3.1:8b",
    "anthropic": "claude-sonnet-4-5",
    "openai": "gpt-4o",
    "azure": "gpt-4o",
}


class LLMProfileError(NetOpsError):
    """An LLM profile is unknown or its provider cannot be configured."""

    status_code = 500
    title = "LLM Provider Configuration Error"
    slug = "llm-profile"


def get_chat_model(
    profile: str | None = None,
    settings: Settings | None = None,
    *,
    model: str | None = None,
    temperature: float = 0.0,
) -> BaseChatModel:
    """Return a configured chat model for *profile*.

    Parameters
    ----------
    profile:
        One of :data:`KNOWN_PROFILES`; defaults to ``settings.llm_profile``
        (``NETOPS_LLM_PROFILE``, default ``local``).
    settings:
        Application settings; defaults to the process-wide cached instance.
    model:
        Model name override (deployment name for ``azure``); defaults per
        :data:`DEFAULT_MODELS`.
    temperature:
        Sampling temperature; deterministic ``0.0`` by default — agent
        control flow relies on structured, reproducible output (ADR-0009).

    Raises
    ------
    LLMProfileError
        For an unknown profile, or when the provider rejects its
        configuration (e.g. a missing API key for an external profile).
    """
    resolved_settings = settings if settings is not None else get_settings()
    selected = profile if profile is not None else resolved_settings.llm_profile
    if selected not in KNOWN_PROFILES:
        raise LLMProfileError(
            f"unknown LLM profile {selected!r}; known profiles: {', '.join(KNOWN_PROFILES)}"
        )
    model_name = model if model is not None else DEFAULT_MODELS[selected]
    if selected != "local":
        # ADR-0009 Decision 3: external egress is an auditable event. M3
        # escalates this structlog record to an append-only audit_log entry.
        _logger.info("external_llm_profile_selected", profile=selected, model=model_name)
    try:
        if selected == "local":
            from langchain_ollama import ChatOllama

            return ChatOllama(
                model=model_name,
                base_url=resolved_settings.ollama_base_url,
                temperature=temperature,
            )
        if selected == "anthropic":
            from langchain_anthropic import ChatAnthropic

            # `model_name` is the field ("model" is its runtime alias);
            # timeout/stop are required-by-signature with None semantics.
            return ChatAnthropic(
                model_name=model_name, temperature=temperature, timeout=None, stop=None
            )
        if selected == "openai":
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(model=model_name, temperature=temperature)
        from langchain_openai import AzureChatOpenAI

        return AzureChatOpenAI(azure_deployment=model_name, temperature=temperature)
    except Exception as exc:
        # Provider constructors validate configuration (API keys, endpoints)
        # eagerly; surface those failures as one typed platform error. The
        # message carries the provider's own description, which names missing
        # settings but never secret values.
        raise LLMProfileError(
            f"failed to construct chat model for profile '{selected}': {exc}"
        ) from exc
