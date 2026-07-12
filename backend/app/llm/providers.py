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
local. Selecting an external profile emits an :class:`LLMAuditEvent` through a
pluggable :class:`LLMAuditSink` (M3 default: a structlog line; M5 injects the
append-only ``audit_log`` writer of ADR-0011).

Role indirection (ADR-0009 Decision 2): :func:`get_chat_model_for_role` resolves
the ``reasoning`` / ``fast`` roles to profiles via settings, so operators route
heavy planning and cheap summarization to different models without code changes.
Structured output (Decision 5): :func:`structured_output` wraps any model with
a JSON-output parser and ONE bounded retry, for models lacking native JSON
mode. Every model the factory returns is also wrapped in the mandatory
:class:`~app.llm.redaction.RedactingChatModel` prompt-redaction pipeline.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Final, Protocol, TypeVar, runtime_checkable

from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
from pydantic import BaseModel, ValidationError

from app.core.config import Settings, get_settings
from app.core.errors import NetOpsError
from app.core.logging import get_logger
from app.llm.redaction import wrap_with_redaction

_logger = get_logger(__name__)

#: The four profiles fixed by ADR-0009 / D9.
KNOWN_PROFILES: Final[tuple[str, ...]] = ("local", "anthropic", "openai", "azure")

#: Role indirection (ADR-0009 D2): agents request a model by role, settings map
#: each role to a profile. ``reasoning`` is the heavy planning path; ``fast`` is
#: cheap tool-output summarization.
KNOWN_ROLES: Final[tuple[str, ...]] = ("reasoning", "fast")

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


class LLMAuditEvent(BaseModel):
    """One audited LLM-egress decision: an *external* profile was selected.

    Selecting any non-``local`` profile means prompt data may leave the
    deployment (ADR-0009 D3); the platform records that as an auditable event.
    M5 links these to the append-only ``audit_log`` (ADR-0011); at M3 the
    default sink emits a structlog line. Only non-secret metadata is recorded —
    never an API key or prompt body.
    """

    model_config = {"frozen": True}

    #: The selected external profile (never ``local``).
    profile: str
    #: Resolved model / deployment name.
    model: str
    #: Always ``True`` — every recorded event is an egress decision.
    egress: bool = True
    #: Role that resolved to this profile, when selection went through role
    #: indirection; ``None`` for a directly named profile.
    role: str | None = None


@runtime_checkable
class LLMAuditSink(Protocol):
    """Destination for LLM-egress audit events (pluggable seam).

    Mirrors :class:`app.agents.framework.tools.AuditSink` but lives in
    ``app/llm/`` so the provider factory never imports the agent framework
    (import-linter: only ``app/llm/`` touches provider classes; the LLM layer
    stays a leaf). M5 swaps in the ``audit_log`` writer; M3 ships the logging
    default below.
    """

    def record(self, event: LLMAuditEvent) -> None:
        """Record *event*; raise on failure (audit-everything, never swallow)."""
        ...


class LoggingLLMAuditSink:
    """Default sink: emit each egress decision as one structlog line."""

    def record(self, event: LLMAuditEvent) -> None:
        """Log *event* as a structured ``external_llm_profile_selected`` record."""
        _logger.info("external_llm_profile_selected", **event.model_dump())


#: Process-wide chat-model cache keyed by (profile, model_name, temperature).
#: Cleared on LLM settings PATCH (Wave 5 / agents H1) so profile switches take
#: effect without a process restart. Connection reuse to Ollama/Anthropic is
#: the primary win — LangChain clients keep HTTP pools on the instance.
_CHAT_MODEL_CACHE: dict[tuple[str, str, float], BaseChatModel] = {}


def clear_chat_model_cache() -> None:
    """Drop cached provider clients (settings change / tests)."""
    _CHAT_MODEL_CACHE.clear()


def get_chat_model(
    profile: str | None = None,
    settings: Settings | None = None,
    *,
    model: str | None = None,
    temperature: float = 0.0,
    audit_sink: LLMAuditSink | None = None,
    _role: str | None = None,
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

    Notes
    -----
    The returned model is always wrapped in a
    :class:`~app.llm.redaction.RedactingChatModel` (A9): every prompt is
    stripped of vendor secrets *before* it reaches the provider, on every
    profile — including ``local`` — so callers cannot leak credentials by
    forgetting to redact manually.
    """
    resolved_settings = settings if settings is not None else get_settings()
    selected = profile if profile is not None else resolved_settings.llm_profile
    if selected not in KNOWN_PROFILES:
        raise LLMProfileError(
            f"unknown LLM profile {selected!r}; known profiles: {', '.join(KNOWN_PROFILES)}"
        )
    if model is not None:
        model_name = model
    elif selected == "local":
        # The local Ollama model is operator-configurable (NETOPS_LLM_LOCAL_MODEL)
        # so picking a pulled model never requires a code change.
        model_name = resolved_settings.llm_local_model
    else:
        model_name = DEFAULT_MODELS[selected]
    if selected != "local":
        # ADR-0009 Decision 3: selecting an external profile means data may
        # leave the deployment, so it is an auditable event. The sink defaults
        # to a structlog line; M5 injects the append-only ``audit_log`` writer.
        sink = audit_sink if audit_sink is not None else LoggingLLMAuditSink()
        sink.record(LLMAuditEvent(profile=selected, model=model_name, role=_role))
    # LLM cost/usage SLI (ADR-0015 §2 / ADR-0046 §1): count the request by profile
    # + resolved model at the one factory all callers route through. Per-call
    # latency + token totals are observed by the provider/runtime layer where the
    # actual invoke happens, via ``metrics.observe_llm_request(... latency/tokens)``
    # — this site owns only the request count (never a prompt/response body).
    from app.core import metrics

    metrics.observe_llm_request(profile=selected, model=model_name)
    cache_key = (selected, model_name, temperature)
    cached = _CHAT_MODEL_CACHE.get(cache_key)
    if cached is not None:
        return cached
    provider_model = _build_provider_model(selected, model_name, resolved_settings, temperature)
    # A9: central, bypass-proof redaction wraps every model the factory returns.
    wrapped = wrap_with_redaction(provider_model)
    _CHAT_MODEL_CACHE[cache_key] = wrapped
    return wrapped


def _build_provider_model(
    selected: str,
    model_name: str,
    resolved_settings: Settings,
    temperature: float,
) -> BaseChatModel:
    """Construct the concrete provider client for *selected* (pre-redaction)."""
    try:
        if selected == "local":
            from langchain_ollama import ChatOllama

            return ChatOllama(
                model=model_name,
                base_url=resolved_settings.ollama_base_url,
                temperature=temperature,
            )
        if selected == "anthropic":
            import os

            from langchain_anthropic import ChatAnthropic

            # langchain_anthropic silently accepts an empty key and only fails
            # at call time; enforce the credential requirement eagerly so the
            # error surfaces at configuration time (ADR-0009 D3 secure-by-default).
            if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
                raise ValueError("ANTHROPIC_API_KEY is not set; cannot use the 'anthropic' profile")
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


def get_chat_model_for_role(
    role: str,
    settings: Settings | None = None,
    *,
    model: str | None = None,
    temperature: float = 0.0,
    audit_sink: LLMAuditSink | None = None,
) -> BaseChatModel:
    """Return a chat model for *role*, routed to a profile via settings.

    Role indirection (ADR-0009 D2): agents ask for ``"reasoning"`` (heavy
    planning) or ``"fast"`` (cheap summarization); the operator maps each role
    to a profile in settings (defaulting to ``llm_profile``). Routing a role to
    an external profile is audited exactly like a direct selection — the
    resolved ``role`` is recorded on the event.

    Raises
    ------
    LLMProfileError
        For an unknown role, or when the resolved profile cannot be configured.
    """
    if role not in KNOWN_ROLES:
        raise LLMProfileError(f"unknown LLM role {role!r}; known roles: {', '.join(KNOWN_ROLES)}")
    resolved_settings = settings if settings is not None else get_settings()
    profile = resolved_settings.llm_profile_for_role(role)
    return get_chat_model(
        profile,
        resolved_settings,
        model=model,
        temperature=temperature,
        audit_sink=audit_sink,
        _role=role,
    )


_SchemaT = TypeVar("_SchemaT", bound=BaseModel)

#: Appended to the prompt when asking a model that lacks native JSON mode to
#: emit structured output. Kept terse: the schema fields are described by the
#: caller's prompt; this only constrains the *envelope*.
_JSON_DIRECTIVE: Final[str] = (
    "Respond with ONLY a single JSON object matching this schema, no prose, no "
    "markdown fences:\n{schema}"
)

#: Appended on the single bounded retry, carrying the prior failure back to the
#: model so it can self-correct (ADR-0009 D5: one bounded retry).
_RETRY_DIRECTIVE: Final[str] = (
    "Your previous response was not valid JSON for the schema "
    "({error}). Respond again with ONLY the corrected JSON object."
)


def _parse_schema(schema: type[_SchemaT], message: BaseMessage) -> _SchemaT:
    """Parse *message* content into *schema*, raising ``ValidationError`` on failure."""
    content = message.content if isinstance(message.content, str) else str(message.content)
    return schema.model_validate_json(content.strip())


def _structured_messages(prompt: LanguageModelInput, schema: type[BaseModel]) -> list[BaseMessage]:
    """Build the message list for a JSON-mode request from *prompt*."""
    directive = _JSON_DIRECTIVE.format(schema=json.dumps(schema.model_json_schema()))
    if isinstance(prompt, str):
        return [HumanMessage(content=f"{prompt}\n\n{directive}")]
    messages: list[BaseMessage] = []
    if isinstance(prompt, BaseMessage):
        messages.append(prompt)
    else:
        for item in prompt:
            msg = item if isinstance(item, BaseMessage) else HumanMessage(content=str(item))
            messages.append(msg)
    return [*messages, HumanMessage(content=directive)]


def structured_output(
    model: BaseChatModel, schema: type[_SchemaT]
) -> Runnable[LanguageModelInput, _SchemaT]:
    """Wrap *model* so it returns a validated *schema* instance (ADR-0009 D5).

    For models without native tool/JSON mode (some Ollama models), this asks
    for a bare JSON object, parses it into *schema*, and on a validation
    failure performs exactly ONE bounded retry that feeds the error back to the
    model. After the retry still fails, a typed :class:`LLMProfileError` is
    raised (the prior raw output is never echoed, so no prompt content leaks).

    The returned runnable supports both ``invoke`` and ``ainvoke``.
    """

    def _run(prompt: LanguageModelInput, config: RunnableConfig | None = None) -> _SchemaT:
        messages = _structured_messages(prompt, schema)
        first = model.invoke(messages, config=config)
        try:
            return _parse_schema(schema, first)
        except ValidationError as exc:
            retry = [
                *messages,
                AIMessage(content=str(first.content)),
                HumanMessage(content=_RETRY_DIRECTIVE.format(error=_summarize(exc))),
            ]
            second = model.invoke(retry, config=config)
            return _parse_retry(schema, second)

    async def _arun(prompt: LanguageModelInput, config: RunnableConfig | None = None) -> _SchemaT:
        messages = _structured_messages(prompt, schema)
        first = await model.ainvoke(messages, config=config)
        try:
            return _parse_schema(schema, first)
        except ValidationError as exc:
            retry = [
                *messages,
                AIMessage(content=str(first.content)),
                HumanMessage(content=_RETRY_DIRECTIVE.format(error=_summarize(exc))),
            ]
            second = await model.ainvoke(retry, config=config)
            return _parse_retry(schema, second)

    return RunnableLambda(_run, afunc=_arun)


def _parse_retry(schema: type[_SchemaT], message: BaseMessage) -> _SchemaT:
    """Parse the retry response; the second failure is terminal (one bounded retry)."""
    try:
        return _parse_schema(schema, message)
    except ValidationError as exc:
        raise LLMProfileError(
            f"model did not return valid structured output for "
            f"{schema.__name__} after one retry: {_summarize(exc)}"
        ) from exc


def _summarize(exc: ValidationError) -> str:
    """Render a validation error compactly (field locations + messages, no values).

    The model's raw output is deliberately *not* included, so no prompt or
    response content can leak into logs or error responses.
    """
    parts = [
        f"{'.'.join(str(loc) for loc in e['loc']) or '<root>'}: {e['type']}" for e in exc.errors()
    ]
    return "; ".join(parts) or "validation failed"


__all__ = [
    "DEFAULT_MODELS",
    "KNOWN_PROFILES",
    "KNOWN_ROLES",
    "LLMAuditEvent",
    "LLMAuditSink",
    "LLMProfileError",
    "LoggingLLMAuditSink",
    "get_chat_model",
    "get_chat_model_for_role",
    "structured_output",
]
