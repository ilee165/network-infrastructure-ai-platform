"""Multi-LLM abstraction (ADR-0009, D9).

Everything outside this package consumes models exclusively through
:func:`~app.llm.providers.get_chat_model` and the
``langchain_core.language_models.BaseChatModel`` interface — no module may
import a concrete provider class (``ChatOllama``, ``ChatAnthropic``, ...)
directly (ADR-0009 Decision 1, enforced by import-linter alongside the
REPO-STRUCTURE §3 boundary rules).

M0 ships the profile factory (:mod:`~app.llm.providers`) and the versioned
prompt registry (:mod:`~app.llm.prompts`). M3 expands the package per
REPO-STRUCTURE §2: role indirection (``reasoning``/``fast``), embeddings
profiles, and the mandatory prompt-redaction pipeline
(:mod:`~app.llm.redaction`). Redaction is wired into ``get_chat_model`` so every
model the factory hands out strips vendor secrets before any provider call (A9).
"""

from app.llm.providers import KNOWN_PROFILES, LLMProfileError, get_chat_model
from app.llm.redaction import RedactingChatModel, redact_messages, redact_prompt

__all__ = [
    "KNOWN_PROFILES",
    "LLMProfileError",
    "RedactingChatModel",
    "get_chat_model",
    "redact_messages",
    "redact_prompt",
]
