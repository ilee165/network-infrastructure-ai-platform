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
profiles, and the mandatory prompt-redaction pipeline (``redaction.py``).
"""

from app.llm.providers import KNOWN_PROFILES, LLMProfileError, get_chat_model

__all__ = [
    "KNOWN_PROFILES",
    "LLMProfileError",
    "get_chat_model",
]
