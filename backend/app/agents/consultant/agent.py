"""Consultant Agent — requirement clarification specialist (M3-11, ADR-0003 §5).

Behaviour (brief §5 / DECISIONS-BRIEF.md §5):

Interactive path
    When the supervisor routes an ambiguous request here, the agent asks one
    focused clarifying question and waits for the user's answer. It never acts
    on an unclear intent — it only asks. This is the default LangGraph subgraph
    behaviour inherited from :class:`~app.agents.framework.base.BaseSpecialistAgent`
    (a tool-less agent compiles to a single model turn).

Autonomous path
    When the platform runs unattended (no human in the loop) code may call
    :meth:`ConsultantAgent.record_question` directly. The method appends a
    structured entry — question, recommended default, date stamp — to
    ``docs/consultant/QUESTIONS.md`` (or an override path injected for tests)
    and returns the recommended default so the caller can proceed without
    blocking.

Module boundary
    This agent has *no* engine tools (``tools`` returns an empty sequence), so
    it never crosses the ``agents -> framework typed tools -> engines`` boundary
    that the import-linter enforces. It imports only ``agents.framework``,
    ``core``, and the standard library.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.tools import NetOpsTool
from app.core.logging import get_logger

_logger = get_logger(__name__)

#: Default path for the autonomous QUESTIONS.md file.
#: Resolved relative to the repo root at import time so the agent works
#: wherever the process is launched from. The path is overridable via the
#: ``questions_path`` constructor argument (used in tests to avoid touching
#: the real docs tree).
_DEFAULT_QUESTIONS_PATH = (
    Path(__file__).resolve().parents[5] / "docs" / "consultant" / "QUESTIONS.md"
)


class ConsultantAgent(BaseSpecialistAgent):
    """Requirement-clarification specialist (CLAUDE.md Core Agent #2).

    Pure-reasoning agent: no engine tools, no network access. Every answer is
    a question or a recorded assumption — never an action.
    """

    def __init__(self, *, questions_path: Path | None = None) -> None:
        """Construct the consultant.

        Parameters
        ----------
        questions_path:
            Override the path to ``QUESTIONS.md`` written by
            :meth:`record_question`. Defaults to
            ``docs/consultant/QUESTIONS.md`` at the repo root. Pass a
            ``tmp_path`` fixture value in tests to avoid touching the real file.
        """
        self._questions_path: Path = questions_path or _DEFAULT_QUESTIONS_PATH

    # ------------------------------------------------------------------
    # BaseSpecialistAgent contract
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "consultant"

    @property
    def description(self) -> str:
        return (
            "Handles ambiguous or unclear requests by asking a focused clarifying "
            "question before any action is taken. Route here when the user's intent "
            "is too vague to identify a specialist confidently."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Consultant Agent for an AI Network Operations Platform.\n\n"
            "Your sole purpose is to resolve ambiguous or unclear requests by asking\n"
            "exactly ONE focused clarifying question. You never take action, run\n"
            "commands, or guess at intent — you only ask.\n\n"
            "Guidelines:\n"
            "- Ask a single, specific question that will let the appropriate specialist\n"
            "  handle the request once answered.\n"
            "- Be concise: one or two sentences at most.\n"
            "- Do not suggest solutions or diagnose problems — just identify what\n"
            "  information is missing.\n"
            "- If the user's message mentions a device, service, or symptom, include\n"
            "  that context in your question so the reply is useful to a routing agent.\n"
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        """No engine tools — the Consultant Agent is pure-reasoning only."""
        return []

    # ------------------------------------------------------------------
    # Autonomous path
    # ------------------------------------------------------------------

    async def record_question(
        self,
        *,
        question: str,
        recommended_default: str,
    ) -> str:
        """Append a structured question entry to QUESTIONS.md and return the default.

        Called by autonomous orchestration code when human interaction is not
        available. The entry records:

        - The question text
        - The recommended default the build will proceed on
        - A UTC date stamp

        Parameters
        ----------
        question:
            The clarifying question the Consultant Agent would have asked.
        recommended_default:
            The value the platform will use while awaiting a human answer.

        Returns
        -------
        str
            *recommended_default* — so the caller can proceed immediately::

                answer = await consultant.record_question(
                    question="Which environment?",
                    recommended_default="staging",
                )
                # answer == "staging"
        """
        entry = _format_entry(question=question, recommended_default=recommended_default)
        await _append_to_file(self._questions_path, entry)
        _logger.info(
            "consultant.question_recorded",
            question=question,
            recommended_default=recommended_default,
            path=str(self._questions_path),
        )
        return recommended_default


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _format_entry(*, question: str, recommended_default: str) -> str:
    """Format a single QUESTIONS.md autonomous-run entry."""
    date_str = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    return (
        f"\n---\n\n"
        f"## Autonomous Run — {date_str}\n\n"
        f"**Question:** {question}\n\n"
        f"**Recommended Default:** {recommended_default}\n\n"
        f"*Recorded automatically; the build proceeded on the recommended default.*\n"
    )


async def _append_to_file(path: Path, content: str) -> None:
    """Create parent dirs and append *content* to *path* (async, non-blocking)."""
    await asyncio.to_thread(_sync_append, path, content)


def _sync_append(path: Path, content: str) -> None:
    """Synchronous write used inside :func:`asyncio.to_thread`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(content)
