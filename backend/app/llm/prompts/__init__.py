"""Versioned prompt registry (ADR-0009 Decision 4).

Every prompt the platform sends to a model is versioned in-repo and addressed
by ``(prompt_id, version)``; reasoning traces record both so any AI decision
is reproducible. M0 keeps prompt text in this module's registry; M3 moves the
texts into per-agent prompt files with ``prompt_id``/``version`` front-matter
under ``llm/prompts/<agent_name>/`` (REPO-STRUCTURE §2) loaded through this
same registry API.

Prompt texts are ``str.format`` templates: placeholders like
``{specialists}`` are filled by the consumer; literal braces must be doubled.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import ConflictError, NotFoundError

#: Prompt id of the supervisor's routing prompt (consumed by
#: :mod:`app.agents.framework.supervisor`).
SUPERVISOR_ROUTING_PROMPT_ID = "master_architect/routing"


class VersionedPrompt(BaseModel):
    """One immutable prompt version.

    Editing a prompt's text means registering a *new* version — published
    versions are frozen so recorded ``(prompt_id, version)`` pairs in
    reasoning traces stay reproducible (ADR-0009).
    """

    model_config = ConfigDict(frozen=True)

    #: Stable identifier, conventionally ``"<agent_name>/<purpose>"``.
    prompt_id: str = Field(min_length=1)
    #: Integer version, starting at 1.
    version: int = Field(ge=1)
    #: The prompt template text (``str.format`` placeholders allowed).
    text: str = Field(min_length=1)


_REGISTRY: dict[str, dict[int, VersionedPrompt]] = {}


def register_prompt(prompt: VersionedPrompt) -> VersionedPrompt:
    """Add *prompt* to the registry; returns it for assignment chaining.

    Raises :class:`~app.core.errors.ConflictError` if that
    ``(prompt_id, version)`` pair is already registered — published versions
    are immutable.
    """
    versions = _REGISTRY.setdefault(prompt.prompt_id, {})
    if prompt.version in versions:
        raise ConflictError(
            f"prompt '{prompt.prompt_id}' version {prompt.version} is already registered; "
            "register a new version instead of editing a published one"
        )
    versions[prompt.version] = prompt
    return prompt


def get_prompt(prompt_id: str, version: int | None = None) -> VersionedPrompt:
    """Return a registered prompt — the latest version unless *version* is given.

    Raises :class:`~app.core.errors.NotFoundError` for an unknown id or
    version.
    """
    versions = _REGISTRY.get(prompt_id)
    if not versions:
        raise NotFoundError(f"prompt '{prompt_id}' is not registered")
    if version is None:
        return versions[max(versions)]
    try:
        return versions[version]
    except KeyError:
        raise NotFoundError(
            f"prompt '{prompt_id}' has no version {version} "
            f"(available: {', '.join(str(v) for v in sorted(versions))})"
        ) from None


def list_prompts() -> list[VersionedPrompt]:
    """Return every registered prompt version, ordered by id then version."""
    return [
        versions[version]
        for prompt_id, versions in sorted(_REGISTRY.items())
        for version in sorted(versions)
    ]


#: First registry entry: the Master Architect's routing prompt (ADR-0003 —
#: routing prompts are versioned in-repo and regression-tested).
SUPERVISOR_ROUTING_PROMPT = register_prompt(
    VersionedPrompt(
        prompt_id=SUPERVISOR_ROUTING_PROMPT_ID,
        version=1,
        text=(
            "You are the Master Architect Agent, the supervisor of a team of "
            "specialist network-operations agents.\n"
            "\n"
            "Read the user's request and select exactly ONE specialist to handle it.\n"
            "\n"
            "Available specialists:\n"
            "{specialists}\n"
            "\n"
            "Rules:\n"
            "- Reply with the chosen specialist's name and nothing else.\n"
            "- Choose the single best fit; never name more than one specialist.\n"
            "- Only use names from the list above; never invent a specialist.\n"
        ),
    )
)
