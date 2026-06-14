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
#: routing prompts are versioned in-repo and regression-tested). Version 1 is
#: the frozen M0 text-parse prompt (the router replied with a bare specialist
#: name). It is retained for reproducibility of recorded ``(prompt_id, version)``
#: trace entries; version 2 below is the structured-output prompt the M3
#: supervisor now consumes.
SUPERVISOR_ROUTING_PROMPT_V1 = register_prompt(
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

#: Version 2 (M3-06): structured-output routing. The supervisor binds this
#: text as the system prompt and calls ``llm.with_structured_output(
#: RoutingDecision)``, so the model emits the decision as structured fields
#: (``specialist`` / ``ambiguous`` / ``rationale``) rather than free text. An
#: ambiguous request escalates to the Consultant Agent instead of guessing
#: (ADR-0003 Decision 2: "when intent is ambiguous, route to the Consultant").
SUPERVISOR_ROUTING_PROMPT = register_prompt(
    VersionedPrompt(
        prompt_id=SUPERVISOR_ROUTING_PROMPT_ID,
        version=2,
        text=(
            "You are the Master Architect Agent, the supervisor of a team of "
            "specialist network-operations agents.\n"
            "\n"
            "Read the user's request and decide how to route it. Return a "
            "RoutingDecision with these fields:\n"
            "- specialist: the name of the single best-fit specialist, or null "
            "if no specialist clearly fits.\n"
            "- ambiguous: true when the request is too vague or underspecified "
            "to route confidently (for example 'fix the network'); false when "
            "one specialist clearly fits.\n"
            "- rationale: one short sentence explaining the decision.\n"
            "\n"
            "Available specialists:\n"
            "{specialists}\n"
            "\n"
            "Rules:\n"
            "- Choose the single best fit; never name more than one specialist.\n"
            "- Only use a name from the list above; never invent a specialist.\n"
            "- If the request is ambiguous, or no specialist fits, set "
            "ambiguous=true and specialist=null so the Consultant Agent can "
            "ask a clarifying question — do not guess.\n"
        ),
    )
)

#: Version 3 (routing disambiguation): adds explicit decision rules and few-shot
#: examples so weak local models distinguish fault DIAGNOSIS (troubleshooting —
#: including reading a device's routing/BGP/OSPF/ACL state to explain a fault)
#: from inventory ENUMERATION (discovery). v2 routed "read the firewall's routing
#: table to find why guests can't reach the internet" to discovery, whose tools
#: lack get_device_routes. The {specialists} roster still provides the names.
SUPERVISOR_ROUTING_PROMPT_V3 = register_prompt(
    VersionedPrompt(
        prompt_id=SUPERVISOR_ROUTING_PROMPT_ID,
        version=3,
        text=(
            "You are the Master Architect Agent, the supervisor of a team of "
            "specialist network-operations agents.\n"
            "\n"
            "Read the user's request and decide how to route it. Return a "
            "RoutingDecision with these fields:\n"
            "- specialist: the name of the single best-fit specialist, or null "
            "if no specialist clearly fits.\n"
            "- ambiguous: true when the request is too vague or underspecified "
            "to route confidently (for example 'fix the network'); false when "
            "one specialist clearly fits.\n"
            "- rationale: one short sentence explaining the decision.\n"
            "\n"
            "Available specialists:\n"
            "{specialists}\n"
            "\n"
            "How to choose (match the user's GOAL, not just keywords):\n"
            "- If the user reports a problem or symptom and wants to know WHY "
            "(something is down, unreachable, dropping traffic, or a route / "
            "peer / adjacency is missing or wrong), route to the troubleshooting "
            "specialist. Reading a device's routing table, BGP or OSPF state, or "
            "ACLs IN ORDER TO DIAGNOSE a fault is troubleshooting work, even "
            "though it inspects a device.\n"
            "- If the user only wants to ENUMERATE or LIST what exists (run a "
            "discovery scan, list or inspect the managed-device inventory, or "
            "look up LLDP/CDP neighbors), route to the discovery specialist. "
            "Discovery is inventory enumeration, not fault diagnosis.\n"
            "- If the request is genuinely unclear or could mean several "
            "different things, set ambiguous=true and specialist=null so the "
            "consultant can ask a clarifying question.\n"
            "\n"
            "Examples:\n"
            "- 'Why can't guest users on 10.0.99.0/24 reach the internet? Check "
            "the firewall's routing table.' -> troubleshooting (a fault, asks "
            "why; reading the routing table is to diagnose it).\n"
            "- 'Is BGP peer 10.0.0.2 down on edge-1, and why?' -> "
            "troubleshooting.\n"
            "- 'List all managed devices' or 'what did the last discovery find?' "
            "-> discovery (pure enumeration).\n"
            "- 'Run a discovery scan of 10.0.0.0/24' -> discovery.\n"
            "- 'Fix the network' -> ambiguous=true, specialist=null (too vague).\n"
            "\n"
            "Rules:\n"
            "- Choose the single best fit; never name more than one specialist.\n"
            "- Only use a name from the list above; never invent a specialist.\n"
            "- If the request is ambiguous, or no specialist fits, set "
            "ambiguous=true and specialist=null so the Consultant Agent can "
            "ask a clarifying question — do not guess.\n"
        ),
    )
)
