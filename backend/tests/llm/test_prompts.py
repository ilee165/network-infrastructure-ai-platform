"""Tests for the versioned prompt registry (app/llm/prompts/__init__.py).

Tests register prompts under unique test-only ids so the module-global
registry stays clean for other tests in the same session.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.errors import ConflictError, NotFoundError
from app.llm.prompts import (
    SUPERVISOR_ROUTING_PROMPT_ID,
    VersionedPrompt,
    get_prompt,
    list_prompts,
    register_prompt,
)


class TestSupervisorRoutingPrompt:
    def test_version_one_text_parse_prompt_still_registered(self) -> None:
        # The M0 text-parse prompt is frozen at version 1 (reproducibility).
        prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, version=1)
        assert prompt.version == 1
        assert "{specialists}" in prompt.text

    def test_latest_version_is_the_structured_output_prompt(self) -> None:
        # M3-06 registered version 2 for structured-output routing; it is the
        # default (latest) version the supervisor now consumes.
        prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
        assert prompt.version >= 2
        assert "{specialists}" in prompt.text

    def test_text_formats_with_a_specialist_roster(self) -> None:
        prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
        rendered = prompt.text.format(specialists="- troubleshooting: diagnoses problems")
        assert "- troubleshooting: diagnoses problems" in rendered
        assert "{specialists}" not in rendered

    def test_listed_by_list_prompts(self) -> None:
        ids = [p.prompt_id for p in list_prompts()]
        assert SUPERVISOR_ROUTING_PROMPT_ID in ids


class TestRegistryBehavior:
    def test_get_unknown_prompt_id_raises_not_found(self) -> None:
        with pytest.raises(NotFoundError):
            get_prompt("test/does-not-exist")

    def test_get_unknown_version_raises_not_found(self) -> None:
        register_prompt(VersionedPrompt(prompt_id="test/known-version", version=1, text="v1 text"))
        with pytest.raises(NotFoundError):
            get_prompt("test/known-version", version=9)

    def test_register_duplicate_version_raises_conflict(self) -> None:
        register_prompt(VersionedPrompt(prompt_id="test/duplicate", version=1, text="original"))
        with pytest.raises(ConflictError):
            register_prompt(VersionedPrompt(prompt_id="test/duplicate", version=1, text="edited"))

    def test_get_returns_latest_version_by_default(self) -> None:
        register_prompt(VersionedPrompt(prompt_id="test/multi", version=1, text="v1"))
        register_prompt(VersionedPrompt(prompt_id="test/multi", version=2, text="v2"))
        assert get_prompt("test/multi").text == "v2"
        assert get_prompt("test/multi", version=1).text == "v1"

    def test_prompt_versions_are_immutable(self) -> None:
        prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
        with pytest.raises(ValidationError):
            prompt.text = "tampered"  # type: ignore[misc]

    def test_version_must_be_a_positive_integer(self) -> None:
        with pytest.raises(ValidationError):
            VersionedPrompt(prompt_id="test/bad-version", version=0, text="text")
