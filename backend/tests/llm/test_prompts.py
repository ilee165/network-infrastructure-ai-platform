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


class TestRoutingPromptV3:
    def test_v3_is_the_latest_routing_prompt(self) -> None:
        latest = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
        assert latest.version == 3

    def test_v3_keeps_specialists_placeholder(self) -> None:
        # The supervisor fills {specialists}; losing it would break routing.
        assert "{specialists}" in get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text

    def test_v3_disambiguates_diagnosis_from_enumeration(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "troubleshooting" in text
        assert "discovery" in text
        assert "why" in text  # symptom/"wants to know why" rule
        assert "enumerat" in text  # discovery = enumeration rule
        assert "routing table" in text  # the exact phrase that mis-routed

    def test_v1_and_v2_still_registered_immutable(self) -> None:
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 1).version == 1
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 2).version == 2

    def test_v3_text_renders_to_valid_string_with_specialists(self) -> None:
        """v3 text must format without errors and leave no unfilled placeholders."""
        roster = "- troubleshooting: diagnoses faults\n- discovery: enumerates devices"
        rendered = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.format(
            specialists=roster
        )
        assert roster in rendered
        assert "{specialists}" not in rendered
        assert "{" not in rendered  # no other unfilled placeholders

    def test_v3_is_frozen_immutable(self) -> None:
        """v3 must be a frozen Pydantic model — editing text must raise."""
        from pydantic import ValidationError

        prompt = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3)
        with pytest.raises(ValidationError):
            prompt.text = "tampered"  # type: ignore[misc]

    def test_v3_contains_how_to_choose_goal_based_rule(self) -> None:
        """v3 must instruct the router to match the user's GOAL, not keywords.

        This rule is the core insight of the v3 disambiguation: a 'read
        routing table' request can be troubleshooting (if the goal is diagnosis)
        or discovery (if the goal is enumeration).
        """
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "goal" in text, (
            "v3 must say to match the user's GOAL rather than just keywords"
        )

    def test_v3_contains_examples_section(self) -> None:
        """v3 must include a concrete few-shot examples section."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "examples" in text, "v3 must have an Examples section for few-shot routing"

    def test_v3_example_shows_firewall_routing_table_as_troubleshooting(self) -> None:
        """The exact regression query (firewall routing table / guest unreachable)
        must appear in v3 examples routed to troubleshooting."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        # The v3 example: "Why can't guest users … Check the firewall's routing table."
        # -> troubleshooting
        assert "routing table" in text
        assert "troubleshooting" in text

    def test_v3_contains_ambiguous_routing_guidance(self) -> None:
        """v3 must tell the router to set ambiguous=true for vague requests
        so the Consultant can ask for clarification (ADR-0003 Decision 2)."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "ambiguous" in text

    def test_v3_discovery_rule_uses_enumeration_language(self) -> None:
        """v3's discovery routing rule must use enumeration language, not just
        the word 'discovery', to avoid keyword matching."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "enumerat" in text  # 'enumerate' or 'enumeration'
        assert "list" in text  # 'list what exists'

    def test_v2_does_not_contain_disambiguation_keywords(self) -> None:
        """v2 must NOT contain the routing-table / enumeration disambiguation
        text — verifying that v3 is the only version with the fix."""
        text_v2 = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 2).text.lower()
        assert "routing table" not in text_v2, (
            "v2 should not contain 'routing table' — that disambiguation is v3-only"
        )
        assert "enumerat" not in text_v2, (
            "v2 should not contain 'enumerat' — that rule is v3-only"
        )

    def test_v3_version_number_is_exactly_three(self) -> None:
        """Sanity: the registered version 3 prompt has version==3 (not 2, not 4)."""
        p = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3)
        assert p.version == 3

    def test_v3_prompt_id_matches_supervisor_routing_id(self) -> None:
        """v3 must use the canonical SUPERVISOR_ROUTING_PROMPT_ID so the
        supervisor's get_prompt(SUPERVISOR_ROUTING_PROMPT_ID) call picks it up."""
        p = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3)
        assert p.prompt_id == SUPERVISOR_ROUTING_PROMPT_ID

    def test_v3_includes_all_three_routing_decision_fields(self) -> None:
        """v3 must describe the three RoutingDecision fields (specialist,
        ambiguous, rationale) so models know what structured output to emit."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "specialist" in text
        assert "ambiguous" in text
        assert "rationale" in text

    def test_v3_registered_before_attempting_re_registration_raises_conflict(
        self,
    ) -> None:
        """Attempting to re-register v3 must raise ConflictError (immutability)."""
        from app.core.errors import ConflictError

        with pytest.raises(ConflictError):
            register_prompt(
                VersionedPrompt(
                    prompt_id=SUPERVISOR_ROUTING_PROMPT_ID,
                    version=3,
                    text="tampered v3 text",
                )
            )


class TestRegistryBehavior:
    def test_get_unknown_prompt_id_raises_not_found(self) -> None:

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
