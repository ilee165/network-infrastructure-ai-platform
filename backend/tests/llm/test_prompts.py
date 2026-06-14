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

    def test_v3_formats_cleanly_with_specialist_roster(self) -> None:
        """format() with {specialists} must not raise and must interpolate."""
        roster = "- discovery: lists devices\n- troubleshooting: diagnoses faults"
        rendered = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.format(
            specialists=roster
        )
        assert "- discovery: lists devices" in rendered
        assert "{specialists}" not in rendered

    def test_v3_describes_null_specialist_for_ambiguous_requests(self) -> None:
        """v3 must instruct the model to set specialist=null when request is
        ambiguous, so the consultant can ask a clarifying question instead of
        the supervisor guessing."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "null" in text
        assert "ambiguous" in text

    def test_v3_contains_examples_section(self) -> None:
        """Few-shot examples are essential for weak local models; v3 must have
        them so removal is caught immediately."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text
        assert "Examples:" in text

    def test_v3_contains_rules_section(self) -> None:
        """The explicit Rules: block guards single-specialist and no-invention
        constraints that v1/v2 also had — verify they survive in v3."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text
        assert "Rules:" in text

    def test_v3_instructs_goal_not_keyword_matching(self) -> None:
        """v3 adds the 'match the user's GOAL, not just keywords' instruction;
        losing it would revert to the keyword-matching failure mode."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "goal" in text

    def test_v3_covers_routing_decision_fields(self) -> None:
        """v3 must describe all three RoutingDecision fields (specialist,
        ambiguous, rationale) so a weak model knows what to return."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "specialist" in text
        assert "ambiguous" in text
        assert "rationale" in text

    def test_v3_explicitly_says_reading_state_to_diagnose_is_troubleshooting(
        self,
    ) -> None:
        """The core disambiguation rule must survive verbatim: reading a device's
        routing/BGP/OSPF/ACL state IN ORDER TO DIAGNOSE is troubleshooting."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text
        # Check the key phrase that guards the regression
        assert "IN ORDER TO DIAGNOSE" in text

    def test_v3_example_regression_query_maps_to_troubleshooting(self) -> None:
        """The specific query that regressed (guest users can't reach internet)
        must appear as a troubleshooting example in v3."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "guest" in text
        assert "troubleshooting" in text

    def test_v3_example_run_discovery_scan_maps_to_discovery(self) -> None:
        """A 'run a discovery scan' example must route to discovery in v3."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "discovery scan" in text
        assert "discovery" in text

    def test_v3_example_fix_network_maps_to_ambiguous(self) -> None:
        """'Fix the network' must be marked as the canonical ambiguous example."""
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "fix the network" in text


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
