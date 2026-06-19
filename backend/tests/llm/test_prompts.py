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

    def test_v1_v2_v3_still_registered_immutable(self) -> None:
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 1).version == 1
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 2).version == 2
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).version == 3


class TestRoutingPromptV4:
    def test_v4_is_registered_as_the_five_way_prompt(self) -> None:
        # v4 is the 5-way prompt (T13); T14 supersedes it with v5 (8-way) but v4
        # stays registered and immutable for reproducibility.
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 4).version == 4

    def test_v4_keeps_specialists_placeholder(self) -> None:
        # The supervisor fills {specialists}; losing it would break routing.
        assert "{specialists}" in get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 4).text

    def test_v4_covers_all_five_specialists(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 4).text.lower()
        for specialist in (
            "discovery",
            "troubleshooting",
            "consultant",
            "configuration",
            "documentation",
        ):
            assert specialist in text

    def test_v4_adds_config_and_documentation_decision_rules(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 4).text.lower()
        # Configuration => drift/compliance narration.
        assert "drift" in text
        assert "complian" in text
        # Documentation => generate inventory/diagram/runbook.
        assert "inventory" in text
        assert "diagram" in text
        assert "runbook" in text

    def test_v4_preserves_v3_diagnosis_vs_enumeration_rules(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 4).text.lower()
        assert "why" in text  # symptom/diagnosis rule retained
        assert "enumerat" in text  # discovery = enumeration rule retained
        assert "routing table" in text  # the exact phrase that mis-routed in v2

    def test_v1_through_v3_still_registered_immutable(self) -> None:
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 1).version == 1
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 2).version == 2
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).version == 3


class TestRoutingPromptV5:
    def test_v5_is_the_latest_routing_prompt(self) -> None:
        # The supervisor auto-selects the latest; v5 is the 8-way prompt (T14).
        latest = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
        assert latest.version == 5

    def test_v5_keeps_specialists_placeholder(self) -> None:
        assert "{specialists}" in get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 5).text

    def test_v5_covers_all_eight_specialists(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 5).text.lower()
        for specialist in (
            "discovery",
            "troubleshooting",
            "consultant",
            "configuration",
            "documentation",
            "automation",
            "ddi",
            "packet",
        ):
            assert specialist in text

    def test_v5_adds_wave4_decision_rules(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 5).text.lower()
        # DDI => DNS/DHCP records + drafting a change request.
        assert "dns" in text
        assert "dhcp" in text
        # Packet analysis => capture / pcap.
        assert "capture" in text
        # Automation => execute an APPROVED change request only.
        assert "approved" in text

    def test_v5_enforces_change_drafts_not_executes_invariant(self) -> None:
        # The critical M5 routing invariant: a request to CHANGE the network
        # routes to the draft-a-CR path, NOT to direct execution.
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 5).text.lower()
        assert "change request" in text
        # The prompt must distinguish drafting/proposing a change from executing
        # an already-approved one (the automation boundary).
        assert "approved" in text
        assert "execut" in text

    def test_v5_preserves_v4_and_v3_rules(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 5).text.lower()
        # v3 diagnosis-vs-enumeration rules retained.
        assert "why" in text
        assert "enumerat" in text
        assert "routing table" in text
        # v4 config/documentation boundaries retained.
        assert "drift" in text
        assert "complian" in text
        assert "inventory" in text
        assert "diagram" in text
        assert "runbook" in text

    def test_v1_through_v4_still_registered_immutable(self) -> None:
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 1).version == 1
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 2).version == 2
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).version == 3
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 4).version == 4


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
