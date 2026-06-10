"""Kind mapping, required-section extraction/validation, sanitization, note paths."""

import pytest

from obsidian_mcp.templates import (
    create_note,
    kind_spec,
    missing_sections,
    note_rel_path,
    required_sections,
    sanitize_component,
    template_text,
)
from obsidian_mcp.vault import Vault, VaultError


class TestKindSpec:
    def test_known_kinds(self) -> None:
        assert kind_spec("runbook") == ("06-Runbooks", "RUNBOOK_TEMPLATE.md")
        assert kind_spec("incident") == ("07-Incidents", "NETWORK_INCIDENT_TEMPLATE.md")
        assert kind_spec("knowledge") == ("04-Knowledge", "KNOWLEDGE_ARTICLE_TEMPLATE.md")
        assert kind_spec("project") == ("02-Projects", "NETWORK_PROJECT_TEMPLATE.md")
        assert kind_spec("inbox") == ("00-Inbox", None)

    def test_unknown_kind_lists_valid_kinds(self) -> None:
        with pytest.raises(VaultError) as exc:
            kind_spec("diary")
        msg = str(exc.value)
        assert "diary" in msg
        for kind in ("runbook", "incident", "knowledge", "project", "inbox"):
            assert kind in msg


class TestRequiredSections:
    def test_incident_sections_are_h2_only(self, vault: Vault) -> None:
        sections = required_sections(vault, "incident")
        assert sections == [
            "Summary",
            "Start Time",
            "End Time",
            "Impact",
            "Root Cause",
            "Timeline",
            "Systems Impacted",
            "Resolution",
            "Lessons Learned",
            "Prevention Actions",
            "Related",
        ]

    def test_runbook_excludes_h3(self, vault: Vault) -> None:
        sections = required_sections(vault, "runbook")
        assert "User Impact" not in sections  # H3 in template
        assert "Impact" in sections

    def test_inbox_has_no_required_sections(self, vault: Vault) -> None:
        assert required_sections(vault, "inbox") == []

    def test_template_text_for_inbox_is_none(self, vault: Vault) -> None:
        assert template_text(vault, "inbox") is None


class TestMissingSections:
    def test_all_present_any_order_any_level(self) -> None:
        content = "### related\n\n## Summary\n\nx\n"
        assert missing_sections(content, ["Summary", "Related"]) == []

    def test_reports_missing_in_template_order(self) -> None:
        assert missing_sections("## Summary\n", ["Summary", "Impact", "Related"]) == [
            "Impact",
            "Related",
        ]


class TestSanitize:
    def test_strips_forbidden_chars(self) -> None:
        assert sanitize_component('a<b>c:d"e\\f|g?h*i') == "abcdefghi"

    def test_strips_control_chars_and_edge_dots_spaces(self) -> None:
        assert sanitize_component(" .name.\x07 ") == "name"


class TestNoteRelPath:
    def test_flat_kind(self) -> None:
        assert note_rel_path("runbook", "BGP Neighbor Down") == ("06-Runbooks/BGP Neighbor Down.md")

    def test_flat_kind_strips_slashes(self) -> None:
        assert note_rel_path("incident", "2026/06/10 outage") == ("07-Incidents/20260610 outage.md")

    def test_project_kind_allows_subfolders(self) -> None:
        assert note_rel_path("project", "AI Platform/Milestone M1") == (
            "02-Projects/AI Platform/Milestone M1.md"
        )

    def test_empty_after_sanitization_raises(self) -> None:
        with pytest.raises(VaultError, match="empty"):
            note_rel_path("runbook", "???")


class TestCreateNote:
    VALID_INCIDENT = "\n".join(
        f"## {s}\n\nN/A\n"
        for s in [
            "Summary",
            "Start Time",
            "End Time",
            "Impact",
            "Root Cause",
            "Timeline",
            "Systems Impacted",
            "Resolution",
            "Lessons Learned",
            "Prevention Actions",
            "Related",
        ]
    )

    def test_creates_valid_incident_with_frontmatter_and_h1(self, vault: Vault) -> None:
        rel = create_note(vault, "incident", "2026-06-10 BGP outage", self.VALID_INCIDENT)
        assert rel == "07-Incidents/2026-06-10 BGP outage.md"
        note = vault.read_note(rel)
        assert note.frontmatter["source"] == "claude-code"
        assert note.frontmatter["kind"] == "incident"
        assert note.frontmatter["tags"] == []
        assert note.body.startswith("# 2026-06-10 BGP outage")

    def test_tags_land_in_frontmatter(self, vault: Vault) -> None:
        rel = create_note(
            vault, "incident", "Tagged incident", self.VALID_INCIDENT, tags=["bgp", "p1"]
        )
        assert vault.read_note(rel).frontmatter["tags"] == ["bgp", "p1"]

    def test_missing_sections_rejected_with_names(self, vault: Vault) -> None:
        with pytest.raises(VaultError) as exc:
            create_note(vault, "incident", "Bad", "## Summary\n\nonly this\n")
        msg = str(exc.value)
        assert "Start Time" in msg and "Related" in msg
        assert "get_template" in msg

    def test_inbox_is_free_form(self, vault: Vault) -> None:
        rel = create_note(vault, "inbox", "Random thought", "anything goes")
        assert rel == "00-Inbox/Random thought.md"

    def test_collision_rejected(self, vault: Vault) -> None:
        create_note(vault, "inbox", "Once", "x")
        with pytest.raises(VaultError, match="already exists"):
            create_note(vault, "inbox", "Once", "y")

    def test_project_h1_is_last_component(self, vault: Vault) -> None:
        content = "\n".join(
            f"## {s}\n\nN/A\n"
            for s in [
                "Executive Summary",
                "Business Objective",
                "Current State",
                "Desired State",
                "Scope",
                "Requirements",
                "Assumptions",
                "Constraints",
                "Dependencies",
                "Architecture Overview",
                "Vendor Technologies",
                "Risks",
                "Implementation Plan",
                "Validation Plan",
                "Rollback Plan",
                "Lessons Learned",
                "Related Notes",
            ]
        )
        rel = create_note(vault, "project", "AI Platform/Overview", content)
        assert rel == "02-Projects/AI Platform/Overview.md"
        assert vault.read_note(rel).body.startswith("# Overview")
