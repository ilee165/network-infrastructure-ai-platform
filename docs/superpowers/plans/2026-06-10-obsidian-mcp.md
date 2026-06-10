# Obsidian MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the vault-aware Obsidian MCP server specified in `docs/superpowers/specs/2026-06-10-obsidian-mcp-integration-design.md`, register it for this project, and migrate the build mission state into the vault.

**Architecture:** Standalone Python package at `tools/obsidian-mcp/` (outside `backend/`, own venv). Three logic modules (`vault.py` filesystem primitives + markdown helpers, `templates.py` kind/template rules, `search.py` ranking) with a thin FastMCP stdio layer (`server.py`). All writes are taxonomy/template-validated; no delete, no overwrite.

**Tech Stack:** Python ≥3.11 (3.14 installed locally), `mcp` SDK (FastMCP), `pyyaml`; dev: `pytest`, `pytest-asyncio`, `ruff`, `mypy`, `types-PyYAML`.

**Environment notes for the engineer:**
- Windows. Run commands from PowerShell. Repo root: `D:\Multi-Agent workflow\network-infrastructure-ai-platform`.
- The tool's venv python is `tools\obsidian-mcp\.venv\Scripts\python.exe` (created in Task 1). Run pytest from `tools/obsidian-mcp/`.
- The real vault is `D:\Brains\Network-brain\Network-infra-projects` — tests NEVER touch it; they use a tmp fixture vault. Only Task 9 (migration) writes to the real vault.
- Commit after every task. Commit messages end with: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

---

## File structure

```
.mcp.json                                    # NEW (repo root) — registers the server
tools/obsidian-mcp/
├── pyproject.toml                           # package metadata, deps, ruff/mypy/pytest config
├── README.md                                # setup, tool reference, registration
├── src/obsidian_mcp/
│   ├── __init__.py                          # version marker only
│   ├── __main__.py                          # python -m obsidian_mcp → main()
│   ├── server.py                            # FastMCP tool definitions (thin) + main()
│   ├── vault.py                             # Vault class, frontmatter, heading utils, append_to_section
│   ├── templates.py                         # KINDS map, section rules, sanitization, create_note
│   └── search.py                            # search + snippet extraction
├── scripts/
│   └── migrate_hub.py                       # one-time execution-hub migration (Task 9)
└── tests/
    ├── conftest.py                          # tmp mini-vault fixture (faithful template copies)
    ├── test_vault.py
    ├── test_templates.py
    ├── test_search.py
    └── test_server.py                       # FastMCP wiring (async list_tools/call_tool)
```

Responsibilities: `vault.py` owns path safety and raw markdown mechanics; `templates.py` owns "what is a valid note of kind X and where does it live"; `search.py` owns ranking/snippets; `server.py` owns only MCP plumbing and error-to-message conversion.

---

### Task 1: Package scaffold + venv

**Files:**
- Create: `tools/obsidian-mcp/pyproject.toml`
- Create: `tools/obsidian-mcp/src/obsidian_mcp/__init__.py`
- Create: `tools/obsidian-mcp/src/obsidian_mcp/__main__.py`
- Create: `tools/obsidian-mcp/README.md` (stub; finished in Task 8)

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "obsidian-mcp"
version = "0.1.0"
description = "Vault-aware Obsidian MCP server for the AI NetOps Platform build workflow"
requires-python = ">=3.11"
dependencies = [
    "mcp",
    "pyyaml",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "pytest-asyncio",
    "ruff",
    "mypy",
    "types-PyYAML",
]

[tool.hatch.build.targets.wheel]
packages = ["src/obsidian_mcp"]

[tool.ruff]
line-length = 100
target-version = "py311"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.12"
mypy_path = "src"
packages = ["obsidian_mcp"]
check_untyped_defs = true
no_implicit_optional = true

[[tool.mypy.overrides]]
module = ["mcp.*"]
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 2: Write `src/obsidian_mcp/__init__.py`**

```python
"""Vault-aware Obsidian MCP server (dev-workflow tooling, not a platform feature)."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Write `src/obsidian_mcp/__main__.py`**

```python
"""Entry point: python -m obsidian_mcp."""

from obsidian_mcp.server import main

main()
```

(`server.py` does not exist yet — that is fine; `__main__` is only executed in Task 8.)

- [ ] **Step 4: Write `README.md` stub**

```markdown
# obsidian-mcp

Vault-aware MCP server exposing the Obsidian vault to Claude Code agents.
See `docs/superpowers/specs/2026-06-10-obsidian-mcp-integration-design.md`.

Setup and tool reference: completed in a later task.
```

- [ ] **Step 5: Create venv and install editable**

Run (from repo root):
```powershell
python -m venv "tools\obsidian-mcp\.venv"
& "tools\obsidian-mcp\.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& "tools\obsidian-mcp\.venv\Scripts\python.exe" -m pip install --quiet -e "tools/obsidian-mcp[dev]"
& "tools\obsidian-mcp\.venv\Scripts\python.exe" -c "import mcp, yaml, obsidian_mcp; print('imports OK', obsidian_mcp.__version__)"
```
Expected: `imports OK 0.1.0`

- [ ] **Step 6: Verify the venv is git-ignored**

Run: `git status --short`
Expected: only the new `tools/obsidian-mcp/` source files appear; NOTHING under `tools/obsidian-mcp/.venv/`. If `.venv` files appear, add `**/.venv/` to the root `.gitignore` in this commit.

- [ ] **Step 7: Commit**

```powershell
git add tools/obsidian-mcp .gitignore
git commit -m "obsidian-mcp: package scaffold and venv setup"
```
(If `.gitignore` was untouched, drop it from the `git add`.)

---

### Task 2: Vault primitives — path safety, frontmatter, read, write-new, list

**Files:**
- Create: `tools/obsidian-mcp/tests/conftest.py`
- Create: `tools/obsidian-mcp/tests/test_vault.py`
- Create: `tools/obsidian-mcp/src/obsidian_mcp/vault.py`

- [ ] **Step 1: Write the fixture (`tests/conftest.py`)**

The fixture builds a miniature vault with the real taxonomy and **faithful copies of the four real templates' heading structure** (all real H2s; bodies abbreviated; H3s included where the real templates have them so the "H2-only" rule is tested).

```python
"""Shared fixture: a tmp mini-vault mirroring D:\\Brains\\Network-brain\\Network-infra-projects."""

from pathlib import Path

import pytest

from obsidian_mcp.vault import Vault

FOLDERS = [
    "00-Inbox", "01-Dashboard", "02-Projects", "03-Architecture", "04-Knowledge",
    "05-Vendors", "06-Runbooks", "07-Incidents", "08-Labs", "09-Reference",
    "10-Templates", "Assets", ".obsidian",
]

RUNBOOK_TEMPLATE = """# {{Runbook Name}}

## Summary

## Symptoms

## Impact

### User Impact

### Service Impact

## Scope

### Affected Systems

## Verification Steps

## Diagnostic Commands

### Cisco

## Expected Results

## Common Root Causes

## Troubleshooting Workflow

## Remediation Steps

## Validation

## Escalation Criteria

## References
"""

INCIDENT_TEMPLATE = """# Incident {{ID}}

## Summary

## Start Time

## End Time

## Impact

## Root Cause

## Timeline

## Systems Impacted

## Resolution

## Lessons Learned

## Prevention Actions

## Related
"""

KNOWLEDGE_TEMPLATE = """# {{Technology Name}}

## Definition

## Purpose

## Business Use Cases

## How It Works

## Key Components

## Architecture

### Logical Flow

## Design Considerations

## Advantages

## Disadvantages

## Common Failure Scenarios

## Troubleshooting

## Vendor Implementations

### Cisco

## Automation Opportunities

## Best Practices

## Related Technologies

## References
"""

PROJECT_TEMPLATE = """# {{Project Name}}

## Executive Summary

## Business Objective

## Current State

## Desired State

### Success Criteria

## Scope

### In Scope

### Out of Scope

## Requirements

## Assumptions

## Constraints

## Dependencies

## Architecture Overview

## Vendor Technologies

## Risks

## Implementation Plan

## Validation Plan

## Rollback Plan

## Lessons Learned

## Related Notes
"""

TEMPLATES = {
    "RUNBOOK_TEMPLATE.md": RUNBOOK_TEMPLATE,
    "NETWORK_INCIDENT_TEMPLATE.md": INCIDENT_TEMPLATE,
    "KNOWLEDGE_ARTICLE_TEMPLATE.md": KNOWLEDGE_TEMPLATE,
    "NETWORK_PROJECT_TEMPLATE.md": PROJECT_TEMPLATE,
}

BGP_NOTE = """---
created: 2026-01-15
tags: [routing]
---

# BGP

## Definition

Border Gateway Protocol is the path-vector routing protocol of the internet.

## Troubleshooting

Check neighbor state with show ip bgp summary. Flapping peers often mean MTU issues.
"""

OSPF_NOTE = """# OSPF

## Definition

Open Shortest Path First is a link-state IGP.

Mentions BGP redistribution exactly once: BGP.
"""


@pytest.fixture()
def vault_root(tmp_path: Path) -> Path:
    for folder in FOLDERS:
        (tmp_path / folder).mkdir()
    for name, text in TEMPLATES.items():
        (tmp_path / "10-Templates" / name).write_text(text, encoding="utf-8")
    (tmp_path / "04-Knowledge" / "BGP.md").write_text(BGP_NOTE, encoding="utf-8")
    (tmp_path / "04-Knowledge" / "OSPF.md").write_text(OSPF_NOTE, encoding="utf-8")
    (tmp_path / ".obsidian" / "hidden.md").write_text("# Hidden", encoding="utf-8")
    (tmp_path / "Assets" / "asset-note.md").write_text("# Asset", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def vault(vault_root: Path) -> Vault:
    return Vault(vault_root)
```

- [ ] **Step 2: Write the failing tests (`tests/test_vault.py`)**

```python
"""Vault primitives: construction, path safety, frontmatter, read/write/list."""

from pathlib import Path

import pytest

from obsidian_mcp.vault import Vault, VaultError, split_frontmatter


class TestConstruction:
    def test_rejects_missing_root(self, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="does not exist"):
            Vault(tmp_path / "nope")

    def test_rejects_root_without_templates_folder(self, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="10-Templates"):
            Vault(tmp_path)


class TestPathSafety:
    def test_resolves_inside_vault(self, vault: Vault) -> None:
        assert vault.resolve("04-Knowledge/BGP.md").is_file()

    def test_rejects_traversal(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="escapes the vault"):
            vault.resolve("../outside.md")

    def test_rejects_absolute_path(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="escapes the vault"):
            vault.resolve("C:/Windows/win.ini")


class TestFrontmatter:
    def test_parses_frontmatter_and_body(self) -> None:
        fm, body = split_frontmatter("---\ntags: [a]\n---\n# Hi\n")
        assert fm == {"tags": ["a"]}
        assert body == "# Hi\n"

    def test_no_frontmatter_returns_empty_mapping(self) -> None:
        fm, body = split_frontmatter("# Hi\n")
        assert fm == {}
        assert body == "# Hi\n"

    def test_unclosed_frontmatter_is_treated_as_body(self) -> None:
        fm, body = split_frontmatter("---\ntags: [a]\n# Hi\n")
        assert fm == {}
        assert body.startswith("---")


class TestReadNote:
    def test_reads_frontmatter_and_body(self, vault: Vault) -> None:
        note = vault.read_note("04-Knowledge/BGP.md")
        assert note.frontmatter["tags"] == ["routing"]
        assert "path-vector" in note.body

    def test_not_found_lists_folder_notes(self, vault: Vault) -> None:
        with pytest.raises(VaultError) as exc:
            vault.read_note("04-Knowledge/EIGRP.md")
        assert "BGP.md" in str(exc.value)
        assert "OSPF.md" in str(exc.value)


class TestWriteNew:
    def test_creates_file_and_parents(self, vault: Vault) -> None:
        rel = vault.write_new("02-Projects/Sub/New.md", "# New\n")
        assert rel == "02-Projects/Sub/New.md"
        assert vault.resolve(rel).read_text(encoding="utf-8") == "# New\n"

    def test_rejects_existing(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="already exists"):
            vault.write_new("04-Knowledge/BGP.md", "x")


class TestSaveExisting:
    def test_rewrites_existing(self, vault: Vault) -> None:
        vault.save_existing("04-Knowledge/OSPF.md", "# OSPF\n\nnew body\n")
        assert "new body" in vault.read_note("04-Knowledge/OSPF.md").body

    def test_rejects_missing(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="not found"):
            vault.save_existing("04-Knowledge/EIGRP.md", "x")


class TestListMd:
    def test_excludes_dot_dirs_and_assets(self, vault: Vault) -> None:
        rels = [vault.rel(p) for p in vault.list_md()]
        assert "04-Knowledge/BGP.md" in rels
        assert not any(r.startswith(".obsidian") for r in rels)
        assert not any(r.startswith("Assets") for r in rels)

    def test_folder_filter(self, vault: Vault) -> None:
        rels = [vault.rel(p) for p in vault.list_md("04-Knowledge")]
        assert rels == ["04-Knowledge/BGP.md", "04-Knowledge/OSPF.md"]

    def test_unknown_folder_raises(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="not a folder"):
            vault.list_md("99-Nope")
```

- [ ] **Step 3: Run tests to verify they fail**

Run (from `tools/obsidian-mcp/`):
```powershell
& ".\.venv\Scripts\python.exe" -m pytest tests/test_vault.py -q
```
Expected: collection error — `ModuleNotFoundError: No module named 'obsidian_mcp.vault'`

- [ ] **Step 4: Write `src/obsidian_mcp/vault.py`**

```python
"""Filesystem primitives for safe vault access plus markdown helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

#: Directories never scanned (in addition to any directory starting with ".").
EXCLUDED_DIRS = {"Assets"}


class VaultError(Exception):
    """Vault access failure; the message is surfaced to the calling agent."""


@dataclass(frozen=True)
class Note:
    path: str
    frontmatter: dict[str, Any]
    body: str


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split leading YAML frontmatter from *text*; tolerant of malformed YAML."""
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            try:
                parsed = yaml.safe_load(text[4:end])
            except yaml.YAMLError:
                parsed = None
            if isinstance(parsed, dict):
                return parsed, text[end + 5 :]
    return {}, text


def heading_text(line: str) -> str | None:
    """Return the heading text of a markdown heading line, else None."""
    stripped = line.strip()
    if not stripped.startswith("#"):
        return None
    level = len(stripped) - len(stripped.lstrip("#"))
    if level > 6 or len(stripped) == level or stripped[level] not in (" ", "\t"):
        return None
    return stripped[level:].strip()


def heading_level(line: str) -> int:
    """Heading level of *line* (assumes heading_text(line) is not None)."""
    stripped = line.strip()
    return len(stripped) - len(stripped.lstrip("#"))


def append_to_section(text: str, section: str, content: str) -> str:
    """Append *content* at the end of the named section. Frontmatter is preserved.

    The section heading match is case-insensitive on the heading text, any level.
    Raises VaultError (listing actual headings) when the section is absent.
    """
    prefix = ""
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            prefix, text = text[: end + 5], text[end + 5 :]

    lines = text.splitlines()
    target = section.strip().lower()
    start: int | None = None
    level = 0
    for i, line in enumerate(lines):
        t = heading_text(line)
        if t is not None and t.lower() == target:
            start, level = i, heading_level(line)
            break
    if start is None:
        headings = [t for line in lines if (t := heading_text(line)) is not None]
        raise VaultError(f"Section not found: {section!r}. Headings in note: {headings}")

    section_end = len(lines)
    for j in range(start + 1, len(lines)):
        t = heading_text(lines[j])
        if t is not None and heading_level(lines[j]) <= level:
            section_end = j
            break

    before = lines[:section_end]
    while before and before[-1].strip() == "":
        before.pop()
    after = lines[section_end:]
    block = content.rstrip("\n").splitlines()
    new_lines = before + [""] + block
    if after:
        new_lines += [""] + after
    return prefix + "\n".join(new_lines) + "\n"


class Vault:
    """Safe accessor for one Obsidian vault directory."""

    def __init__(self, root: Path) -> None:
        resolved = root.resolve()
        if not resolved.is_dir():
            raise VaultError(f"Vault root does not exist: {resolved}")
        if not (resolved / "10-Templates").is_dir():
            raise VaultError(f"Not an expected vault (missing 10-Templates/): {resolved}")
        self.root = resolved

    def resolve(self, rel_path: str) -> Path:
        candidate = (self.root / rel_path).resolve()
        if candidate != self.root and not candidate.is_relative_to(self.root):
            raise VaultError(f"Path escapes the vault: {rel_path}")
        return candidate

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def read_note(self, rel_path: str) -> Note:
        target = self.resolve(rel_path)
        if not target.is_file():
            folder = target.parent
            names: list[str] = []
            if folder.is_dir():
                names = sorted(p.name for p in folder.glob("*.md"))
            raise VaultError(
                f"Note not found: {rel_path}. "
                f"Markdown files in that folder: {names if names else 'none'}"
            )
        fm, body = split_frontmatter(target.read_text(encoding="utf-8"))
        return Note(self.rel(target), fm, body)

    def write_new(self, rel_path: str, text: str) -> str:
        target = self.resolve(rel_path)
        if target.exists():
            raise VaultError(f"Note already exists: {rel_path} (overwrites are not allowed)")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return self.rel(target)

    def save_existing(self, rel_path: str, text: str) -> None:
        target = self.resolve(rel_path)
        if not target.is_file():
            raise VaultError(f"Note not found: {rel_path}")
        target.write_text(text, encoding="utf-8")

    def list_md(self, folder: str | None = None) -> list[Path]:
        base = self.resolve(folder) if folder else self.root
        if not base.is_dir():
            raise VaultError(f"'{folder}' is not a folder in the vault")
        results: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if not d.startswith(".") and d not in EXCLUDED_DIRS
            )
            for name in sorted(filenames):
                if name.endswith(".md"):
                    results.append(Path(dirpath) / name)
        return results
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_vault.py -q`
Expected: all pass (note: `append_to_section` is tested in Task 3).

- [ ] **Step 6: Commit**

```powershell
git add tools/obsidian-mcp/tests tools/obsidian-mcp/src/obsidian_mcp/vault.py
git commit -m "obsidian-mcp: vault primitives - path safety, frontmatter, read/write/list"
```

---

### Task 3: append_to_section behavior

**Files:**
- Modify: `tools/obsidian-mcp/tests/test_vault.py` (append a class at the end)
- (Implementation already landed in Task 2's `vault.py`; this task locks behavior with tests and fixes anything the tests expose.)

- [ ] **Step 1: Append the failing/locking tests to `tests/test_vault.py`**

```python
class TestAppendToSection:
    NOTE = """---
created: 2026-06-10
---

# Log

## Iterations

- iteration 1

## Decisions

- D1
"""

    def test_appends_to_middle_section_before_next_heading(self) -> None:
        from obsidian_mcp.vault import append_to_section

        out = append_to_section(self.NOTE, "Iterations", "- iteration 2")
        body = out.split("## Decisions")[0]
        assert "- iteration 1" in body
        assert "- iteration 2" in body
        assert out.index("- iteration 2") > out.index("- iteration 1")
        assert out.index("- iteration 2") < out.index("## Decisions")

    def test_appends_to_last_section_at_eof(self) -> None:
        from obsidian_mcp.vault import append_to_section

        out = append_to_section(self.NOTE, "Decisions", "- D2")
        assert out.rstrip().endswith("- D2")

    def test_match_is_case_insensitive(self) -> None:
        from obsidian_mcp.vault import append_to_section

        out = append_to_section(self.NOTE, "iterations", "- x")
        assert "- x" in out

    def test_frontmatter_is_preserved_and_never_matched(self) -> None:
        from obsidian_mcp.vault import append_to_section

        out = append_to_section(self.NOTE, "Iterations", "- y")
        assert out.startswith("---\ncreated: 2026-06-10\n---\n")

    def test_unknown_section_lists_headings(self) -> None:
        from obsidian_mcp.vault import VaultError, append_to_section
        import pytest

        with pytest.raises(VaultError) as exc:
            append_to_section(self.NOTE, "Nope", "- z")
        msg = str(exc.value)
        assert "Log" in msg and "Iterations" in msg and "Decisions" in msg
```

- [ ] **Step 2: Run the new tests**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_vault.py::TestAppendToSection -q`
Expected: PASS (the Task 2 implementation already covers this). If any fail, fix `append_to_section` in `vault.py` until green — the tests are the contract, do not weaken them.

- [ ] **Step 3: Commit**

```powershell
git add tools/obsidian-mcp/tests/test_vault.py tools/obsidian-mcp/src/obsidian_mcp/vault.py
git commit -m "obsidian-mcp: lock append_to_section contract with tests"
```

---

### Task 4: templates.py — kinds, required sections, sanitization, paths

**Files:**
- Create: `tools/obsidian-mcp/tests/test_templates.py`
- Create: `tools/obsidian-mcp/src/obsidian_mcp/templates.py`

- [ ] **Step 1: Write the failing tests (`tests/test_templates.py`)**

```python
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
            "Summary", "Start Time", "End Time", "Impact", "Root Cause", "Timeline",
            "Systems Impacted", "Resolution", "Lessons Learned", "Prevention Actions",
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
        assert note_rel_path("runbook", "BGP Neighbor Down") == (
            "06-Runbooks/BGP Neighbor Down.md"
        )

    def test_flat_kind_strips_slashes(self) -> None:
        assert note_rel_path("incident", "2026/06/10 outage") == (
            "07-Incidents/20260610 outage.md"
        )

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
            "Summary", "Start Time", "End Time", "Impact", "Root Cause", "Timeline",
            "Systems Impacted", "Resolution", "Lessons Learned", "Prevention Actions",
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
                "Executive Summary", "Business Objective", "Current State", "Desired State",
                "Scope", "Requirements", "Assumptions", "Constraints", "Dependencies",
                "Architecture Overview", "Vendor Technologies", "Risks",
                "Implementation Plan", "Validation Plan", "Rollback Plan",
                "Lessons Learned", "Related Notes",
            ]
        )
        rel = create_note(vault, "project", "AI Platform/Overview", content)
        assert rel == "02-Projects/AI Platform/Overview.md"
        assert vault.read_note(rel).body.startswith("# Overview")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_templates.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'obsidian_mcp.templates'`

- [ ] **Step 3: Write `src/obsidian_mcp/templates.py`**

```python
"""Kind/template rules: where notes live and what sections they must contain."""

from __future__ import annotations

from datetime import date

import yaml

from obsidian_mcp.vault import Vault, VaultError, heading_text

#: kind -> (vault folder, template filename in 10-Templates, or None for free-form)
KINDS: dict[str, tuple[str, str | None]] = {
    "runbook": ("06-Runbooks", "RUNBOOK_TEMPLATE.md"),
    "incident": ("07-Incidents", "NETWORK_INCIDENT_TEMPLATE.md"),
    "knowledge": ("04-Knowledge", "KNOWLEDGE_ARTICLE_TEMPLATE.md"),
    "project": ("02-Projects", "NETWORK_PROJECT_TEMPLATE.md"),
    "inbox": ("00-Inbox", None),
}

_FORBIDDEN_CHARS = '<>:"\\|?*'


def kind_spec(kind: str) -> tuple[str, str | None]:
    try:
        return KINDS[kind]
    except KeyError:
        raise VaultError(f"Unknown kind: {kind!r}. Valid kinds: {sorted(KINDS)}") from None


def template_text(vault: Vault, kind: str) -> str | None:
    _, template = kind_spec(kind)
    if template is None:
        return None
    return vault.resolve(f"10-Templates/{template}").read_text(encoding="utf-8")


def required_sections(vault: Vault, kind: str) -> list[str]:
    text = template_text(vault, kind)
    if text is None:
        return []
    return [line[3:].strip() for line in text.splitlines() if line.startswith("## ")]


def missing_sections(content: str, required: list[str]) -> list[str]:
    have = {
        t.lower() for line in content.splitlines() if (t := heading_text(line)) is not None
    }
    return [s for s in required if s.lower() not in have]


def sanitize_component(name: str) -> str:
    cleaned = "".join(c for c in name if c not in _FORBIDDEN_CHARS and ord(c) >= 32)
    return cleaned.strip(" .")


def note_rel_path(kind: str, title: str) -> str:
    folder, _ = kind_spec(kind)
    if kind == "project":
        parts = [sanitize_component(p) for p in title.split("/")]
        parts = [p for p in parts if p]
    else:
        parts = [sanitize_component(title.replace("/", ""))]
        parts = [p for p in parts if p]
    if not parts:
        raise VaultError(f"Title is empty after sanitization: {title!r}")
    return f"{folder}/" + "/".join(parts) + ".md"


def build_note_text(kind: str, title: str, content: str, tags: list[str] | None) -> str:
    frontmatter = {
        "created": date.today().isoformat(),
        "source": "claude-code",
        "kind": kind,
        "tags": list(tags or []),
    }
    header = "---\n" + yaml.safe_dump(frontmatter, sort_keys=False).strip() + "\n---\n\n"
    h1 = title.split("/")[-1].strip() if kind == "project" else title.strip()
    return header + f"# {h1}\n\n" + content.rstrip("\n") + "\n"


def create_note(
    vault: Vault, kind: str, title: str, content: str, tags: list[str] | None = None
) -> str:
    required = required_sections(vault, kind)
    missing = missing_sections(content, required)
    if missing:
        raise VaultError(
            f"Content is missing required sections for kind '{kind}': {missing}. "
            f"Call get_template('{kind}') to see the expected structure."
        )
    rel = note_rel_path(kind, title)
    return vault.write_new(rel, build_note_text(kind, title, content, tags))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_templates.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```powershell
git add tools/obsidian-mcp/tests/test_templates.py tools/obsidian-mcp/src/obsidian_mcp/templates.py
git commit -m "obsidian-mcp: kind/template rules with section validation and safe paths"
```

---

### Task 5: search.py — AND-token ranking with snippets

**Files:**
- Create: `tools/obsidian-mcp/tests/test_search.py`
- Create: `tools/obsidian-mcp/src/obsidian_mcp/search.py`

- [ ] **Step 1: Write the failing tests (`tests/test_search.py`)**

```python
"""Search: AND semantics, weighted ranking, folder filter, snippets, exclusions."""

import pytest

from obsidian_mcp.search import search
from obsidian_mcp.vault import Vault, VaultError


class TestSearch:
    def test_and_semantics_requires_all_tokens(self, vault: Vault) -> None:
        # "path-vector" appears only in BGP.md; "link-state" only in OSPF.md
        assert search(vault, "path-vector link-state") == []

    def test_title_hits_outrank_body_hits(self, vault: Vault) -> None:
        # BGP.md has "BGP" in its title; OSPF.md mentions BGP only in the body.
        hits = search(vault, "bgp")
        assert [h.path for h in hits][:2] == ["04-Knowledge/BGP.md", "04-Knowledge/OSPF.md"]
        assert hits[0].score > hits[1].score

    def test_folder_filter(self, vault: Vault) -> None:
        assert search(vault, "bgp", folder="06-Runbooks") == []

    def test_excluded_dirs_never_match(self, vault: Vault) -> None:
        assert search(vault, "hidden") == []
        assert search(vault, "asset") == []

    def test_snippets_contain_match_context_not_whole_file(self, vault: Vault) -> None:
        hits = search(vault, "flapping")
        assert len(hits) == 1
        assert any("MTU" in s for s in hits[0].snippets)
        assert all(len(s) < 400 for s in hits[0].snippets)

    def test_limit(self, vault: Vault) -> None:
        assert len(search(vault, "definition", limit=1)) == 1

    def test_empty_query_raises(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="Empty query"):
            search(vault, "   ")

    def test_title_falls_back_to_filename(self, vault: Vault) -> None:
        (vault.root / "00-Inbox" / "no-heading.md").write_text("plain text", encoding="utf-8")
        hits = search(vault, "plain")
        assert hits[0].title == "no-heading"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_search.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'obsidian_mcp.search'`

- [ ] **Step 3: Write `src/obsidian_mcp/search.py`**

```python
"""Token search over the vault: AND semantics, weighted ranking, short snippets."""

from __future__ import annotations

from dataclasses import dataclass

from obsidian_mcp.vault import Vault, VaultError, heading_text

_TITLE_WEIGHT = 3
_HEADING_WEIGHT = 2
_MAX_SNIPPETS = 3


@dataclass(frozen=True)
class SearchHit:
    path: str
    title: str
    score: int
    snippets: list[str]


def _extract_snippets(lines: list[str], tokens: list[str]) -> list[str]:
    snippets: list[str] = []
    used: set[int] = set()
    for i, line in enumerate(lines):
        lowered = line.lower()
        if any(t in lowered for t in tokens):
            lo, hi = max(0, i - 1), min(len(lines), i + 2)
            if any(j in used for j in range(lo, hi)):
                continue
            used.update(range(lo, hi))
            snippets.append("\n".join(lines[lo:hi]).strip())
            if len(snippets) == _MAX_SNIPPETS:
                break
    return snippets


def search(
    vault: Vault, query: str, folder: str | None = None, limit: int = 10
) -> list[SearchHit]:
    tokens = [t for t in query.lower().split() if t]
    if not tokens:
        raise VaultError("Empty query")

    scored: list[tuple[int, float, SearchHit]] = []
    for path in vault.list_md(folder):
        text = path.read_text(encoding="utf-8")
        if not all(t in text.lower() for t in tokens):
            continue
        lines = text.splitlines()
        title = path.stem
        for line in lines:
            if line.startswith("# "):
                title = line[2:].strip()
                break
        heading_lines = "\n".join(line for line in lines if heading_text(line) is not None)
        body_lines = "\n".join(line for line in lines if heading_text(line) is None)
        title_l, headings_l, body_l = title.lower(), heading_lines.lower(), body_lines.lower()
        score = sum(
            _TITLE_WEIGHT * title_l.count(t)
            + _HEADING_WEIGHT * headings_l.count(t)
            + body_l.count(t)
            for t in tokens
        )
        hit = SearchHit(vault.rel(path), title, score, _extract_snippets(lines, tokens))
        scored.append((score, path.stat().st_mtime, hit))

    scored.sort(key=lambda item: (-item[0], -item[1]))
    return [hit for _, _, hit in scored[:limit]]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_search.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```powershell
git add tools/obsidian-mcp/tests/test_search.py tools/obsidian-mcp/src/obsidian_mcp/search.py
git commit -m "obsidian-mcp: AND-token search with weighted ranking and snippets"
```

---

### Task 6: server.py — FastMCP wiring + main()

**Files:**
- Create: `tools/obsidian-mcp/tests/test_server.py`
- Create: `tools/obsidian-mcp/src/obsidian_mcp/server.py`

- [ ] **Step 1: Write the failing tests (`tests/test_server.py`)**

```python
"""FastMCP wiring: six tools registered; calls round-trip through the vault."""

import pytest

from obsidian_mcp.server import create_server
from obsidian_mcp.vault import Vault

EXPECTED_TOOLS = {
    "search_notes",
    "read_note",
    "list_notes",
    "get_template",
    "create_note",
    "append_note",
}


@pytest.fixture()
def server(vault: Vault):
    return create_server(vault)


async def test_six_tools_registered(server) -> None:
    tools = await server.list_tools()
    assert {t.name for t in tools} == EXPECTED_TOOLS


async def test_read_note_roundtrip(server) -> None:
    result = await server.call_tool("read_note", {"path": "04-Knowledge/BGP.md"})
    assert "path-vector" in str(result)


async def test_search_notes_roundtrip(server) -> None:
    result = await server.call_tool("search_notes", {"query": "flapping"})
    assert "BGP.md" in str(result)


async def test_create_then_append_roundtrip(server, vault: Vault) -> None:
    await server.call_tool(
        "create_note",
        {"kind": "inbox", "title": "Hub Test", "content": "## Log\n\n- first\n"},
    )
    await server.call_tool(
        "append_note",
        {"path": "00-Inbox/Hub Test.md", "section": "Log", "content": "- second"},
    )
    note = vault.read_note("00-Inbox/Hub Test.md")
    assert "- first" in note.body and "- second" in note.body


async def test_get_template_lists_required_sections(server) -> None:
    result = await server.call_tool("get_template", {"kind": "incident"})
    text = str(result)
    assert "Root Cause" in text and "Prevention Actions" in text


async def test_error_surfaces_message(server) -> None:
    with pytest.raises(Exception, match="Unknown kind"):
        await server.call_tool(
            "create_note", {"kind": "diary", "title": "x", "content": "y"}
        )
```

Note: `call_tool` error behavior differs across `mcp` SDK versions — some raise, some return error content. If `test_error_surfaces_message` fails because no exception is raised, replace it with:

```python
async def test_error_surfaces_message(server) -> None:
    result = await server.call_tool(
        "create_note", {"kind": "diary", "title": "x", "content": "y"}
    )
    assert "Unknown kind" in str(result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_server.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'obsidian_mcp.server'`

- [ ] **Step 3: Write `src/obsidian_mcp/server.py`**

```python
"""FastMCP stdio server exposing the vault-aware tool surface."""

from __future__ import annotations

import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from obsidian_mcp import templates
from obsidian_mcp.search import search as search_impl
from obsidian_mcp.vault import Vault, VaultError, append_to_section


def create_server(vault: Vault) -> FastMCP:
    mcp = FastMCP("obsidian")

    @mcp.tool()
    def search_notes(query: str, folder: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        """Search vault notes (AND across whitespace-split tokens; case-insensitive).

        Returns ranked hits: path, title, score, up to 3 short snippets. Title hits
        rank above heading hits above body hits. Never returns full note bodies —
        follow up with read_note(path) for the one you need. Optional folder
        restricts to one top-level vault folder (e.g. "06-Runbooks").
        """
        return [asdict(hit) for hit in search_impl(vault, query, folder, limit)]

    @mcp.tool()
    def read_note(path: str) -> dict[str, Any]:
        """Read one note by vault-relative path (e.g. "04-Knowledge/BGP.md").

        Returns its parsed YAML frontmatter and full markdown body.
        """
        note = vault.read_note(path)
        return {"path": note.path, "frontmatter": note.frontmatter, "body": note.body}

    @mcp.tool()
    def list_notes(folder: str | None = None) -> list[dict[str, str]]:
        """List markdown notes (path + title), optionally within one folder."""
        results = []
        for p in vault.list_md(folder):
            title = p.stem
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.startswith("# "):
                    title = line[2:].strip()
                    break
            results.append({"path": vault.rel(p), "title": title})
        return results

    @mcp.tool()
    def get_template(kind: str) -> dict[str, Any]:
        """Show the template and required H2 sections for a note kind.

        Kinds: runbook, incident, knowledge, project, inbox (inbox is free-form).
        Call this before create_note to see the structure your content must follow.
        """
        folder, _ = templates.kind_spec(kind)
        text = templates.template_text(vault, kind)
        return {
            "kind": kind,
            "folder": folder,
            "required_sections": templates.required_sections(vault, kind),
            "template": text if text is not None else "(free-form; no template)",
        }

    @mcp.tool()
    def create_note(
        kind: str, title: str, content: str, tags: list[str] | None = None
    ) -> str:
        """Create a new note of the given kind in its taxonomy folder.

        Content must contain every required H2 section of the kind's template
        (any order; empty/N-A bodies allowed) and starts at the first H2 — the
        server writes the H1 title and frontmatter. The "inbox" kind is free-form.
        For kind "project", "/" in the title creates subfolders. Never overwrites.
        """
        rel = templates.create_note(vault, kind, title, content, tags)
        return f"Created {rel}"

    @mcp.tool()
    def append_note(path: str, section: str, content: str) -> str:
        """Append content to the end of a named section of an existing note.

        Section matching is case-insensitive on heading text (any level). Only
        appends — never replaces existing lines.
        """
        vault.read_note(path)  # existence check with a helpful error
        raw = vault.resolve(path).read_text(encoding="utf-8")
        vault.save_existing(path, append_to_section(raw, section, content))
        return f"Appended to '{section}' in {path}"

    return mcp


def main() -> None:
    root = os.environ.get("OBSIDIAN_VAULT_ROOT")
    if not root:
        print("OBSIDIAN_VAULT_ROOT is not set", file=sys.stderr)
        raise SystemExit(1)
    try:
        vault = Vault(Path(root))
    except VaultError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    create_server(vault).run()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `& ".\.venv\Scripts\python.exe" -m pytest tests/test_server.py -q`
Expected: PASS (apply the documented `call_tool` error-behavior fallback if needed).

- [ ] **Step 5: Run the whole suite + lint + types**

```powershell
& ".\.venv\Scripts\python.exe" -m pytest -q
& ".\.venv\Scripts\ruff.exe" check .
& ".\.venv\Scripts\ruff.exe" format .
& ".\.venv\Scripts\python.exe" -m mypy
```
Expected: pytest all pass; ruff clean (commit any formatting changes); mypy no errors.

- [ ] **Step 6: Commit**

```powershell
git add tools/obsidian-mcp
git commit -m "obsidian-mcp: FastMCP server wiring with six vault tools"
```

---

### Task 7: Startup failure behavior (no vault, bad vault)

**Files:**
- Test: manual command checks (process-level behavior; not worth pytest harness)

- [ ] **Step 1: Verify missing env var exits 1 with message**

Run (from repo root):
```powershell
& "tools\obsidian-mcp\.venv\Scripts\python.exe" -m obsidian_mcp
$LASTEXITCODE
```
(with `OBSIDIAN_VAULT_ROOT` unset; if your shell session has it set, run `Remove-Item Env:OBSIDIAN_VAULT_ROOT` first.)
Expected: prints `OBSIDIAN_VAULT_ROOT is not set` to stderr; `$LASTEXITCODE` is `1`.

- [ ] **Step 2: Verify bad root exits 1 with message**

```powershell
$env:OBSIDIAN_VAULT_ROOT = "C:\definitely\not\here"
& "tools\obsidian-mcp\.venv\Scripts\python.exe" -m obsidian_mcp
$LASTEXITCODE
Remove-Item Env:OBSIDIAN_VAULT_ROOT
```
Expected: prints `Vault root does not exist: ...`; exit code `1`.

- [ ] **Step 3: Verify clean startup against the real vault (then kill it)**

```powershell
$env:OBSIDIAN_VAULT_ROOT = "D:\Brains\Network-brain\Network-infra-projects"
$p = Start-Process -FilePath "tools\obsidian-mcp\.venv\Scripts\python.exe" -ArgumentList "-m","obsidian_mcp" -PassThru -NoNewWindow
Start-Sleep -Seconds 3
$p.HasExited
Stop-Process -Id $p.Id -Force -Confirm:$false
Remove-Item Env:OBSIDIAN_VAULT_ROOT
```
Expected: `$p.HasExited` is `False` (server is up, waiting on stdio). No vault files are modified by startup.

No commit (no file changes).

---

### Task 8: Registration (.mcp.json) + README

**Files:**
- Create: `.mcp.json` (repo root)
- Modify: `tools/obsidian-mcp/README.md` (replace stub)

- [ ] **Step 1: Write `.mcp.json`**

```json
{
  "mcpServers": {
    "obsidian": {
      "command": "tools/obsidian-mcp/.venv/Scripts/python.exe",
      "args": ["-m", "obsidian_mcp"],
      "env": {
        "OBSIDIAN_VAULT_ROOT": "D:\\Brains\\Network-brain\\Network-infra-projects"
      }
    }
  }
}
```

- [ ] **Step 2: Replace `tools/obsidian-mcp/README.md`**

```markdown
# obsidian-mcp

Vault-aware MCP server exposing the user's Obsidian vault
(`D:\Brains\Network-brain\Network-infra-projects`) to Claude Code agents in this
project. Dev-workflow tooling only — NOT part of the NetOps platform product.
Design: `docs/superpowers/specs/2026-06-10-obsidian-mcp-integration-design.md`.

## Setup (one-time)

From the repo root:

```powershell
python -m venv "tools\obsidian-mcp\.venv"
& "tools\obsidian-mcp\.venv\Scripts\python.exe" -m pip install -e "tools/obsidian-mcp[dev]"
```

The server is registered in the repo-root `.mcp.json`; restart the Claude Code
session after first setup so the tools load.

## Tools

| Tool | Purpose |
| --- | --- |
| `search_notes(query, folder?, limit?)` | AND-token search; returns path/title/score + up to 3 snippets, never full bodies |
| `read_note(path)` | One note: parsed frontmatter + body |
| `list_notes(folder?)` | Note paths + titles |
| `get_template(kind)` | Template text + required H2 sections for a kind |
| `create_note(kind, title, content, tags?)` | Template-validated create into the kind's taxonomy folder; no overwrites |
| `append_note(path, section, content)` | Append to the end of a named section; never replaces lines |

Kinds: `runbook` → `06-Runbooks/`, `incident` → `07-Incidents/`,
`knowledge` → `04-Knowledge/`, `project` → `02-Projects/` (titles may contain `/`
for subfolders), `inbox` → `00-Inbox/` (free-form).

## Tests

```powershell
cd tools/obsidian-mcp
& ".\.venv\Scripts\python.exe" -m pytest -q
```

Tests run against a tmp fixture vault — they never touch the real vault.
```

- [ ] **Step 3: Validate `.mcp.json` parses**

Run: `& "tools\obsidian-mcp\.venv\Scripts\python.exe" -c "import json; json.load(open('.mcp.json')); print('json OK')"`
Expected: `json OK`

- [ ] **Step 4: Commit**

```powershell
git add .mcp.json tools/obsidian-mcp/README.md
git commit -m "obsidian-mcp: register stdio server in .mcp.json and document tools"
```

---

### Task 9: Execution-hub migration (writes the REAL vault)

**Files:**
- Create: `tools/obsidian-mcp/scripts/migrate_hub.py`
- Modify: `C:\Users\isaac\.claude\projects\D--Multi-Agent-workflow-network-infrastructure-ai-platform\memory\netops-platform-loop-mission.md` (shrink to pointer)
- Modify: `C:\Users\isaac\.claude\projects\D--Multi-Agent-workflow-network-infrastructure-ai-platform\memory\MEMORY.md` (update hook line)

This task writes to `D:\Brains\Network-brain\Network-infra-projects` — the user approved this migration in the spec. The script is idempotent-hostile by design (create_note refuses overwrites), so it runs exactly once.

- [ ] **Step 1: Write `tools/obsidian-mcp/scripts/migrate_hub.py`**

The main project note goes through `create_note` (dogfooding the validation path); the three operational hub notes are written via `Vault.write_new` per the spec.

```python
"""One-time migration: move build mission state into the vault (spec §Execution-hub).

Run:  .venv/Scripts/python.exe scripts/migrate_hub.py   (from tools/obsidian-mcp/)
"""

from pathlib import Path

from obsidian_mcp.templates import create_note
from obsidian_mcp.vault import Vault

VAULT_ROOT = Path(r"D:\Brains\Network-brain\Network-infra-projects")
PROJECT_DIR = "02-Projects/AI Network Operations Platform"

PROJECT_NOTE_CONTENT = """## Executive Summary

Self-hosted AI-powered Network Operations Platform (FastAPI modular monolith,
LangGraph supervisor agents, Postgres+pgvector, Neo4j projection, React/TS
frontend). Built autonomously by Claude Code from `CLAUDE.md`; repo:
`D:/Multi-Agent workflow/network-infrastructure-ai-platform`.

## Business Objective

An AI Network Engineer for enterprise infrastructure teams: discovery,
troubleshooting, packet analysis, configuration management, DDI, documentation
generation, automation — multi-vendor ([[Cisco]], [[Juniper]], [[Arista]],
[[Palo Alto]], [[Fortinet]], [[F5]], [[BlueCat]], [[Infoblox]], AWS, Azure, VMware).

## Current State

M0 scaffold complete (commit 40f82e7): backend foundation, vendor plugin system
with [[Cisco]] IOS reference plugin, agent framework, multi-LLM providers, React
frontend, Docker deploy, CI. 173 backend tests, 92% coverage.

## Desired State

Deployable on-prem platform per docs/roadmap/MVP.md (M0-M5) and PRODUCTION.md.

### Success Criteria

- [ ] M1: inventory, credential vault, discovery engine, devices API
- [ ] M2: topology in Neo4j
- [ ] M3: agents with persisted reasoning traces
- [ ] M4: config management + approvals
- [ ] M5: packet analysis (bounded diagnostic captures)

## Scope

See repo `docs/roadmap/MVP.md`.

## Requirements

See repo `CLAUDE.md` and `docs/architecture/DECISIONS-BRIEF.md` (D1-D16).

## Assumptions

See repo `docs/architecture/ASSUMPTIONS.md`.

## Constraints

Local-first, self-hosted, human approval for changes, audit everything.

## Dependencies

Local: Python 3.14, Node 20+, Docker. LLM: Ollama default ([[Python]], [[APIs]]).

## Architecture Overview

See repo `docs/architecture/DIAGRAMS.md` and ADRs 0001-0016.

## Vendor Technologies

[[Cisco]], [[Juniper]], [[Arista]], [[Palo Alto]], [[Fortinet]], [[F5]],
[[BlueCat]], [[Infoblox]].

## Risks

See repo `docs/consultant/GAP-ANALYSIS.md` (16 gaps tracked).

## Implementation Plan

Tracked in [[Status]] and [[Iteration Log]].

## Validation Plan

Per-milestone: pytest/vitest suites, ruff/mypy, CI, UAT via /gsd-verify-work.

## Rollback Plan

Git history in the repo; milestone commits are atomic.

## Lessons Learned

Appended to [[Iteration Log]] as the build proceeds.

## Related Notes

[[Status]] · [[Iteration Log]] · [[Decisions]]
"""

STATUS = """# Status

Execution hub for the AI Network Operations Platform build. Claude Code reads
this note at session start (via obsidian MCP `read_note`) and keeps it current.

## Current Milestone

M0 complete (commit `40f82e7`, 2026-06-10). Build PAUSED before M1 per user
directive while the Obsidian integration lands.

## Active Directives

- Vault is the central execution hub: keep this note and [[Iteration Log]]
  current via obsidian MCP tools (`append_note`).
- Consultant questions never block: defaults live in repo
  `docs/consultant/QUESTIONS.md`.
- Commit partial work promptly — session limits kill long workflows.

## Next Steps

- Finish obsidian-mcp tool (this migration is its last task).
- Resume build: M1 — inventory models, credential vault (core/crypto.py),
  discovery engine, netmiko transport, devices API, auth routes + RBAC,
  alembic migration 0001.

## Related

[[AI Network Operations Platform]] · [[Iteration Log]] · [[Decisions]]
"""

ITERATION_LOG = """# Iteration Log

Build history of the [[AI Network Operations Platform]]. Newest entries are
appended to the Iterations section by Claude Code via `append_note`.

## Iterations

- **Iteration 1 (2026-06-09):** Phase 1 architecture: DECISIONS-BRIEF (D1-D16),
  25 docs (16 ADRs, gap analysis, diagrams, MVP+production roadmaps, repo
  blueprint). Commit `59b447c`.
- **Iteration 2 (2026-06-09):** Workflow phase2-m0-scaffold died on session
  limit after ~28 foundation files. Lesson: commit partial work promptly.
- **Iteration 3 (2026-06-10):** Foundation recovered + committed (`54a8559`):
  config, logging, errors, security, health API, celery, alembic, tests.
- **Iteration 4 (2026-06-10):** Resume workflow died on session limit again,
  but frontend builder finished its whole file set first - recovered as
  `42bfaa6`. Stale 3.12 venv rebuilt on Python 3.14. passlib replaced with
  direct bcrypt (`083f638`) - passlib 1.7.4 is unmaintained and breaks against
  bcrypt>=4.1.
- **Iteration 5 (2026-06-10):** Workflow wf_bbcb1806-92f completed: plugin
  system (normalized schemas, capability ABCs, registry, cisco_ios reference
  plugin) + agent framework (tool classification, traces, supervisor, LLM
  providers) + verify/fix. M0 complete: `40f82e7` - 173 tests, 92% coverage.
- **Iteration 6 (2026-06-10):** User directive: pause before M1; design+build
  Obsidian integration (vault as execution hub). Spec + this MCP server built.

## Decisions

See [[Decisions]].
"""

DECISIONS = """# Decisions

One-line summaries; authoritative ADRs live in the repo at `docs/adr/`.

## Architecture (D1-D16)

- FastAPI modular monolith; LangGraph supervisor agents — repo
  `docs/architecture/DECISIONS-BRIEF.md`
- Postgres+pgvector system of record (ADR-0004); [[Neo4j]] projection (ADR-0005)
- Capability-based vendor plugin system (ADR-0006); device connectivity (ADR-0007)
- Celery+Redis async jobs (ADR-0008); multi-LLM via LangChain, Ollama default
- Tool classification read_only / state_changing / diagnostic (ADR-0011)
- React+TS+Vite frontend (ADR-0012); Compose→Helm deployment (ADR-0013)
- Worker-side tcpdump + EOS capture only at M5 (ADR-0014)
- Observability (ADR-0015); testing/CI standards (ADR-0016)

## Build-time

- passlib replaced with direct bcrypt (2026-06-10, commit `083f638`)
- REPO-STRUCTURE ratified as-built v0.2: top-level `db.py`, versioned health
  paths (2026-06-10, commit `40f82e7`)
- Obsidian vault is the build's execution hub (2026-06-10, this migration;
  spec `docs/superpowers/specs/2026-06-10-obsidian-mcp-integration-design.md`)

## Related

[[AI Network Operations Platform]] · [[Status]] · [[Iteration Log]]
"""


def main() -> None:
    vault = Vault(VAULT_ROOT)
    created = []
    created.append(
        create_note(
            vault,
            "project",
            "AI Network Operations Platform/AI Network Operations Platform",
            PROJECT_NOTE_CONTENT,
            tags=["netops-platform", "active"],
        )
    )
    for name, text in (
        ("Status.md", STATUS),
        ("Iteration Log.md", ITERATION_LOG),
        ("Decisions.md", DECISIONS),
    ):
        created.append(vault.write_new(f"{PROJECT_DIR}/{name}", text))
    print("Created:")
    for rel in created:
        print(f"  {rel}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the migration**

Run (from `tools/obsidian-mcp/`):
```powershell
& ".\.venv\Scripts\python.exe" scripts\migrate_hub.py
```
Expected output:
```
Created:
  02-Projects/AI Network Operations Platform/AI Network Operations Platform.md
  02-Projects/AI Network Operations Platform/Status.md
  02-Projects/AI Network Operations Platform/Iteration Log.md
  02-Projects/AI Network Operations Platform/Decisions.md
```
If it fails with "already exists", the migration already ran — do not force; inspect the vault.

- [ ] **Step 3: Verify in the vault**

```powershell
Get-ChildItem "D:\Brains\Network-brain\Network-infra-projects\02-Projects\AI Network Operations Platform"
```
Expected: the four files above. Spot-check one:
```powershell
Get-Content "D:\Brains\Network-brain\Network-infra-projects\02-Projects\AI Network Operations Platform\Status.md" -TotalCount 5
```

- [ ] **Step 4: Shrink the Claude memory file to a pointer**

Replace the ENTIRE contents of
`C:\Users\isaac\.claude\projects\D--Multi-Agent-workflow-network-infrastructure-ai-platform\memory\netops-platform-loop-mission.md` with:

```markdown
---
name: netops-platform-loop-mission
description: Standing build mission — execution state lives in the Obsidian vault (02-Projects/AI Network Operations Platform/Status.md); use the obsidian MCP tools
metadata:
  type: project
---

Mission state for the AI Network Operations Platform build moved to the Obsidian
vault on 2026-06-10 (user directive: vault is the central execution hub).

- **Read state**: `read_note("02-Projects/AI Network Operations Platform/Status.md")`
  via the obsidian MCP server for current milestone, directives, next steps.
- **Write state**: after each iteration, `append_note` to `Iteration Log.md`
  (section "Iterations") and keep `Status.md` current.
- The server lives at `tools/obsidian-mcp` (registered in repo `.mcp.json`,
  `OBSIDIAN_VAULT_ROOT=D:\Brains\Network-brain\Network-infra-projects`).
- Standing rules unchanged: consultant questions never block (defaults in
  `docs/consultant/QUESTIONS.md`); commit partial work promptly (session limits
  kill long workflows); the /loop is re-armed by the user.
```

- [ ] **Step 5: Update the MEMORY.md index line**

In `C:\Users\isaac\.claude\projects\D--Multi-Agent-workflow-network-infrastructure-ai-platform\memory\MEMORY.md`, replace the existing line

```
- [NetOps platform loop mission](netops-platform-loop-mission.md) — standing autonomous build loop per CLAUDE.md; iteration log and next steps
```

with

```
- [NetOps platform loop mission](netops-platform-loop-mission.md) — standing build loop; execution state lives in the Obsidian vault (use obsidian MCP tools)
```

- [ ] **Step 6: Commit**

```powershell
git add tools/obsidian-mcp/scripts/migrate_hub.py
git commit -m "obsidian-mcp: execution-hub migration script (run once against the vault)"
```
(The vault and Claude memory directory are outside the repo — only the script is committed.)

---

### Task 10: Final verification

- [ ] **Step 1: Full suite from clean state**

Run (from `tools/obsidian-mcp/`):
```powershell
& ".\.venv\Scripts\python.exe" -m pytest -q
& ".\.venv\Scripts\ruff.exe" check .
& ".\.venv\Scripts\ruff.exe" format --check .
& ".\.venv\Scripts\python.exe" -m mypy
```
Expected: all green.

- [ ] **Step 2: Confirm repo tree is clean and pushed state is coherent**

Run: `git status --short` (expect clean) and `git log --oneline -8` (expect the obsidian-mcp commits atop `4231a9e`).

- [ ] **Step 3: Tell the user**

Report: the MCP server tools become available after **restarting the Claude Code session** (`.mcp.json` is read at session start). Suggest verifying with `/mcp` in the new session, then `search_notes("BGP")` as a smoke test.

---

## Self-review (run after writing, fixed inline)

- **Spec coverage:** six tools (Tasks 4–6), validation rules (Task 4), write safety (Tasks 2, 4), search semantics (Task 5), error messages (Tasks 2–6), startup failures (Task 7), registration + README (Task 8), hub migration incl. memory pointer (Task 9), testing strategy (fixture in Task 2). Deferred items from spec (backlinks, propose_edit, platform integration) intentionally absent.
- **Placeholder scan:** none; every step has full code/commands.
- **Type consistency:** `Vault.read_note → Note(path, frontmatter, body)`; `create_note(vault, kind, title, content, tags) → str` used identically in Tasks 4, 6, 9; `append_to_section(text, section, content) → str` in Tasks 2, 3, 6; `SearchHit(path, title, score, snippets)` in Tasks 5, 6.
