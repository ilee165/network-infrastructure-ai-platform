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
    def search_notes(
        query: str, folder: str | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
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
        """List markdown notes (path + title), optionally within one folder.

        Returns a flat list ordered folder-by-folder (no nested grouping).
        """
        results = []
        for p in vault.list_md(folder):
            title = p.stem
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
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
    def create_note(kind: str, title: str, content: str, tags: list[str] | None = None) -> str:
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
