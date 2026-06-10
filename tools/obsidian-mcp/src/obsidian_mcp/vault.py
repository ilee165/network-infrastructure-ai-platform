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
                return parsed, text[end + 5 :].removeprefix("\n")
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
        # Atomic replace: a crash mid-write must not truncate a hub note.
        tmp = target.parent / (target.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, target)

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
