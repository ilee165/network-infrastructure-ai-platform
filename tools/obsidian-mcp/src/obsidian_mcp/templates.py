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
