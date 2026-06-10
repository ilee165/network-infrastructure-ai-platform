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


def search(vault: Vault, query: str, folder: str | None = None, limit: int = 10) -> list[SearchHit]:
    tokens = [t for t in query.lower().split() if t]
    if not tokens:
        raise VaultError("Empty query")

    scored: list[tuple[int, float, SearchHit]] = []
    for path in vault.list_md(folder):
        # errors="replace": one non-UTF-8 file must not break vault-wide search
        text = path.read_text(encoding="utf-8", errors="replace")
        if not all(t in text.lower() for t in tokens):
            continue
        lines = text.splitlines()
        title = path.stem
        title_idx = -1
        for i, line in enumerate(lines):
            if line.startswith("# "):
                title = line[2:].strip()
                title_idx = i
                break
        heading_lines = "\n".join(
            line
            for i, line in enumerate(lines)
            if i != title_idx and heading_text(line) is not None
        )
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
