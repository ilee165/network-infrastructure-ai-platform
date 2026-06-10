# Obsidian MCP Integration — Design Spec

**Date:** 2026-06-10
**Status:** Approved by user (design review 2026-06-10)
**Scope:** Development-workflow tooling only — NOT a platform product feature.

## Context

The user runs an Obsidian vault at `D:\Brains\Network-brain\Network-infra-projects`
(the folder containing `.obsidian`) that serves as their network-infrastructure
knowledge base. It has a deliberate taxonomy (`00-Inbox` … `10-Templates`), per-type
documentation standards (defined in the vault's `CLAUDE/CLAUDE.md`), four templates
in `10-Templates/`, and aggressive wiki-linking conventions.

The user wants the vault to become the **central execution hub** for the AI Network
Operations Platform build: agents (Claude Code and its subagents/workflow agents)
get on-demand vault access through MCP tools — search returns snippets instead of
whole files entering context — and project execution state (mission status,
iteration log, decisions) moves into the vault where the user can watch and steer
the build from Obsidian.

## Decisions made during design review

1. **Read + write** access (not read-only, not inbox-gated). Writes are constrained
   by taxonomy and template validation enforced in server code.
2. **Build workflow only.** The platform's LangGraph agents do NOT consume this
   server. No platform code changes.
3. **Vault is the hub.** Mission state moves from Claude's private memory directory
   into `02-Projects/AI Network Operations Platform/`; Claude memory keeps only a
   pointer.
4. **Custom server over community servers** (Approach A): direct-filesystem Python
   MCP server, because template/taxonomy enforcement is the core value and no
   off-the-shelf server provides it; also avoids a runtime dependency on the
   Obsidian app (REST-plugin approaches require Obsidian running).

## Goals

- Agents can search, read, list, create, and append vault notes via MCP tools
  without loading vault content wholesale into context.
- Writes always conform to the vault's taxonomy and template standards, enforced
  in code, not prompts.
- Project execution state lives in the vault and stays current as the build runs.

## Non-goals (out of scope)

- Platform/product integration (Documentation agent → vault is a future,
  separately designed feature).
- Obsidian Local REST API plugin or any Obsidian-app automation.
- Note deletion or arbitrary note editing tools (Claude's native Edit tool remains
  available for surgical edits under user oversight).
- Sync/conflict handling (single-user local vault).
- Adding the tool to the platform's CI pipeline.

## Architecture

- **Location:** `tools/obsidian-mcp/` in this repo — outside `backend/`, with its
  own `pyproject.toml` and venv. Never touches platform dependencies or CI.
- **Stack:** Python ≥3.11, official `mcp` Python SDK (FastMCP), `pyyaml` for
  frontmatter. No other runtime dependencies; search is pure Python.
- **Transport:** stdio MCP server, launched by Claude Code per `.mcp.json` at the
  repo root (checked in).
- **Vault root:** `OBSIDIAN_VAULT_ROOT` env var, set in `.mcp.json` to
  `D:\Brains\Network-brain\Network-infra-projects`. The server refuses to start if
  the path doesn't exist or lacks `10-Templates/`.
- **Filesystem direct:** reads/writes Markdown files; Obsidian auto-detects
  changes. Works when Obsidian is closed.

### Package layout

```
tools/obsidian-mcp/
├── pyproject.toml          # [project] obsidian-mcp; deps: mcp, pyyaml; dev: pytest, ruff, mypy
├── README.md               # setup (venv creation), tool reference, .mcp.json registration
├── src/obsidian_mcp/
│   ├── __init__.py
│   ├── __main__.py         # python -m obsidian_mcp → run stdio server
│   ├── server.py           # FastMCP tool definitions (thin layer)
│   ├── vault.py            # path safety, read/write primitives, frontmatter
│   ├── templates.py        # kind→folder/template mapping, section extraction, validation
│   └── search.py           # scan, rank, snippet extraction
└── tests/
    ├── conftest.py         # tmp_path mini-vault fixture (taxonomy + real template copies)
    ├── test_search.py
    ├── test_vault.py
    ├── test_templates.py
    └── test_tools.py       # tool-level behavior incl. error messages
```

## Tool surface

Six tools. All `path` arguments are vault-root-relative POSIX-style strings
(e.g. `06-Runbooks/BGP Neighbor Down.md`).

### `search_notes(query: str, folder: str | None = None, limit: int = 10)`

- Case-insensitive token match over all `.md` files, excluding dot-folders
  (`.obsidian`, `.deepeval`) and `Assets/`. The query is whitespace-split into
  tokens; a note matches only if **all** tokens appear in it (AND semantics);
  the score sums the weighted counts of every token.
- Ranking: hits in the H1/title count ×3, hits in any heading ×2, body hits ×1;
  ties broken by file modification time (newer first).
- Returns per note: relative path, title (first H1, else filename), score, up to
  3 snippets (matched line ± 1 line of context).
- `folder` restricts the scan to one top-level folder.
- Never returns full note bodies.

### `read_note(path: str)`

- Returns parsed YAML frontmatter (as a mapping; empty if none) and the full body.
- Not-found error lists the `.md` files in the requested note's folder.

### `list_notes(folder: str | None = None)`

- Lists `.md` files (relative path + title) under `folder`, or the whole vault
  grouped by top-level folder. Same exclusions as search.

### `get_template(kind: str)`

- Returns the raw template text and the list of required section headings for the
  kind (see mapping below). Lets an agent see the expected structure before writing.

### `create_note(kind: str, title: str, content: str, tags: list[str] = [])`

- Kind mapping:

  | kind | folder | template | validation |
  |---|---|---|---|
  | `runbook` | `06-Runbooks/` | `RUNBOOK_TEMPLATE.md` | required sections |
  | `incident` | `07-Incidents/` | `NETWORK_INCIDENT_TEMPLATE.md` | required sections |
  | `knowledge` | `04-Knowledge/` | `KNOWLEDGE_ARTICLE_TEMPLATE.md` | required sections |
  | `project` | `02-Projects/` | `NETWORK_PROJECT_TEMPLATE.md` | required sections |
  | `inbox` | `00-Inbox/` | none | none (free-form) |

- **Required sections** = the H2 headings of the kind's template file, parsed at
  call time (so the user can evolve templates without code changes). Validation:
  every required H2 heading must appear in `content` (exact heading text, any
  order). Section bodies may be empty or `N/A`. Missing sections → rejection
  listing exactly which are missing.
- The server writes: frontmatter (`created` ISO date, `source: claude-code`,
  `kind`, `tags`), then `# {title}` as H1, then `content` (which begins at the
  first H2). Agents therefore supply section content only — H1 and frontmatter are
  server-owned.
- Filename: sanitized title + `.md`, created inside the kind's folder. For the
  `project` kind only, `title` may contain `/` as a subfolder separator (e.g.
  `AI Network Operations Platform/Milestone M1`); the title is split on `/` first
  and **each path component** is then sanitized (`<>:"\|?*` and control chars
  stripped, trimmed). All other kinds are flat — `/` in their titles is stripped
  by sanitization.
- Collision: error if the target file already exists (no overwrites).

### `append_note(path: str, section: str, content: str)`

- Finds the heading line whose text equals `section` (any heading level;
  comparison is case-insensitive after stripping `#` markers and surrounding
  whitespace); appends `content` at the end of that section (immediately before
  the next heading of the same or higher level, or EOF).
- Unknown section → error listing the note's actual headings.
- Only appends — never replaces existing lines.

## Write safety

- Every resolved path must be inside the vault root (`Path.resolve()` +
  `is_relative_to` check); traversal attempts are rejected.
- No delete capability. No overwrite capability.
- Writes are UTF-8.
- Curated folders are reachable only through template-validated `create_note` or
  section-scoped `append_note`; free-form content goes to `00-Inbox`.

## Error handling

All tool failures raise structured MCP tool errors with actionable messages:

- unknown `kind` → lists valid kinds
- missing required sections → lists the missing headings
- note not found → lists notes in that folder
- unknown section → lists the note's headings
- path traversal / outside-vault → explicit rejection message
- vault root missing at startup → server exits with a clear message

## Execution-hub migration (one-time, part of implementation)

1. Create `02-Projects/AI Network Operations Platform/` containing:
   - `Status.md` — current milestone, active user directives, next steps,
     active workflow IDs. Updated every iteration.
   - `Iteration Log.md` — the build history migrated from Claude's memory file
     (iterations 1–5 + M0 completion), then appended per iteration.
   - `Decisions.md` — one-line decision summaries wiki-linked to topics, each
     pointing at the authoritative ADR path in this repo (no content duplication).
2. Notes follow vault linking rules (`[[...]]` links to Knowledge/Vendor topics).
3. Shrink `netops-platform-loop-mission.md` in Claude's memory directory to a
   pointer at `Status.md` + the standing instruction to use the obsidian MCP tools.
4. Tooling: the project's main note (`AI Network Operations Platform.md`, from the
   project template) is created through `create_note` as a dogfooding check.
   `Status.md`, `Iteration Log.md`, and `Decisions.md` are operational hub notes,
   not template-typed documents — the one-time migration writes them directly
   (native Write tool); all **ongoing** updates to them flow through
   `append_note`/`read_note`.

## Registration

`.mcp.json` at the repo root (checked in):

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

The command path is repo-relative (resolved from the project root). The README
documents one-time venv setup:
`python -m venv tools/obsidian-mcp/.venv && tools/obsidian-mcp/.venv/Scripts/pip install -e tools/obsidian-mcp`.

## Testing

Pytest against a `tmp_path` mini-vault fixture that recreates the taxonomy folders
and copies the four real templates:

- search: ranking order (title > heading > body), folder filter, exclusions,
  snippet shape, limit
- vault: traversal rejection, frontmatter round-trip, not-found errors
- templates: section extraction from each template, validation accept/reject with
  exact missing-section messages, kind mapping
- create: per-kind folder placement, frontmatter content, H1 ownership, filename
  sanitization, collision error, inbox free-form path
- append: end-of-section insertion (middle and last section), unknown-section error

Tests run from the tool's own venv (`pytest` from `tools/obsidian-mcp/`). Not part
of platform CI.

## Future (explicitly deferred)

- Platform Documentation agent writing to the vault (own design + ADR when its
  milestone arrives; this server's kind/validation model is the rehearsal).
- Backlink/graph queries (`get_backlinks`), tag queries.
- A `propose_edit` tool for reviewed modifications of existing curated notes.
