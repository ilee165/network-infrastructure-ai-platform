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
