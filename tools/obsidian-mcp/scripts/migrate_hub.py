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
