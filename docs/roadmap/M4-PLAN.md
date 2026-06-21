# M4 Build Plan — Config Management + Documentation Agent

**Status:** COMPLETE — shipped 2026-06-14 (PR #24, `f40f7f6 M4 — Config Management + Documentation Agent`).
**Authority:** Implements `docs/roadmap/MVP.md` §6. Bound by `CLAUDE.md`, decisions D1–D16, and `ARCHITECTURE/REPO-STRUCTURE.md`. Build executed via the orchestrated wf-* workflow roster (`.claude/agents/`), mirroring the M1/M3 pattern.

## Goal

Scheduled configuration backups, drift detection, and compliance checking across the three MVP plugins (`cisco_ios`, `cisco_iosxe`, `eos`); a read-only **Configuration Agent**; a **Documentation Agent** generating inventories, diagrams, and runbooks from live data, embedded into pgvector for RAG. All write paths stay hard-rejected until M5 — agents are read-only by construction.

## Build approach

One orchestrated build workflow (mirrors M1's `wf_a7368a4c-6a1`, 18 tasks): TDD per task, exactly one atomic commit per task, dual sonnet review (`wf-spec-reviewer` + `wf-quality-reviewer`) behind mechanical gates, `agentType` model tiering. Sequential tasks where files overlap; parallel only within a task (the two reviews). `resumeFromRunId` for restarts.

Maps onto the milestone template (`10-Templates/CLAUDE_CODE_MILESTONE_EXECUTION.md`): this workflow is Phase 4 (Implementation) + Phase 6 (Validation). Phases 1/2/3/7/9 (discovery, branch, plan doc, vault update, final report) are the human-facing wrapper.

## Task waves (dependency-ordered)

Cx = complexity (S/M/L). Every task also runs dual review → `wf-fixer` (if findings) → `wf-verifier`.

| # | Task | Wave | wf-* role | Cx |
|---|------|------|-----------|----|
| 1 | ADRs: snapshot storage (content-addressed), compliance YAML rule format, doc-gen + RAG model, diagram render path | 0 plan | `wf-implementer` | M |
| 2 | Alembic 0006: `config_snapshots`, `compliance_policies`, `documents`, pgvector `embeddings` (partition/retention where applicable) | 1 | `wf-implementer` | M |
| 3 | `CONFIG_BACKUP` capability on `cisco_ios` (first, certified against conformance suite) | 1 | `wf-implementer` | M |
| 4 | `CONFIG_BACKUP` on `cisco_iosxe` + `eos` (mirror #3) | 1 | `wf-implementer-light` | S |
| 5 | `engines/config_mgmt/` snapshot capture (content-addressed, diff-friendly) + `config`-queue tasks (scheduled + on-demand) | 2 | `wf-implementer` | L |
| 6 | Drift detection (last-approved baseline vs current, unified diff) | 2 | `wf-implementer` | M |
| 7 | Compliance engine: declarative YAML rules (regex + parsed-model assertions, severity info/warn/violation) + seeded policy pack | 2 | `wf-implementer` | L |
| 8 | `knowledge/` embedding + chunking pipeline + pgvector RAG retrieval tool | 2 | `wf-implementer` | L |
| 9 | **Configuration Agent** (read-only): explain-drift / assess-policy / compliance-summary typed tools — ⚠️ secret-touching | 3 | `wf-implementer` | L |
| 10 | **Documentation Agent** — network inventory (Markdown + CSV from normalized tables) | 3 | `wf-implementer-light` | M |
| 11 | Documentation Agent — diagrams (Mermaid from Neo4j projection + rendered PNG via Cytoscape export) | 3 | `wf-implementer` | M |
| 12 | Documentation Agent — runbooks (template + LLM narrative grounded in inventory/topology) — ⚠️ secret-touching | 3 | `wf-implementer` | L |
| 13 | Register Configuration + Documentation agents with Master Architect; **routing prompt v4 + sharpened 5-way specialist descriptions** | 3 | `wf-implementer` | M |
| 14 | API: `/api/v1/devices/{id}/config-snapshots` (+ drift, compliance sub-resources) under the devices router; document endpoints on the `docs` router | 4 | `wf-implementer-light` | M |
| 15 | Frontend: config snapshots / diff / compliance views | 4 | `wf-implementer-light` | M |
| 16 | Frontend: documents library + download | 4 | `wf-implementer-light` | S |
| 17 | **M4 eval suite** (6 exit criteria), RAG retrieval eval, **5-way real-LLM routing eval** | 5 | `wf-eval-designer` | L |
| 18 | Full gates + live-lab validation + release branch | 5 | `wf-implementer` | M |

## Agent roster decision

**Product agents (`backend/app/agents/`):** add exactly the two the roadmap specifies — **Configuration Agent** and **Documentation Agent**. No more. The Documentation Agent stays ONE agent with three tool groups (inventory/diagram/runbook), not three agents — adding agents widens the supervisor routing surface, which is already M4's top risk.

**Build roster (`.claude/agents/`):** added **`wf-eval-designer`** (strong model, read+write) this cycle. M4 is the first milestone where LLM-output quality (runbook grounding, drift/compliance explanation, RAG retrieval, a now 5-way routing decision) is itself the deliverable, and the existing six wf-* roles cover implement/review/fix/verify but had no eval-design specialist. It owns task #17 and the eval layer of #9/#11/#12/#13. Pays forward into M5 (3 more agents + packet/DDI evals).

## Risks → escalation & sequencing

1. **⚠️ Config snapshots contain secret material** (enable/type-7/9 secrets, SNMP communities, PSKs). Any path feeding config content to an LLM — Configuration Agent diff-explanation (#9), runbooks (#12) — MUST pass through the A9 redaction layer (`llm/redaction.py`). Per the roster escalation rule, **escalate the reviewers on #9 and #12 to the strong model** (`opts.model`). Raw snapshot storage is treated like `raw_artifacts`: RBAC + audit, never returned in plaintext beyond the snapshot resource.
2. **5-way routing disambiguation** (#13): discovery / troubleshooting / consultant **+ configuration + documentation**. Exactly the failure the M3 routing fix addressed, now wider. Sharp descriptions + routing prompt v4 + the real-LLM routing eval (#17, held-out cases) are mandatory. See `docs/superpowers/plans/2026-06-14-supervisor-routing-disambiguation.md`.
3. **RAG retrieval eval** (#17): relevance is fuzzy — needs a held-out reference set of (query → expected chunk) with citation assertion.
4. **Diagram PNG via Cytoscape export** (#11): couples a backend `docs`-queue job to frontend rendering; may need a headless render path. Resolve in ADR #1.

## Exit-criteria → task mapping (MVP.md §6)

| Exit criterion | Tasks |
|---|---|
| Nightly scheduled backup of 100% reachable devices; failures audited | 3, 4, 5 |
| Out-of-band change flagged as drift w/ accurate diff; agent explanation references changed lines | 6, 9 |
| Seeded policy violation reported (device/rule/severity/evidence); compliant device clean | 7, 9 |
| Generated inventory matches normalized tables; diagram matches Neo4j node/edge set | 10, 11 |
| RAG query against a generated runbook returns relevant chunk with citation | 8, 12, 17 |
| All artifacts downloadable from UI, recorded in `documents` with embeddings | 8, 14, 15, 16 |

## Next step

Execute Wave 0 (ADRs + spec), then launch the orchestrated build workflow for Waves 1–5. Update vault `00-STATUS` / `03-TASKS` as work progresses (vault = execution hub). Note: the vault is an **external Obsidian vault**, not tracked in this repo — only the `tools/obsidian-mcp` dev tooling lives in-tree.
