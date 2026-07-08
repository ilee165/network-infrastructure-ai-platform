GOAL: Finish P4-W2 (application-dependency topology) on branch feat/p4-w2-app-dependency-topology. T1 schema+projection (e0a9af5), T2 derivation (1e8d16f), and the T3 tagging API (7d64a29) are committed; the wave still lacks its read surface — `LAYERS` in backend/app/knowledge/topology_read.py stops at "dns", nothing answers "what depends on X", and no UI can tag or see applications. Land the T3 tagging UI and all of W2-T4: `LAYER_APP`, a bounded `fetch_impact` read, a viewer+ impact endpoint, the read-only provenance-citing Troubleshooting-Agent tool `get_application_impact`, and the app-dependency UI with per-edge source badges. Headline: Impact.

**Read first.** Repo root R = `D:/Multi-Agent workflow/network-infrastructure-ai-platform`; paths below relative to R unless absolute.

- D:/Multi-Agent workflow/network-infrastructure-ai-platform/docs/goals/2026-07-07-1004-netops-p4w2-impact-rider.md — phases, depth tests, wave task ledger with per-task exit criteria.
- docs/adr/0052-application-dependency-topology.md — binding contract (§7 tagging, §8 reads).
- docs/roadmap/p4-tasks/W2-T3-manual-application-tagging.md and W2-T4-impact-analysis.md — specs.
- Exemplars at HEAD: backend/app/api/v1/applications.py (committed tagging API), backend/app/knowledge/topology_read.py, backend/app/agents/troubleshooting/tools.py, frontend/src/pages/TopologyPage.tsx, frontend/src/pages/DevicesPage.tsx.

**Posture.** Reads + UI only: no Alembic migration, no table/column change, no projector-write change. `knowledge/` stays the sole Neo4j reader, the projector the sole writer (lint-imports boundary). No agent tagging tool — the only new agent tool is READ_ONLY. CR-gating stays declined (user decision 2026-07-05); derived applications stay undeletable. No `git push`. Edits inside R.

**Deliverables.**

- Tagging UI — applications page: list manual+derived apps, create/edit/delete manual apps, tag-object-into-application flow, manual-edge removal; write controls hidden below engineer; derived rows show no delete control.
- `fetch_impact(client, *, target_label, target_key, depth)` — Device/IPAddress/Interface/Subnet/Application targets, both directions, depth ≤ MAX_NEIGHBORHOOD_DEPTH, JSON-safe, per-edge `sources` + compact provenance + `projected_at` watermark.
- Impact endpoint on the topology router at viewer+; `app` layer served by the existing graph/neighborhood surfaces.
- `get_application_impact(target)` — `@netops_tool(classification=READ_ONLY)`; every claim cites source + evidence refs + watermark; failures return the house `{"error": ...}` object.
- TopologyPage app layer rendering DEPENDS_ON edges with per-edge source badges.

**Phases.** Eleven in the rider. Each: named depth tests first (red) → implement → gates green → one conventional commit ending "(rider PN)".

**Verification.**

- Backend gates in transcript, all green: `pytest`, `ruff check .`, `ruff format --check .`, `mypy`, `lint-imports` (run from backend/ in its .venv).
- Frontend gates in transcript, all green: `npm run test`, `npm run lint`, `npm run typecheck`.
- Every named depth test in the rider exists and passes; the rider's wave ledger shows each W2-T1..T4 exit criterion checked via an in-transcript command.

**Stop when** all eleven phases are committed, both gate suites are green in the transcript, and the rider's wave ledger has every T1–T4 exit criterion verified — or stop after 30 turns and report what remains.
