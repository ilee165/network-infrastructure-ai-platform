GOAL: Fix the merge-blocking gap on branch feat/p4-w2-app-dependency-topology (PR #119): `fetch_impact`/`_read_impact` in backend/app/knowledge/topology_read.py (~L458-544) cannot surface an IPAddress-bound Application dependent (F5-VIP case) transitively from a Device/Subnet/Interface target — `_PHYSICAL_REL_TYPES` (~L112) never touches `IPAddress`, only `DEPENDS_ON`/`RESOLVES_TO` do. Scoped down + documented as a known limitation in 63f465f (already pushed) rather than fixed; this round implements the fix and proves it against a REAL Neo4j, then unblocks the merge. Headline: Reachable.

**Read first.** Repo root R = `D:/Multi-Agent workflow/network-infrastructure-ai-platform`; paths below relative to R.

- docs/goals/2026-07-07-1540-netops-p4w2-impact-ip-reach-rider.md — mechanism, phases, named depth tests.
- backend/app/knowledge/topology_read.py — `_read_impact`, `fetch_impact`, `_PHYSICAL_REL_TYPES`, `_SITELESS_REL_TYPES` (sibling fix, same file, 63f465f).
- backend/app/engines/topology/nodes.py L138-160, L260-300 — key fact this round hinges on: an `IPAddress` node's `pg_id` IS the `normalized_interfaces` row id it was derived from, so an `IPAddress` and its originating `Interface` node share one `pg_id` across labels. Verify still true at HEAD before designing around it.
- backend/tests/engines/topology/test_projector.py L1-10, L739-800 — the established live-Neo4j test convention: one `@pytest.mark.integration` test alongside its fake-tx siblings, skip-clean via `Neo4jClient(get_settings()).health_check()`, seeded via real `full_rebuild(client, nodes, edges, t1, applications=...)`. Reuse verbatim — no new marker/directory.
- backend/tests/knowledge/test_topology_impact.py — fake-tx unit suite, de-mocked to string-shape assertions in 63f465f.
- docs/adr/0052-application-dependency-topology.md §8 (~L439-474) — promises "device → its interfaces → their IPs → applications"; confirm the fix matches.
- PR #119 (github.com/ilee165/network-infrastructure-ai-platform/pull/119), summary comment #issuecomment-4906952265 — names this gap (B3) as the merge hold.

**Posture.** Stay on `feat/p4-w2-app-dependency-topology`. Reads-only Cypher extension: no migration, no projector write-path change, no new rel type. Reuse the existing `integration` pytest marker (already documented as "Postgres/Neo4j/Redis" in pyproject.toml) — no new marker. No new CI service job: prove it once locally against compose Neo4j in transcript; wiring `neo4j:` into the `pg-integration` CI job is an explicit out-of-scope follow-up. If you uncomment docker-compose.yml's neo4j port mapping to reach it locally, revert before the final commit (`git diff --stat` clean). No `git push` until the final phase.

**Phases.** Eleven in the rider. Each: named depth test first (red against real Neo4j where marked live) → implement → gates green → one conventional commit ending "(rider PN)".

**Verification.**
- Live seed + reproduction test in transcript, RED before the fix and GREEN after, actual Cypher output pasted: `NETOPS_NEO4J_URI=bolt://localhost:7687 NETOPS_NEO4J_PASSWORD=<...> pytest backend/tests/knowledge/test_topology_impact.py -m integration -v`.
- Full backend gates green in transcript: `pytest`, `ruff check .`, `ruff format --check .`, `mypy`, `lint-imports` (from backend/, its .venv).
- Every rider-named depth test exists and passes; `git diff --stat` on docker-compose.yml is empty at the end.

**Stop when** all eleven phases are committed, the live-Neo4j proof and both edge-case depth tests are green, the full backend gate suite is green, and the fix is pushed to `feat/p4-w2-app-dependency-topology` with a PR #119 comment citing the proof — or stop after 25 turns and report what remains.
