# Wave 5 Implementation Plan — Perf/Scale Point Fixes

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source:
[`PERF-REVIEW-2026-07-10.md`](PERF-REVIEW-2026-07-10.md) (ranked table #N,
per-layer IDs). Wave 2 already shipped the three cheapest CRITs (bcrypt
to_thread, WS poll cursor, auto-rebuild gate); this wave takes the remaining
CRIT/HIGH point fixes that don't need a design phase.

**Explicitly deferred (structural ceilings, not this wave):**
- Audit chain global lock (#7) — deliberate ADR-0038/0042 design; sharded
  keys / async outbox only if a throughput requirement materializes (Wave 7
  retention ADR is the venue to note it).
- Route-table streaming path (#8's memory triple-hold + fixed read_timeout,
  workers H2) — needs a collect-parse-persist streaming design before any
  BGP-core use case; record as ARCH debt, do the bulk-upsert half now (T4).
- Anthropic `cache_control` prompt caching + router intent cache (agents
  M2/H6) — needs eval re-run to prove no routing regression; defer to an
  agents-focused follow-up.

**Shape:** one branch (`fix/review-wave5`), one PR, atomic commit per task.
Every perf fix carries a **measurement** in the commit message (before/after
on the stated metric, measured locally or in CI) — perf claims without
numbers don't merge. Behavior-preserving except where stated.

---

## Group A — Discovery pipeline (perf #1, #2)

### T1 — Vendor detection SSH churn (perf #1 CRIT)
`backend/app/workers/tasks/discovery.py:301-343`, `transport/ssh.py:104`.
Nested cred×vendor loop opens a full `ConnectHandler` per candidate (~13
vendors, 5–15 s per wrong driver) → 40–90 s waste/device; 100-device wave ≈
1.5–2.5 h handshake burn.
- Fix: (a) order candidates by known vendor/prior `sysDescr` before looping;
  (b) in-session autodetect via netmiko `SSHDetect` where the credential
  works; (c) reuse the detection session for collection (post-detection
  reuse already exists at `:322-327` — extend it to the detect phase).
- Note: T1 rides on Wave 3's host-key verification — detection sessions obey
  the same strict-mode policy.
- Measure: per-device detection wall time on the lab matrix (or mocked timing
  harness), before/after.

### T2 — Orchestrators block their own pool (perf #2 CRIT / repo H12)
`discovery.py:566-571`, `config.py:513-521`
(`.get(disable_sync_subtasks=False)`); compose runs one worker, no `-c`.
c=1 deadlocks; c=2 fully serial (100×8 s ≈ 13.3 min vs ~80 s at c=10).
- Fix: chord/callback continuation instead of blocking `.get()` —
  finalization runs as the chord body. If chord semantics fight the existing
  wave-barrier logic, fallback: dedicated `orchestrator` queue + per-queue
  `-c` in compose/Helm (both deploy paths updated together).
- Measure: 20-device simulated wave wall time at c=2, before/after.

## Group B — Persistence & Neo4j (perf #8, #9, #18 + M5)

### T3 — Bulk upsert for interfaces/routes/neighbors (perf #8)
`backend/app/engines/discovery/persistence.py:126-156,196-227`. Full-table
ORM preload + per-row setattr/add: 10k routes ≈ 10–40 s + 50–100 MB.
- Fix: bulk `INSERT ... ON CONFLICT DO UPDATE` over values lists +
  set-difference delete. **Keep the SQLite seam** — unit suite runs SQLite;
  use dialect-appropriate upsert (`sqlalchemy.dialects.postgresql.insert` vs
  sqlite `on_conflict_do_update`) behind one helper, and add a
  `tests/pg/` case (with `pytestmark = pytest.mark.integration`, prove
  collection) so PG semantics are gate-covered.
- Measure: 10k-row synthetic upsert timing, before/after.

### T4 — Delta projection instead of full-estate re-projection (perf #9)
`backend/app/workers/tasks/topology.py:144-158,249-273`,
`projector.py:426-447` (+ dup loader `rebuild.py:130-136`). Every discovery
sync pays an O(full graph) MERGE/SET + 18 sweep scans regardless of delta;
snapshot-diff engine (`engines/topology/diff.py`) exists but is unused for
projection.
- Fix: project the snapshot diff — scope the load to run-touched devices,
  skip unchanged SET; full projection remains the manual-rebuild path.
  Consolidate the duplicated loader while there.
- Guard: Wave 2's watermark gate (T10) changed the trigger; this changes the
  payload — keep the two behaviors separately testable.
- Measure: 1-device sync on a seeded 500-device estate — elements written
  before/after.

### T5 — `/topology/graph` double full-edge scan (perf #18) + M5 batch wipe
`topology_read.py:247-256,390-403`, `api/v1/topology.py:112-119`,
`projector.py:167-168,474-476`.
- Fix: indexed `(:Device {site})` seed + expand (add the site index to
  `schema.py`); fold the count pass into `LIMIT max+1`; ETag/TTL keyed on
  endpoint+params+`projected_at` watermark. Wipe path: `CALL {} IN
  TRANSACTIONS` for the DETACH DELETE batches.
- Measure: query count/latency on seeded graph via Neo4j query log.

## Group C — Agents/LLM hygiene (perf #10, #11 + H5, H2-doc)

### T6 — Cache the supervisor stack (perf #10 / agents H1)
`api/v1/agents.py:300-318,486-491`, `supervisor.py:184-281`,
`providers.py:199-227`. 10 agents + 10+ graph compiles + fresh provider
client per request.
- Fix: process-wide cache keyed `(profile, model)`; invalidate on LLM
  settings PATCH (hook the settings-update path). Provider clients reused →
  connection reuse to Ollama/Anthropic.
- Test: cache hit on second request; invalidation on settings change;
  existing routing evals stay green (roster unchanged).

### T7 — Model call bounds (perf #11 / agents H3+H4)
`providers.py:199-220`, `framework/base.py:126-137`.
- Fix: explicit per-call timeout + bounded retries + `num_ctx`/`keep_alive`
  on Ollama; cap/summarize ToolMessages re-sent in the ReAct loop (truncate
  large tool outputs with a marker; window history beyond N turns). Settings
  knobs for timeout/num_ctx — `.env.example`/config-contract updated together
  (generated after Wave 4).
- Test: wedged-provider simulation times out instead of hanging; oversized
  tool output truncated at the documented cap.

### T8 — Embedding client singleton + LRU (agents H5)
`knowledge/embedding.py:115-127,409-410,335`.
- Fix: module-level client singleton; LRU keyed on text hash for query
  embeddings; content-hash skip on regenerate.
- Test: repeated retrieve embeds once; regenerate skips unchanged chunks.

### T9 — Parallelize documentation section generation (agents H2)
`documentation/tools.py:722-731,1017-1027`.
- Fix: `asyncio.gather` the independent section calls (runbook + incident
  report share the shape — pairs with repo M40's dedupe if trivial, else
  gather-only). Add the missing per-call timeout (repo M41) in the same
  commit — these READ_ONLY tools currently have no bound.
- Measure: doc-generation wall time on local model, before/after.

## Group D — Frontend (perf #5, #15, #16)

### T10 — Code-splitting (perf #5 CRIT)
`App.tsx:26-58`, `TopologyPage.tsx:22`, `vite.config.ts:23-26`. 894.96 KB
min single chunk; cytoscape (~440 KB) shipped to `/login`.
- Fix: `React.lazy` per route + Suspense shell; `manualChunks` for cytoscape
  (and other heavyweights the visualizer surfaces). **Build gate asserts ≥2
  chunks** (bite proof: revert lazy → gate RED). Verify with
  rollup-plugin-visualizer; record entry-chunk size before/after.
- L-FE-1: lazy-wrapping changes import shapes — sweep test mocks.

### T11 — ChatPage replay renders (perf #15)
`ChatPage.tsx:167-176,257-263`.
- Fix: rAF-batched frame buffer (or `startTransition`) + memoized
  bubble/step components + stable keys.
- Test: replay of N recorded steps triggers O(N) row renders (assert via
  render-count probe), transcript content unchanged.

### T12 — TopologyPage persistent cytoscape (perf #16)
`TopologyPage.tsx:301-322,554`, `topology-graph.ts:201-218`.
- Fix: persistent cy instance; apply element diffs; re-layout only on
  structural change; viewport preserved across refetch and diff-overlay
  toggle (memoize `topology-graph.ts` outputs so identity is stable).
- Test: refetch with unchanged elements → no layout call, viewport retained.

## Group E — Infra quick wins (perf #13, #14 + startup MEDIUMs)

### T13 — Backend Dockerfile layer cache (perf #13)
`deploy/docker/backend.Dockerfile:35-37`.
- Fix: install from `requirements.lock.txt` in an early layer; `COPY app`
  after; `pip install --no-deps .` last. Kills the 2–5 min full reinstall
  per source edit and the pyproject-vs-lockfile drift.
- Verify: two consecutive builds with a source-only change — second build
  uses cached dep layer (CI build logs as evidence).

### T14 — Compose cold start + entrypoint hygiene (perf #14 + startup M6)
`docker-compose.yml:59-65,91,212-214,257-264`, `backend.Dockerfile:69,72`,
`main.py:203`.
- Fix: api→neo4j `service_started` (lifespan never touches neo4j);
  `--start-interval=2s` on the backend healthcheck; guard the duplicate
  `create_app()` (module-level app vs `--factory`) — standardize both deploy
  paths on one entrypoint shape.
- Measure: compose cold-start-to-healthy wall time, before/after.

### T15 — Small-bore batch
One commit each, trivial:
- Rate limiter: pipeline/Lua the 4 sequential Redis RTTs
  (`deps.py:210-211`, `limiter.py:136-150`).
- Drift check: `content_hash` short-circuit before difflib
  (`engines/config_mgmt/drift.py:223-231`).
- nginx: `upstream api { keepalive 32; }` + `gzip_comp_level 6` +
  `gzip_vary` (`nginx.conf:27-42,76-87`).
- react-query `staleTime` 5 s → per-domain 30–60 s (`main.tsx:28`).
- DB pool/concurrency Settings knobs (startup H2: pool size, celery `-c`)
  sized so `workers × pool ≤ max_connections`; documented defaults.

---

## Ordering & dependencies

- Wave 3 before T1 (detection sessions inherit host-key policy).
- Wave 4 before T7/T15 config knobs (`config-drift` generator owns
  `.env.example` — add fields to `Settings`, regenerate).
- T4 after T3 (projection reads what persistence wrote; keep the seam
  stable). T10 before T11/T12 (lazy boundaries change component module
  shapes — do the mock sweep once).
- Group A/B/C/D/E are otherwise independent — parallelizable across
  implementer agents; B and C are the two largest.
- No P4-W3 collision except `api/v1/topology.py` (T5) — coordinate if P4-W3
  is in flight.

## Model & review policy

Standard tier (`wf-implementer`) throughout — no secret surfaces. T2 and T4
get spec review (orchestration semantics and projection correctness are the
two regression-prone tasks). T15 items can go `wf-implementer-light`.

## Gates (per task and PR exit)

- Backend/frontend/static gates as standard; new `tests/pg/` files carry the
  integration marker with collection proof.
- Perf evidence per task in commit message (metric, before, after, method).
- Build gate for ≥2 JS chunks proven to bite (T10).
- `graphify update .` after merge.

## Exit criteria

- Discovery: detection churn eliminated (per-device detect ≤ ~1 driver
  attempt amortized); orchestrators no longer hold pool slots.
- Persistence/Neo4j: 10k-row re-discovery in seconds not tens of seconds;
  1-device sync writes O(delta) not O(estate); `/topology/graph` single
  bounded scan + watermark caching.
- Agents: supervisor/client/embedder cached; every model call bounded by
  timeout; ReAct prompts capped.
- Frontend: entry chunk ≤ ~300 KB min with cytoscape split out; replay and
  topology interactions jank-free at the stated scales.
- Infra: incremental image builds ~10–20 s; compose cold start ~15 s.
- Deferred items (audit-lock ceiling, route streaming, prompt caching)
  recorded in `docs/ARCHITECTURE_DEBT.md` with this wave as provenance.
- `REVIEW-WAVES-PLAN.md` status table updated.
