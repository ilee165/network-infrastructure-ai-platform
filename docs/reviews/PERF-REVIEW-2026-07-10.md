# Performance Review — 2026-07-10

- **HEAD:** `7478693` (code tree identical to `6c50783`; delta is docs-only)
- **Method:** six parallel read-only audit agents (DB/API, agents/LLM, workers/plugins, Neo4j/topology, frontend, startup/infra), graphify-oriented, line-level verified. No code was modified. Frontend numbers are from a real `vite build`; backend import profile from `python -X importtime` (host Py3.14 — re-run in the Py3.12 container for absolutes).
- **Scope note:** findings are review-verified against source, not load-tested. Each carries a "measure" hook to confirm before investing.

## Executive summary

The platform is structurally clean where most codebases rot: no N+1 in the API/service layer, UNWIND-batched Neo4j writes, process-cached engines/settings, lazy heavy imports (langgraph/plugins/netmiko off the boot path, cold import ~2.2 s), react-query + selector-only zustand on the frontend, HNSW-indexed pgvector. The real costs sit in a small number of architectural hot spots: **collection-layer session churn and self-blocking orchestration**, a **perpetual Neo4j full-rebuild loop**, a **50 Hz N+1 WebSocket poll**, a **global write-serializing audit chain**, **inline bcrypt on the event loop**, and a **single 895 KB frontend chunk**. Most of the top items are days-not-weeks fixes with order-of-magnitude measurable wins.

## Top findings (ranked by expected impact)

| # | Sev | Area | Finding | Measurable impact | Direction |
|---|-----|------|---------|-------------------|-----------|
| 1 | CRIT | Discovery | Fresh SSH session per (credential × vendor) candidate during vendor detection — `workers/tasks/discovery.py:301-343`; ~13 vendor candidates, 5–15 s per wrong-driver attempt | avg ~40–90 s wasted per device; 100-device wave ≈ 1.5–2.5 h of handshake burn | in-session autodetect (netmiko `SSHDetect`) or order candidates by known vendor/sysDescr; reuse session for collection |
| 2 | CRIT | Discovery | Orchestrators block a slot of the same worker pool they dispatch into (`child.get(disable_sync_subtasks=False)`) — `discovery.py:566-571`, `config.py:513-521`; compose runs ONE worker, no `-c` | c=1 deadlocks; c=2 → fully serial: 100 dev × 8 s ≈ 13.3 min vs ~80 s at concurrency 10 | chord/callback instead of blocking `.get()`, or dedicated orchestrator queue + per-queue `-c` |
| 3 | CRIT | Neo4j | Auto-rebuild staleness (300 s) == schedule period (5 min) → perpetual full drop-and-reproject on an idle estate — `auto_rebuild.py:80-89`, `values.yaml:414,418` | ~288 full wipe+rebuild cycles/day at O(full graph) each; readers race wiped graph | gate on drift watermark (PG change vs graph watermark), or staleness ≥ 2× schedule |
| 4 | CRIT | Agents/WS | Trace stream polls DB at 50 Hz with N+1 full-trace reload per tick — `api/v1/agents.py:148,632-657,342-364` | ~400 queries/s **per open socket** for up to 30 s, while Redis pub/sub already delivers frames | ≥500 ms fallback poll + "steps newer than cursor" single query; pub/sub carries liveness |
| 5 | CRIT | Frontend | Single 894.96 KB min / 264.42 KB gz JS chunk; cytoscape (~440 KB) shipped to `/login` — `App.tsx:26-58`, `vite.config.ts:23-26` (measured) [AR1-tracked] | route-lazy + cytoscape chunk → −65–70% initial JS (entry ~250–300 KB min) | `React.lazy` per route + Suspense + manualChunks; assert ≥2 chunks in build gate |
| 6 | HIGH | DB/API | bcrypt runs inline on the event loop (login, password change, dummy-hash on unknown user) — `core/security.py:138,151`; call sites `auth/login.py:285,289`, `account.py:173-176`, `users.py:204,323` | 200–300 ms full-loop stall per hash; 10 concurrent logins ≈ 2–3 s serialized stall of ALL in-flight requests; password change ≈ 400–600 ms | wrap in `asyncio.to_thread` (pattern exists at `main.py:118`) |
| 7 | HIGH | Platform | Audit hash chain: global `pg_advisory_xact_lock` on one fixed key held across quorum `synchronous_commit` — `services/audit/service.py:309-335,440`; fires on 45+ write paths | hard cluster-wide ceiling ≈ 50–200 audited writes/s regardless of replicas/pods; queue depth linear beyond | deliberate ADR-0038/0042 design; if throughput ever matters: sharded chain keys or async outbox appender |
| 8 | HIGH | Persistence | Interface/route/neighbor upsert: full-table ORM preload + per-row merge — `engines/discovery/persistence.py:126-156` | 10k-route device ≈ 10–40 s + 50–100 MB per re-discovery; 900k-route BGP core → GBs + minutes-to-hours (unusable) | bulk `INSERT ... ON CONFLICT DO UPDATE` over values lists + set-difference delete |
| 9 | HIGH | Neo4j | Every discovery sync = full-estate re-projection (unfiltered 6-table load, MERGE+SET every element, 18 sweep scans) — `workers/tasks/topology.py:144-158`, `projector.py:426-447` | 1-device run on 5k-device estate pays the same ~2M-element write pass as full import | project snapshot-diff (diff engine already exists at `engines/topology/diff.py`); skip unchanged SET |
| 10 | HIGH | Agents/LLM | Supervisor stack (10 agents, 10+ graph compiles, fresh provider client) rebuilt per request — `api/v1/agents.py:300-318,486-491`, `providers.py:199-227` | tens–hundreds ms CPU/request + TCP/TLS handshake per run (no connection reuse to Ollama/Anthropic) | cache compiled graph + client keyed (profile, model), invalidate on settings PATCH |
| 11 | HIGH | Agents/LLM | No timeout/retry/`num_ctx` on any chat model; ReAct history + full tool outputs re-sent every turn, unbounded — `providers.py:199-220`, `framework/base.py:126-137` | wedged Ollama hangs runs indefinitely; 2k-route tool output ≈ 30–60K tokens re-sent per loop turn (silently truncated locally, $0.10+/turn external) | per-call timeout + bounded retries + explicit `num_ctx`; cap/summarize ToolMessages, window history |
| 12 | HIGH | Engines | O(n²) pairwise firewall shadow/redundancy analysis — `engines/security/firewall.py:169-172` | 5k rules ≈ 12.5M pairs ≈ 15–60 s; 20k-rule rulebase ≈ 4–15 min CPU per call | dimension indexing (zone/address/service) to prune candidate predecessors |
| 13 | HIGH | Infra | `backend.Dockerfile` copies `app/` before the single `pip install .` → full PyPI reinstall on any source edit; installs from pyproject, not lockfile — `deploy/docker/backend.Dockerfile:35-37` | ~2–5 min rebuild per code change vs ~10–20 s with cached dep layer; version drift vs `requirements.lock.txt` | lockfile install in early layer, `COPY app` after, `pip install --no-deps .` |
| 14 | HIGH | Infra | Compose cold start gated ~60–90 s by neo4j healthcheck chain the api never touches at boot — `docker-compose.yml:59-65,257-264`, backend healthcheck 30 s interval no start-interval | api could be ready in ~5 s; frontend waits on api's first 30 s probe | api→neo4j `service_started`; `--start-interval=2s` on healthcheck |
| 15 | HIGH | Frontend | ChatPage: one setState per WS frame, index-keyed unmemoized rows → O(N²) row renders during trace replay — `ChatPage.tsx:167-176,257-263` | 100-step replay ≈ 100 full-transcript re-renders (visible jank) | rAF-batched frame buffer + memoized bubble/step components |
| 16 | HIGH | Frontend | TopologyPage: cytoscape destroyed + rebuilt + full O(V+E) layout on every elements identity flip — `TopologyPage.tsx:301-322,554` | multi-second main-thread freeze at few-thousand-node graphs; viewport state lost | persistent cy instance, apply diffs, re-layout only on structural change |
| 17 | HIGH | Neo4j | Var-length undirected traversals path-explode through hub nodes (neighborhood/impact) — `topology_read.py:336-345,513-529` | depth caps hops not fan-out: /24 with 1k members at depth 4–5 → 10^6–10^9 path enumerations for a small answer | NODE_GLOBAL-uniqueness expansion (apoc subgraph) or per-hop frontier |
| 18 | HIGH | Neo4j | `GET /topology/graph`: label-less O(E_total) relationship scan run TWICE per request (count + fetch); site/vrf are post-filters; zero caching despite `projected_at` watermark — `topology_read.py:247-256,390-403`, `api/v1/topology.py:112-119` | every request pays 2× full edge scan regardless of site size; ~50% overhead from count pass | indexed `(:Device {site})` seed + expand; `LIMIT max+1` instead of count pass; ETag/TTL on watermark |

## Quick wins (each ≤ ~1 day, measurable immediately)

1. **bcrypt → `asyncio.to_thread`** (#6) — removes 200–600 ms event-loop stalls on auth paths.
2. **Auto-rebuild staleness gate** (#3) — one condition + one values change kills ~288 idle rebuilds/day.
3. **WS poll 20 ms → ≥500 ms + cursor query** (#4) — >99% reduction in per-socket DB load.
4. **Dockerfile layer order + lockfile install** (#13) — 2–5 min → 10–20 s incremental builds.
5. **Compose `depends_on` + healthcheck start-interval** (#14) — cold start 60–90 s → ~15 s.
6. **Drift check: short-circuit on `content_hash` equality before difflib** (`drift.py:223-231`) — skips whole-config diffs for unchanged snapshots.
7. **Rate limiter: pipeline/Lua the 4 sequential Redis RTTs per authenticated request** (`deps.py:210-211`, `limiter.py:136-150`) — 4 RTTs → 1 on nearly every route.
8. **Route-level `React.lazy` + cytoscape chunk** (#5) — −65–70% initial JS, measured baseline exists.
9. **react-query `staleTime` 5 s → per-domain 30–60 s** (`main.tsx:28`) — stops full-list refetch on every tab hop.
10. **nginx: upstream keepalive + `gzip_comp_level 6`/`gzip_vary`** (`nginx.conf:27-42,76-87`) — kills per-request TCP churn + ~15–20% wire size.
11. **Documentation agent: `asyncio.gather` the 2 serial section LLM calls** (`documentation/tools.py:722-731,1017-1027`) — halves doc-generation wall time on local models.
12. **Guard duplicate `create_app()`** (`main.py:203` vs `--factory` in Dockerfile) — app built twice per boot; also two deploy paths build different objects.

## Structural ceilings (need design, not patches)

- **Audit chain global lock** (#7) — the platform-wide mutation ceiling. Any future throughput requirement forces sharded chains or an async outbox.
- **Full-estate projection** (#9 + #3) — delta projection keyed on run-touched devices; the snapshot-diff engine already exists, it's just unused for projection.
- **Route-table scale path** (#8 + workers H2) — full `show route` held ~3× in memory (raw string + Pydantic list + ORM); 30 s fixed read_timeout fails large tables. Streaming/chunked collect-parse-persist needed before any BGP-core use case.
- **DB pool + process fan-out sizing** — SQLAlchemy defaults (5+10) × api + celery forks vs `max_connections=100`; 16-core host can demand 255 conns. Expose pool/concurrency knobs in Settings (`db.py:123,141`, compose `:91`).
- **LLM caching tiers** (#10, #11 + M2) — compiled-graph/client cache, embedder singleton + LRU (new client per embed call today, `knowledge/embedding.py:115-127`), router intent cache, Anthropic `cache_control` on static prompts (~90% input-cost cut on those segments).

## Focus-dimension coverage

| Requested dimension | Where it landed |
|---|---|
| Unnecessary allocations | route-table 3× materialization (H2 workers); per-edge node property duplication (Neo4j M1); tshark whole-JSON buffer (M3); redaction re-scan per call (LLM M3) |
| Inefficient algorithms | firewall O(n²) (#12); VM×F5 O(V×M) (`app_derivation.py:503-516`); var-length path explosion (#17); difflib full-config (M5) |
| Repeated I/O | supervisor rebuild/request (#10); embedder client per call; compliance R×C regex scans (M4); derivation+projection double table load (Neo4j M3); config pack re-parse |
| Blocking operations | bcrypt (#6); topology diff unbounded JSONB diff on loop (`api/v1/topology.py:225-227`); redaction sync CPU in async nodes |
| N+1 queries | WS trace poll (#4); `_load_traces` REST N+1 (`agents.py:342-364`); app-upsert per-row `session.get` (`app_derivation_store.py:99`); route layer otherwise clean (verified) |
| Excessive API calls | router re-paid per turn, no dedup of identical tool calls, serial doc sections; 2 serial auth RTTs on frontend boot (`main.tsx:17-21`) |
| Caching opportunities | zero LLM-tier caching; topology reads uncached despite watermark; no prompt caching; frontend staleTime + 3-shape device-list keys (L6) |
| Concurrency issues | orchestrator self-blocking (#2); wave barrier stalls (M6: one slow device ≈ +6.5 min/wave); serial doc sections; single-process uvicorn (1 core ceiling) |
| Memory usage | 900k-route ORM blow-up (#8); tshark 1–5 GB JSON; ChatPage unbounded transcript (L5); no compose mem limits (neo4j JVM unbounded); audit_log unbounded growth [AR1 R6] |
| Startup time | measured 2.2 s import (fastapi 1.08 s dominant, heavy deps verified lazy — good posture); compose chain 60–90 s (#14); dup `create_app()`; serial KMS probe + audit write in lifespan |

## Verified non-findings (posture credit)

No loop-awaited queries anywhere in `api/v1`/`services`; settings `lru_cache`d; engines/sessionmakers process-cached with reader fallback; list endpoints capped (sole exception `list_users`); alembic index coverage matches filters incl. `ix_audit_log_seq`; Neo4j writes UNWIND-batched; async Neo4j driver singleton; troubleshooting device I/O correctly `asyncio.to_thread`-offloaded; chunk embedding batched; pgvector HNSW + `<=>` LIMIT correct; alembic not at boot; langgraph/langchain/plugins/netmiko/scapy/neo4j/redis all lazy imports; frontend react-query throughout, selector-only zustand, tables paginated ≤100, correct immutable asset caching; DDI HTTP clients instance-scoped with keepalive.

## Overlap with existing tracking

- **AR1** (`docs/reviews/AR1-REMEDIATION-PLAN.md`): frontend code-splitting (#5, AR-W3-T4), query-hook layer (fixes L6), SettingsPage god file (bundle-only cost — verified not a re-render problem), audit_log unbounded growth (R6), `useAgentStream` (partial vehicle for #15 + ChatPage WS unmount race M2).
- Repo review 2026-07-10: frontend M24 (WS unmount race), M34 (no AbortSignal), M35/M36.

---

# Appendix — full per-layer findings

## A. Backend DB/API layer

### HIGH
**H-1. bcrypt runs inline on the event loop in async auth routes**
`core/security.py:138` (`hashpw`), `:151` (`checkpw`); call sites `api/v1/auth/login.py:285` (dummy-hash equalizer — every unknown-username attempt pays full bcrypt), `:289`; `account.py:173,176` (verify then hash back-to-back ≈ 400–600 ms stall); `users.py:204,323`. Blocks all in-flight requests on the worker incl. SSE streams. Measure: p99 of unrelated GET while looping POST /auth/login. Fix: `asyncio.to_thread`.

**H-2. Global advisory lock serializes every mutating request via audit hash chain**
`services/audit/service.py:440` (fixed `_CHAIN_LOCK_KEY`), `:453-460` head read, `:309,364-399` quorum `synchronous_commit`, lock held to caller commit. 45+ call sites. Ceiling ≈ 1/audited-txn-latency ≈ 50–100 mutations/s cluster-wide at 10–20 ms txns. Measure: `pg_locks` advisory waits under k6 write ramp. Deliberate ADR-0038/0042 design; direction if needed: sharded chain keys or queued chain assignment.

### MEDIUM
**M-1. Engine pool at SQLAlchemy defaults, no knobs** — `db.py:123,141`: 5+10 per process, 30 s checkout timeout, overflow churn amplified by mTLS handshakes; `pool_pre_ping` = +1 RTT per checkout. Fix: Settings fields for both engines.
**M-2. `/topology/diff` loads two unbounded JSONB snapshots, diffs in Python on the loop** — `api/v1/topology.py:225-227`, `:78-80`; `/graph` capped, `/diff` not. Fix: same cap + thread offload.

### LOW
**L-1.** `list_users` unpaginated (`auth/users.py:169`) — sole uncapped list.
**L-2.** `Device.credential` `lazy="joined"` on every device query (`models/inventory.py:201`) — join paid even when unused.
**L-3.** Device list filters status/vendor unindexed (`devices.py:83-84`; only hostname/credential_id indexed in 0001).
**L-4.** OFFSET pagination on append-heavy tables (config_snapshots/agents/virtualization) — O(offset) scan-discard; keyset exists in audit export (`export/cursor.py:60`) but not API lists.

## B. Agents/LLM layer

### CRITICAL
**C1. WS trace stream 50 Hz N+1** — `api/v1/agents.py:148` (0.02 s), `:152` (1500 polls), loop `:632-657`, `_load_traces` `:342-364`: per tick 1 session query + per-trace 2 queries in fresh sessions ≈ 400 q/s/socket with 3 traces, redundant with Redis relay (`:651`). Fix: cursor query + ≥500 ms fallback.

### HIGH
**H1. Supervisor stack rebuilt per request** — `agents.py:300-318,486-491`; `build_default_registry` = 10 agents; `supervisor.py:184-281` compiles supervisor + every specialist subgraph; fresh `ChatOllama`/`ChatAnthropic` per request (`providers.py:199-227`) → no conn reuse. Fix: process-wide cache keyed (profile, model), invalidate on settings PATCH.
**H2. Doc sections generated serially with duplicated context** — `documentation/tools.py:722-731`, `:1017-1027`: independent sections sequential, full facts re-sent each call. Gather → ~½ wall, ~−40% input tokens.
**H3. No timeout/retry/num_ctx on any model** — `providers.py:218-220` (`timeout=None`), `:199-205` (no `num_ctx`/`keep_alive`): wedged provider hangs graph; Ollama default context silently truncates oversized prompts. Fix: explicit timeout + bounded retries + num_ctx.
**H4. Unbounded ReAct prompt growth** — `framework/base.py:126,134-137`: full history + full ToolMessages (inventory CSVs, route JSONs) re-sent every loop turn; 2k routes ≈ 30–60K tokens/turn. Fix: cap/summarize tool outputs, window history.
**H5. Embeddings: new client per call, no cache** — `knowledge/embedding.py:115-127` (client per `embed()`), `:409-410` (query embedded per retrieve), `:335` (no content-hash skip on regenerate). pgvector itself correct (HNSW `0006:179-183`, `<=>` LIMIT `:428-437`). Fix: singleton + LRU on text hash.
**H6. Router re-paid every turn, no cache/short-circuit** — `supervisor.py:198-235`; one-shot session design (`agents.py:453-499`) → every message = full re-route + specialist classifier = 2 LLM RTTs before any tool. Fix: normalized-intent cache + keyword pre-router.

### MEDIUM
**M1. 12–16 sequential trace commits per run** — `framework/traces.py:234-246,249-298,301-308`: per step fresh session + `FOR UPDATE` + `COUNT(*)` + commit + reload, serialized between LLM calls; per-step Redis publish awaited inline (`:405-442`). ≈ 25–80 ms serial/run + lock contention. Fix: in-memory ordinal, batch inserts, drop COUNT.
**M2. No provider prompt caching** — `providers.py:218-227`: static routing/system prompts billed fresh every external call; `cache_control` would cut those segments ~90%.
**M3. Redaction re-scans entire conversation every model call** — `llm/redaction.py:83-273,334+`: 16 regexes × total chars, sync CPU in async nodes, compounds with H4. Fix: memoize per message, redact at append.
**M4. `_load_traces` N+1 on REST paths + duplicate profile queries** — `agents.py:342-364` at `:501,558`; profile queried twice (`:315-316`, `:513-514`). Fix: joined query; reuse resolved profile.

### LOW
**L1.** Structured-output schema re-serialized per call (`providers.py:297-309`); retry doubles prompt (bounded 1, by design).
**L2.** pgvector `ef_search` at default 40, no knob — matters past ~100K chunks.
**L3.** No per-run tool-call memoization — identical (tool, args) within one run pays device I/O twice.

## C. Workers / plugins / engines

### CRITICAL
**C1. SSH session per (credential × vendor) candidate** — `workers/tasks/discovery.py:301-343`: nested cred×vendor loop, full `ConnectHandler` per candidate, ~13 vendors, 5–15 s per wrong driver (`transport/ssh.py:104` conn_timeout 10 s). avg k≈6 → 40–90 s waste/device; 100-device wave ≈ 1.5–2.5 h aggregate. Fix: SSHDetect / order by prior vendor; reuse session (post-detection reuse already exists `:322-327`).
**C2. Orchestrators block own pool** — `discovery.py:566-571`, `config.py:513-521` (`.get(disable_sync_subtasks=False)`); compose one worker all queues no `-c` (`docker-compose.yml:91`). c=1 deadlock; c=2 serial. 100×8 s ≈ 13.3 min vs ~80 s at c=10. Fix: chord/callback or queue split.

### HIGH
**H1. Per-row ORM upsert with full-table preload** — `engines/discovery/persistence.py:126-156,196-227`: SELECT all existing rows as ORM, per-row setattr, row-by-row UPDATE/add. 10k routes ≈ 10–40 s + 50–100 MB; 900k unusable. Fix: bulk ON CONFLICT upsert + set-diff delete (keep SQLite seam).
**H2. Full route-table materialization ×3 + fixed 30 s read_timeout** — `discovery.py:322-327` (Pydantic list + raw_outputs), `persistence.py:68-87` (whole `show route` as ONE RawArtifact row), `ssh.py:105`. 900k ≈ 80–150 MB raw + ~1 GB Pydantic + ~1 GB ORM in one prefork child; large tables timeout or OOM. Fix: per-VRF/protocol streaming, per-capability timeout, artifact segmentation.
**H3. O(n²) firewall pairwise coverage** — `engines/security/firewall.py:169-172` + `_covers` `:142-152`: n²/2 × 6 set comparisons. 5k ≈ 15–60 s; 20k ≈ 4–15 min. Fix: dimension indexing.

### MEDIUM
**M1. Fresh AsyncEngine + conn per task phase** — `discovery.py:129-167` (+clones in config/packet/topology): mTLS handshake 20–80 ms each; 100-device run ≥200 handshakes. Fix: per-worker-process engine.
**M2. O(V×M) VM↔F5 evidence matching** — `engines/topology/app_derivation.py:503-516`: 5k×5k = 25M iters ≈ 10–40 s/derivation. Fix: index evidence by address/fqdn_key.
**M3. tshark whole-JSON buffering** — `engines/packet/executor.py:459,495`: JSON ~20–100× pcap; 50 MB cap (`capture.py:139-140`) → 1–5 GB string; RLIMIT_AS makes near-cap captures fail rather than stream. Fix: `-T ek` NDJSON streaming.
**M4. Per-rule full-config regex compliance scans** — `compliance/engine.py:137-151`: R×C bytes; 200×5 MB = 1 GB/device ≈ 5–20 s; pack YAML re-parsed per load (`loader.py:47-52`). Fix: parse-once line/section index; cache pack.
**M5. Whole-config difflib per drift check** — `drift.py:223-231`: no `content_hash` short-circuit despite hashes on both rows. Fix: hash check first.
**M6. Wave barrier: slowest device stalls wave** — `discovery.py:608-640` + retries `:428-433`: one slow target ≈ 3 × (13 × 10 s) ≈ +6.5 min/wave; retries re-run full C1 sweep. Fix: per-device budget, neighbor-driven expansion.
**M7. One compose worker, all queues, implicit sizing** — `docker-compose.yml:91` (`acks_late`+prefetch-1 correct in `celery_app.py:158-160`). Fix: per-queue workers with explicit `-c`.

### LOW
**L1.** Stale-sweep = full label/rel-type scan per projection (`projector.py:444-447`) — index `projected_at` or sweep by tracked keys.
**L2.** Full re-projection per run (`workers/tasks/topology.py:224,273,304`) — by-design idempotency; delta projection past ~10k nodes. (Same as Neo4j H1.)
**L3.** DDI clients correctly instance-scoped (bluecat/panos/fortios/f5/infoblox/spatiumddi) — verify one client per device-session across capabilities.

## D. Neo4j / topology

### CRITICAL
**C1. Perpetual auto-rebuild loop** — `engines/topology/auto_rebuild.py:80-89` (`age >= staleness`), `values.yaml:414,418` (5-min schedule, 300 s staleness), wipe `projector.py:474-476`: watermark refreshed only by projection → every tick stale again → full DETACH DELETE + reproject ~288×/day idle; readers race wiped graph. Fix: drift-gated rebuild or staleness ≥ 2× period.

### HIGH
**H1. Incremental sync = full-estate re-projection** — `workers/tasks/topology.py:144-158,249-273`, `projector.py:426-447` (+dup loader `rebuild.py:130-136`): O(total rows) hydration + O(N+E) MERGE/SET + 18 sweeps per run, delta-independent; snapshot diff (`engines/topology/diff.py`) unused for projection. Fix: project the diff; skip unchanged SET.
**H2. Path explosion in var-length undirected traversals** — `topology_read.py:336-345` (neighborhood), `:513-529` (impact): relationship-uniqueness path enumeration through hubs (Subnet with 1k members, core mesh) → O(degree^depth) paths for small distinct results; depth ≤5 caps hops not fan-out. Fix: NODE_GLOBAL uniqueness (apoc) or frontier BFS.
**H3. `/topology/graph` label-less O(E) scan ×2 per request** — `topology_read.py:247-256` + count `:390-403`; `api/v1/topology.py:112-119`; no `Device.site` index (`schema.py:121-142` = key constraints only); site/vrf post-filters. Over-cap requests still pay full scan to say 413. Fix: indexed site seed + expand; `LIMIT max+1` fold; drop separate count.

### MEDIUM
**M1. Node property maps shipped per incident edge** — `topology_read.py:252-254` (+ `:341-343`, `:525-527`), Python dedup `:276-296`: wire O(E × prop_size); degree-500 device's props cross Bolt 500×. Fix: distinct nodes once + endpoint keys.
**M2. No caching despite `projected_at` watermark** — `api/v1/topology.py:83-209`; watermark at `topology_read.py:182-189`. Fix: TTL/ETag keyed endpoint+params+watermark.
**M3. Derivation+projection double-load, 3 event loops per task** — `workers/tasks/topology.py:195-224,249-257,328,344,360`: tables ORM-hydrated twice, 3 engine create/dispose cycles. Fix: single loop/engine, load once.
**M4. PG N+1 in application upsert** — `app_derivation_store.py:99` (per-row `session.get`), `:143` (flush in loop), `:154-222` (Python anti-joins). Fix: bulk IN-select, single flush, SQL diff.
**M5. Unbatched DETACH DELETE per label on wipe** — `projector.py:167-168,474-476`: 10^5–10^6 element single transactions risk tx-memory aborts on the recovery path (and per C1 runs constantly). Fix: `CALL {} IN TRANSACTIONS`.

### LOW
**L1.** Freshness probe `max(n.last_projected_at)` = AllNodesScan per tick (`auto_rebuild.py:66-68`) — singleton meta node instead.
**L2.** Autocommit tx per 1000-row batch (~2000+ commits/pass at 5k-device scale), results unconsumed; constraints DDL re-run per pass (`projector.py:431-447`, `topology.py:263`, `schema.py:140-142`) — explicit txs + consume; constraints at startup.
**L3.** Impact co-key join planner-fragile (`topology_read.py:522`) — restructure to `OPTIONAL MATCH (ip:IPAddress {pg_id: n.pg_id})`; confirm NodeIndexSeek via PROFILE.

## E. Frontend

### CRITICAL
**C1. Zero code-splitting; 894.96 KB min / 264.42 KB gz single chunk; cytoscape (~440 KB) to `/login`** [AR1 AR-W3-T4] — `App.tsx:26-58`, `TopologyPage.tsx:22`, `vite.config.ts:23-26`. Route-lazy + cytoscape chunk → −45–50% (topology split alone) to −65–70% (full route lazy). Verify: rollup-plugin-visualizer.

### HIGH
**H1. ChatPage per-frame setState, O(N²) replay renders** [AR1 partial: useAgentStream] — `ChatPage.tsx:167-176,257-263`; stream replays all recorded steps (`:7-8`); per-macrotask messages defeat React batching. Fix: rAF buffer/startTransition + memoized rows.
**H2. TopologyPage cytoscape recreate + full layout per elements flip** — `TopologyPage.tsx:301-322,554`; `topology-graph.ts:201-218` returns fresh arrays → identity flip on refetch AND diff-overlay toggle; viewport lost. Fix: persistent instance + diff application.

### MEDIUM
**M1. Global `staleTime: 5_000`** — `main.tsx:28`: every route remount refires full-list queries (100–500 rows: Applications/Adc/Virtualization/Config). Fix: per-domain 30–60 s.
**M2. ChatPage WS unmount race** [review M24] — `ChatPage.tsx:163-165` vs `:224`: socket assigned after await never closed on fast unmount → orphan socket streams into unmounted setState. Fix: cancelled flag/AbortController.
**M3. No AbortSignal/timeout in api client** [review M34] — `api/client.ts:108-125`: react-query cancellation never reaches fetch; stalled backend pins connection pool. Fix: thread `signal` + `AbortSignal.timeout`.
**M4. Cold start = 2 serial auth RTTs before protected render** — `main.tsx:17-21` (refresh → me). Fix: single boot endpoint or optimistic shell.

### LOW
**L1.** DevicesPage polls whole 20-run list every 3 s while runs active (`DevicesPage.tsx:40,343-354`; stops when idle — correct); Dashboard readiness every 15 s.
**L2.** SettingsPage 1598-line module in entry chunk [AR1 M35] — verified NOT a re-render problem (child routes, section-local state); bundle/parse cost only.
**L3.** nginx gzip level 1, no brotli/gzip_static (`nginx.conf:27-28`): ~+15–20% wire vs gz(6); asset cache headers correct (`:90-103`).
**L4.** No virtualization; all tables ≤100 rows — fine; outlier `ConfigPage.tsx:476` 500-device select → searchable combobox when it grows.
**L5.** ChatPage transcript unbounded incl. full traces (`ChatPage.tsx:157`); stores otherwise clean (toasts evict, selector-only zustand).
**L6.** Device list fetched under 3 distinct query keys/shapes (Config 500 / Devices 100 / Topology) → 3 full downloads; AR1 query-hook layer is the vehicle.

## F. Startup / infra

Measured: `python -X importtime -c "import app.main"` = **2.19 s** total; cumulative fastapi 1.08 s, sqlalchemy 0.42 s, `app.api.v1` 0.42 s, `app.core.crypto` 0.29 s (0.23 s = `app.core.logging`), httpx 0.12 s, oidc 0.12 s. langchain/langgraph/plugins/netmiko/scapy/neo4j/redis NOT on import path (lazy — good). Alembic = explicit one-shot service, not boot. Middleware stack only 3 deep.

### HIGH
**1.** Audit chain global lock (= DB/API H-2, ranked #7 above).
**2. Pool defaults × process fan-out vs max_connections=100** — `db.py:123,141` no knobs; celery no `-c` (`docker-compose.yml:91`): 8-core → up to 135 potential conns, 16-core → 255 → `too many clients` under bursts. Fix: Settings knobs sized `workers × pool ≤ max_connections`, or PgBouncer.
**3. Dockerfile layer-cache defeat** — `backend.Dockerfile:35-37`: COPY app before single `pip install .`; installs from pyproject not lockfile. 2–5 min per code change vs 10–20 s. Fix: lockfile layer first, `--no-deps .` after.
**4. Compose cold start 60–90 s via neo4j health gate** — `docker-compose.yml:59-65,257-264` (start_period 60 s), backend healthcheck 30 s interval no start-interval (`backend.Dockerfile:69`), frontend waits api healthy (`:212-214`). Lifespan never touches neo4j. Fix: `service_started` + `--start-interval=2s`.

### MEDIUM
**5. Rate limiter: 4 sequential Redis RTTs per authenticated request** — `deps.py:210-211` + `limiter.py:136-150` (INCR then TTL/EXPIRE per key, 2 keys, no pipeline). Fix: one Lua/pipelined RTT.
**6. `create_app()` runs twice per boot; two deploy paths differ** — `main.py:203` module-level app + Dockerfile `--factory` (`:72`) vs k8s `app.main:app` (`api-deployment.yaml:52-53`). Fix: guard or standardize entrypoint.
**7. nginx→uvicorn `Connection: close` every non-WS request** — `nginx.conf:39-42,76-87`: no upstream keepalive; TIME_WAIT accumulation. Fix: `upstream api { keepalive 32; }`.
**8. Single-process uvicorn, cpu limit 2, 1 replica default** — `backend.Dockerfile:72` no `--workers`; `values.yaml:218,228-234`; HPA opt-in. One event loop ≈ one core; bcrypt/serialization saturate 1 core while 2nd idles. Fix: 2 workers/pod (mind in-memory fallbacks) or default HPA.
**9. No compose resource limits on neo4j/postgres/api/worker** — only packet-analysis bounded (`docker-compose.yml:183-188`): neo4j JVM grabs 2–4 GB unconstrained → swap/OOM cascade on dev hosts. Fix: heap env + mem_limit/cpus.

### LOW
**10.** Duplicate JWT decode + per-request user SELECT (`deps.py:193,276-283`) — share claims via `request.state`, optional short-TTL user cache.
**11.** `pool_pre_ping` +1 RTT per checkout (`db.py:123,141`) — benchmark vs `pool_recycle` once pools explicit.
**12.** Boot-serial KMS probe then audit write (`main.py:118,141-143`) ≈ +0.2–2 s — overlap the awaits.
**13.** 2 `BaseHTTPMiddleware` wrappers (request-id, metrics; `main.py:176,194`) ≈ 100–200 µs/req each, blocks streaming pass-through — pure-ASGI.
**14.** `celery inspect ping` healthchecks fork full interpreter every 30 s ×2 containers (`docker-compose.yml:103-108,195-200`) — file heartbeat.
**15.** Readiness probe builds fresh Neo4j driver per poll (`health.py:88`) — cache probe driver.
**16.** Shared Redis client unbounded `max_connections` (`main.py:71`) — cap in settings.
**17.** nginx gzip incomplete (no vary/comp_level/min_length; JSON via proxy uncompressed unless upstream compresses) — `nginx.conf:27-28`.
**18.** `proxy_read_timeout 300s` on WS path (`nginx.conf:86`): idle agent sockets >5 min between frames get cut → reconnect churn — longer WS timeout or app pings <300 s.
