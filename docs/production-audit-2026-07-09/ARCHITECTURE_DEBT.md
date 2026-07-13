# Architecture Debt & Developer Experience

Production readiness audit, 2026-07-09 (HEAD `5403c3b`). Backend ~3589 unit tests; frontend 461. Items that tax future change more than they break today.

---

## 1. README phase status and migration head are stale

- **Severity:** High (DX / onboarding honesty)
- **Location:** `README.md:5` (status still “P1 in progress” + Vendor Wave 1 NX-OS/JunOS/BlueCat); `README.md:37` (migrations `0001`→`0010`; tree head is `0018_p4_application_dependency_topology`)
- **Root cause:** Status banner not updated through P2 exit, P3 exit, P4 W1–W2. Migration wording hard-coded a past ceiling.
- **User impact:** New contributors and operators mis-judge maturity and first-run schema steps.
- **Proposed fix:** Rewrite status to MVP complete + P3 exited + P4 in progress (W1–W2 landed, W3 reporting pending); say `alembic upgrade head` without a stale numeric ceiling; mention F5/VMware plugins + Applications.
- **Effort:** S | **Risk:** None

---

## 2. `pg-test-routing` still advisory

- **Severity:** Medium
- **Location:** `.github/workflows/ci.yml` (`pg-test-routing` not in `all-gates` needs); `backend/tests/pg/README.md`; `ci/scripts/check-pg-test-routing.sh`
- **Root cause:** Wave 3 introduced the heuristic as advisory during a false-positive soak; promotion (~2026-07-10 target in IMPLEMENTATION_WAVES) not flipped.
- **User impact:** New PG-semantic code can land without `tests/pg/` and only surface as a non-blocking signal.
- **Proposed fix:** Review soak false-positive rate; add job to `all-gates` needs when ready.
- **Effort:** S | **Risk:** Low (false positives)

---

## 3. Monolithic `ci.yml`

- **Severity:** Medium (DX)
- **Location:** `.github/workflows/ci.yml` (backend, frontend, security-scan, docker, docker-publish, infra, kind-harness*, drills, kms-emulators, pg-integration, packet bite-proof, lockfile, observability, pg-test-routing, all-gates, …)
- **Root cause:** Every phase appended gates to one file. Gate graph is sound; review/conflict cost is high.
- **Proposed fix:** Keep `all-gates` as single required check; document job map in CONTRIBUTING or a short CI README; optional later path-filtered splits.
- **Effort:** M | **Risk:** Low

---

## 4. P4 plan / PRODUCTION header markers lag as-built

- **Severity:** Medium (process docs)
- **Location:** `docs/roadmap/P4-PLAN.md` (still “W0 not started” in header while W1–W2 code exists); `PRODUCTION.md` header still “Draft v0.1”
- **Root cause:** Design docs not re-stamped after implementation waves.
- **Proposed fix:** Bump P4 status to in-progress with W1–W2 complete / W3 pending; refresh PRODUCTION status line (body markers remain authoritative).
- **Effort:** S | **Risk:** None

---

## 5. Unbounded secondary list endpoints

- **Severity:** Medium
- **Location examples:**
  - `applications.py` GET `/{id}/dependencies` — all rows
  - `devices.py` interfaces / neighbors — full list
  - `auth/users.py` GET `/users` — all users
- **Root cause:** Primary inventory lists paginate (`limit ≤ 500`); nested or admin lists do not.
- **Proposed fix:** Cap or paginate; update UI assumptions.
- **Effort:** S–M | **Risk:** Low–Medium for client shapes

---

## 6. JWT access tokens HS256 + no aud/iss pin

- **Severity:** Low (architecture debt; ADR-0010)
- **Location:** `backend/app/core/security.py`
- **Root cause:** Symmetric shared secret; refresh path is stronger (stateful jti). Compromised API secret forges roles.
- **Proposed fix:** Long-term RS256/ES256 + rotation; short-term enforce prod secret strength (already partially gated).
- **Effort:** L | **Risk:** High if done poorly

---

## 7. Frontend production bundle size

- **Severity:** Low → **CLOSED (Wave 5 T10)** on `fix/review-wave5`
- **Location:** was single ~895 kB JS chunk; now entry ~23 kB + vendor ~252 kB + cytoscape ~443 kB + per-route chunks
- **Fix shipped:** `React.lazy` routes + `manualChunks` + CI `check:chunks` gate

---

## 8. Wave 5 deferred structural ceilings (provenance: WAVE5-PLAN)

Explicitly **not** fixed in Wave 5 point-fix wave — record here so they do not evaporate.

### 8a. Audit chain global lock (#7)

- **Severity:** Medium (throughput ceiling, deliberate design)
- **Location:** audit write path / ADR-0038 + ADR-0042
- **Root cause:** Global advisory lock for hash-chain integrity
- **Proposed fix:** Sharded keys / async outbox only if a real throughput requirement materializes; Wave 7 retention ADR is the venue
- **Effort:** L | **Risk:** High (correctness)

### 8b. Route-table streaming + BGP bulk path (#8 memory / workers H2)

- **Severity:** Medium (memory triple-hold + fixed read_timeout on large route tables)
- **Location:** discovery collection / persistence of large BGP tables
- **Root cause:** Collect-parse-persist holds full tables in memory
- **Proposed fix:** Streaming design before any BGP-core use case; bulk upsert half shipped as Wave 5 T3
- **Effort:** L | **Risk:** Medium

### 8c. Anthropic `cache_control` + router intent cache (agents M2/H6)

- **Severity:** Low–Medium (token cost)
- **Location:** agent prompts / supervisor router
- **Root cause:** Full prompts re-paid every turn; no provider prompt cache
- **Proposed fix:** Needs eval re-run to prove no routing regression; agents-focused follow-up
- **Effort:** M | **Risk:** Medium (routing quality)

### 8d. Wave 5 T4 delta path GC

- **Severity:** Low (deferred GC)
- **Location:** `project(..., stale_sweep=False)` on discovery-sync delta path
- **Root cause:** Scoped projection skips estate-wide stale sweep so untouched devices are never wiped; removed interfaces on a *touched* device also wait for full rebuild GC
- **Proposed fix:** Scoped stale sweep by device keys (Option A) or rely on periodic auto-rebuild / manual rebuild (current)
- **Effort:** M | **Risk:** Medium

### 8e. Embedding rows carry no model identity — in an unwired pipeline (PR #161 review)

- **Severity:** Low **today**, Medium **the day RAG is wired** (see 8f — nothing calls this pipeline at runtime, so the degradation cannot currently occur)
- **Location:** `embeddings` table / `app/knowledge/embedding.py` content-hash skip
- **Root cause:** `Embedding` rows persist only `(document_id, chunk_index, chunk_text, embedding)`; the regenerate skip compares chunk *texts*, so after an embedding-model/profile switch unchanged documents would keep serving old-space vectors — `EMBEDDING_DIM` stays 768 across many models, so nothing errors
- **Mitigation shipped (PR #161):** query-LRU keyed by (model, base_url); `clear_embedder_caches()` wired into the settings-PATCH invalidation; `embed_document(force=True)` bypass + docstring warning
- **Blocking condition:** the migration below is a **prerequisite for wiring RAG**, not a follow-up to it — wiring first would start accumulating model-blind vectors
- **Proposed fix:** migration adding `embeddings.model` (or profile) column, included in the skip condition and the retrieval filter
- **Effort:** M (migration + backfill decision) | **Risk:** Low

### 8f. The RAG pipeline has no production caller (PR #161 review)

- **Severity:** Medium (dead subsystem carrying live maintenance + review cost; docstring asserts a caller that does not exist)
- **Location:** `app/knowledge/embedding.py` — `embed_document`, `retrieve`, `OllamaEmbedder`, the query LRU, the content-hash skip
- **Root cause:** Nothing in `backend/app` calls `embed_document` or `retrieve`. They are exported from `app.knowledge.__init__` and exercised only by unit tests + the M4/RAG eval suites. The Documentation Agent has **no** retrieval tool (`agents/documentation/tools.py` contains no RAG wrapper), contradicting the module docstring's claim that `retrieve` "is the service-layer core the agent-facing typed tool wrapper (shipped with the Documentation Agent) calls" (ADR-0019 §6). The sole runtime import of the module is `clear_embedder_caches()` from the settings-PATCH invalidation path.
- **Consequences:** (a) ADR-0019's "cite a platform-generated artifact" capability is not actually reachable by any agent; (b) Wave 5's H5 query-LRU optimizes a path that never executes; (c) review effort (two CodeRabbit findings on this PR) is being spent on unreachable code; (d) §8e's corruption scenario is latent, not live.
- **Proposed fix:** decide the subsystem's fate explicitly — either **wire it** (add the Documentation Agent retrieval tool + an embed-on-generate hook, doing the §8e migration *first*), or **retire it** (drop the module, the `embeddings` table, and the pgvector dependency) — and correct the docstring either way. Do not leave it half-shipped.
- **Effort:** M (wire) / S (retire) | **Risk:** Low — nothing depends on it today

---

## Closed since 2026-07-01

| Prior debt | Status |
|---|---|
| Packet opt-in default vs ADR-0031 | **CLOSED** — ADR-0049 executor-split |
| FastAPI `<0.137` upper pin | **CLOSED** — lifted |
| Monolithic `auth.py` (~1.5k LOC) | **CLOSED** — package split |
| Topology unbounded full-graph UI | **CLOSED** — scoped reads + `topology_max_nodes` 413 (Wave 5) |
| Shared UI primitives missing | **CLOSED** — Wave 4 components |
| Frontend single ~895 kB chunk | **CLOSED** — Wave 5 T10 lazy + cytoscape split |

---

## SQLite vs PG posture (ongoing)

- Unit suite: aiosqlite, no external services — correct for speed.
- PG layer: `tests/pg/` covers refresh reuse, applications concurrency/tagging/derivation, audit/credentials, etc.
- Residual risk remains for any new PG-only SQL that only gets SQLite unit tests until `pg-test-routing` blocks.

---

## Strengths

- Import-linter module-boundary contracts kept.
- Dual lockfiles + CI drift gate.
- pip-audit / npm-audit / gitleaks / Trivy / SBOM / cosign publish path.
- Zero TODO/FIXME scatter in `backend/app` and `frontend/src` — debt lives in docs/ADRs.
- P4 plugins follow documented secret-redaction patterns (name-mangled slots, typed PluginError, conformance leak tests).
