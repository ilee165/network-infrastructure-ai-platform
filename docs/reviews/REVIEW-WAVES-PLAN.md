# Review Remediation Waves — Consolidated Plan (2026-07-11)

Consolidated 7-wave remediation plan synthesized from the four 2026-07-10 review
documents in this directory:

- [`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) — full-repo review (6 CRITICAL / 14 HIGH / 47 MEDIUM / 13 LOW)
- [`PERF-REVIEW-2026-07-10.md`](PERF-REVIEW-2026-07-10.md) — performance review (18 ranked findings)
- [`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md) — testing strategy (F1–F9)
- [`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) — architecture remediation track (AR-W0…W4)

Finding IDs below refer to those documents. This track is **separate from P4**
(W3–W5 pending); it does not replace or reorder P4. Discipline follows
AR1 §0: one PR per wave, atomic commit per task, every new CI gate must prove
it bites (plant violation → RED → revert → GREEN, run URLs in PR body),
lockfiles regenerated in the same commit as any dependency addition.

Resolved conflicts / standing decisions from the planning session:

- SettingsPage split **deferred** (opportunistic policy, per AR1).
- Audit advisory-lock write ceiling: **no action** this track (design-level; retention ADR in Wave 7 is the venue).
- HA-defaults flip stays **rejected** (ADR-0048); ship documented `values-prod-ha.yaml` profile instead.
- Microservice split and router-prefix renames stay rejected.

Local PG verification: `docker run pgvector/pgvector:pg16` with
`NETOPS_TEST_DATABASE_URL=postgresql+asyncpg://netops:netops@127.0.0.1:55432/netops_test`
(plain `postgres:16` lacks the `vector` extension the migrations need).

---

## Wave 1 — Ship-stoppers + partition time bomb ✅ DONE

**PR #140, merged to main 2026-07-11 (squash `8eec70d`).** 6 atomic commits.

| ID | Fix |
|----|-----|
| C1 | Forced-password-change guard was dead code — `require_role` now routes through `get_active_user`; escape hatches preserved |
| C4 | Approved CR no longer stranded in `executing` on finalize exception (state-aware salvage, exception text scrubbed) |
| C5 | `sentinel://` HA URL supported in API; Sentinel coordinates wired (Redis HA tier no longer crashes pod at boot) |
| C6 | Helm renders real LLM Settings keys; in-cluster Ollama default matches the chart Service |
| H4 | Monthly-partition pre-creation beat task for the four partitioned tables (partitions previously ended `2026_07`) |
| F1 | `tests/pg/test_refresh_reuse.py` lit up (pg marker) + pg-integration job fails on deselection |

Verified: 3672 unit + 63 pg-integration green. F1's previously-dark tests
failed on first real run (MissingGreenlet) — fixed in-wave.

## Wave 2 — Small bugs + perf quick wins

Point fixes, each independently committable; one PR.

- **H1** — `devices.py` mgmt_ip unique-race returns 500 → map to 409.
- **H5** — firewall management-plane exposure check misses `services=("any",)`.
- **H6** — topology auto-rebuild steady-state ticks force edge gauge to 0.
- **H13** — agent tool exception `detail` bypasses the A9 redaction chokepoint.
- **H14** — `DiscoveryRunStatus` missing backend `"partial"` (FE enum drift).
- **Perf: bcrypt off the event loop** (perf H-1 / repo H2) — `asyncio.to_thread` on hash/verify in login, password change, dummy-hash path.
- **Perf: WS trace-stream 50 Hz N+1 poll** (perf #4 CRIT) — ≥500 ms fallback poll + steps-newer-than-cursor single query; Redis pub/sub carries liveness.
- **Perf: auto-rebuild perpetual full re-projection** (perf #3 CRIT) — gate on drift watermark or staleness ≥ 2× schedule period.
- **H9** — spatiumddi shared `httpx.AsyncClient` across per-call `asyncio.run()` loops.
- **H10** — packet capture tasks not idempotent under redelivery; false queue-rationale comment.
- **H11** — fail-closed KEK audit helper triplicated and drifted — unify.
- **FE M24** — ChatPage socket assigned after `await` post-unmount (leak).
- **FE M34** — API client gains `AbortSignal`/timeout support.
- **CI: Node 22 + SHA-pin actions** (part of F9).
- **F2** — frontend coverage measurement (coverage-v8 + CI threshold).
- **F6** — `pytest-timeout` + de-sleep the two real-clock `sleep(5)` tests.

## Wave 3 — Config-write transport (secret/change-safety surface — STRONG model)

- **C2** — JunOS `commit confirmed` documented but never issued; JunOS config writes are effectively no-ops. Implement real confirmed-commit flow.
- **C3** — unescaped config text interpolated into Tcl string corrupts `replace_config` staging — escape/quote properly.
- **H7** — SSH host keys never verified — introduce known-hosts/TOFU policy.
- **AR-W2-T1** — extract `plugins/vendors/cli_common/` shared lifecycle mixin + textfsm helpers (repo H8: ADR-0021 write engine copy-pasted 5×). One vendor per atomic commit: base → cisco_ios → eos → cisco_nxos → junos; 35 parity/plugin test files stay green **unchanged** per commit; behavioral divergence between copies is a finding, not a silent unification. Must land before any new CLI vendor wave.

## Wave 4 — Drift gates (AR-W0 / AR-W1)

- **AR-W0-T1** — import-linter layer stack contract in `backend/pyproject.toml` (`api|workers` → `services|engines|agents` → `plugins|knowledge|llm` → `schemas|models|db` → `core`). Bite proof required.
- **Config-contract gate** — `.env.example` ↔ `Settings` drift check (repo H3: 19 documented vars vs ~82 fields; header claims 1:1). Covers F3's config seam.
- **AR-W1-T2 — OpenAPI→TS codegen** — deterministic spec export (`backend/scripts/export_openapi.py`), `openapi-typescript` dev-dep, adopt for `devices` + `applications` modules; CI `contract-drift` job regenerates and diffs; bite proof = planted enum mismatch → RED. Sweep sibling `vi.mock`s (L-FE-1). Structurally prevents the H14 class.
- **F3** — contract tests for remaining test-blind seams where the repo-review CRITICALs lived.

## Wave 5 — Perf/scale point fixes

From `PERF-REVIEW-2026-07-10.md` ranked list (excluding items shipped in W2):

- **Perf #1 CRIT** — vendor-detection SSH churn: fresh session per (credential × vendor) candidate, ~40–90 s wasted per device. In-session autodetect (`SSHDetect`) or candidate ordering by prior vendor/sysDescr; reuse session for collection.
- **Perf #2 CRIT / repo H12** — orchestrators block their own worker pool (`.get(disable_sync_subtasks=False)`): chord/callback or dedicated orchestrator queue + per-queue concurrency.
- **Perf #5 CRIT** — 895 KB single JS chunk; cytoscape shipped to `/login`: `React.lazy` per route + `manualChunks`; build gate asserts ≥2 chunks. (AR1-tracked.)
- **Neo4j full-estate re-projection per discovery sync** (perf #9) — snapshot-diff projection (diff engine exists at `engines/topology/diff.py`).
- **Per-row ORM upsert with full-table preload** (perf workers H1) — bulk `INSERT ... ON CONFLICT` + set-difference delete.
- **Supervisor stack rebuilt per request** (perf agents H1) + embeddings client-per-call (H5) + router re-paid every turn (H6) — process-wide caches.
- **ChatPage O(N²) replay renders / TopologyPage cytoscape rebuild** (perf #15/#16) — rAF-batched buffer + memoized components.
- Remaining perf quick-wins from §"Quick wins" as capacity allows.

## Wave 6 — FE platform kit + read-facade

Coordinate scheduling with P4-W3 (compliance reporting UI) to avoid churn.

- FE shared primitives + React Query hook layer (AR-W3 scope).
- **F5** — shared frontend mock factory + QueryClient test wrapper — structurally ends the L-FE-1 class.
- Route-level lazy loading if not landed in Wave 5.
- Router ORM-write extraction, worst 3 routers (partial AR risk R1) — read-facade so agents/routers stop holding raw DB sessions directly.

## Wave 7 — Retention ADR + integration CI + CI decomposition

- **Retention/partitioning ADR** (AR risk R6, design-only) — unbounded append-only growth of hash-chained `audit_log`, traces, snapshots; chain blocks naive pruning. Venue for the audit advisory-lock ceiling discussion.
- **F4** — Neo4j + Redis pytest integration CI job (largest remaining integration blind spot).
- **AR-W4-T2 — CI decomposition** (AR risk R7) — split the 2,449-line `ci.yml` into composite actions; schedule **last**, when no other wave is adding jobs.
- **F9 remainder** — checksum kubeconform/kube-linter downloads, bounded retries on egress-dependent steps.
- **F7/F8** as capacity allows — REST vendor client error-path fixtures (shared parametrized MockTransport); coverage-gate semantics.

---

## Dependency notes

- Wave 3 must precede any new CLI vendor work (cli_common extraction).
- Wave 4's codegen gate should land before Wave 6's FE refactors (types first, then hooks).
- Wave 7's CI decomposition goes last — no other wave may be adding CI jobs concurrently.
- Run `graphify update .` after each wave.

## Status

| Wave | Status |
|------|--------|
| 1 | ✅ Merged (PR #140, 2026-07-11) |
| 2 | 🔄 In progress on `fix/review-wave2` — all 16 tasks implemented (T1–T16) |
| 3–7 | Pending — user calls each wave |
