# Implementation Waves — Remediation Plan from the 2026-07-01 Audit

Derived from [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md) and its companion reports. Five waves, risk-ordered per the remediation brief; every wave stays under 20 changed files.

> **Execution status (2026-07-04):** All five waves are merged. W1 → PR #90 (2026-07-02); W2 → PRs #93/#94/#95 (2026-07-02/03, item 7 dropped per ADR-0048 Rejection); W3 → PR #108 (2026-07-03, which also carried the out-of-wave packet executor-split); W4 → PR #109 (2026-07-04, all five items landed in the one squash `c87d79c` — the commit subject names only the primitives); W5 → PR #110 (2026-07-04, `05dd460`). The 2026-07-01 remediation plan is complete. One deferred success criterion remains: the W3 `pg-test-routing` gate is advisory pending its false-positive soak — promote to blocking ~2026-07-10. Per-wave annotations below.

Conventions: one atomic commit per task (repo standing discipline); every wave ends with the full gate set green (`ruff check . && ruff format --check . && mypy && lint-imports`, `pytest`, `vitest/eslint/tsc`, plus wave-specific gates). Rollback unit = the task's atomic commit (`git revert`), never `reset --hard`.

> **Note on Wave 1 scope:** the audit found **zero Critical-severity issues**. Wave 1 therefore holds the highest-risk *actual bugs* (broken feature, resource leak, production race) rather than an empty "critical" bucket.

---

## Wave 1 — Broken-behavior bug fixes — ✅ DONE (2026-07-02, PR #90)

**Goal:** Every shipped feature actually works: live troubleshooting reads return device data, the app shuts down cleanly, and the cross-replica WebSocket relay is deterministic (flake retired for real).

**Work items (audit refs):**
1. Wire credentialed transport into Troubleshooting Agent live reads (FUNCTIONAL_BUGS #1) — mirror the `workers/tasks/discovery.py` credential→transport→instantiate pattern; regression test asserting the "not yet wired" sentinel can never be returned.
2. Close the shared Redis client (+ fan-out subscribers) in lifespan shutdown (FUNCTIONAL_BUGS #3); delete the stale M1/M2 placeholder comments while in the file (FUNCTIONAL_BUGS #6).
3. Real fix for the WS fan-out terminal-event race (FUNCTIONAL_BUGS #2) — sequence/watermark reconciliation between Redis pub/sub frames and DB replay; de-flake `test_live_frame_published_by_another_replica_is_relayed`.

**Files affected (~10):**
- `backend/app/agents/troubleshooting/tools.py`
- `backend/tests/agents/test_troubleshooting_tools.py` (extend) + 1 new live-read wiring test module
- `backend/app/main.py`
- `backend/tests/test_main_lifespan.py` (or existing lifespan test home)
- `backend/app/services/agent_stream/` (fan-out + ticket/replay modules, 2–3 files)
- `backend/app/api/v1/agents.py` (WS handler, only if the reconciliation lands there)
- `backend/tests/api/test_agents.py`

**Dependencies:** none — first wave by design. Item 1 touches the credential surface → strong-model/security review required (repo policy).

**Test plan:**
- New: wired live-read tests (mock transport asserting credential resolution + `to_thread` execution); sentinel-regression test; deterministic relay test run under repetition (`pytest -q --count`-style loop or seeded race harness) to prove the flake is gone, not lucky.
- Existing: full `pytest` (2,789), `pg-integration` job untouched but must stay green.
- Live: compose up → Chat page → ask Troubleshooting Agent for live BGP peers against a lab/mock device → real data or a *credential*-shaped error, never "not yet wired".

**Rollback plan:** each item is one revertible commit. Item 3's relay change is the only behavioral risk to streaming; if regression appears post-merge, revert that single commit — the known flake returns (documented, tolerable) while rework happens.

**Success criteria:**
- Zero occurrences of "not yet wired" reachable in code or responses.
- WS relay test green across 50 consecutive local runs and 5 CI runs; flake memo (`ws-fanout-relay-test-flaky`) retired.
- Graceful shutdown emits no unclosed-connection warnings; Redis `CLIENT LIST` count returns to baseline after api stop.

---

## Wave 2 — Functional & security improvements — ✅ DONE (2026-07-02/03, PRs #93/#94/#95; item 7 dropped)

**Goal:** Close the exploitable/user-visible hardening gaps: render-crash safety net, refresh-token theft detection (with its frontend prerequisite), secure-by-default quickstart, and live enforcement gates that actually block.

**Work items (audit refs):**
1. App-level React ErrorBoundary + per-route fallback (UI_UX #1) — placed here, not Wave 4: it is a resilience control, not polish.
2. Single-flight refresh guard in `apiFetch` (FUNCTIONAL_BUGS #4) — **must merge before item 3.**
3. Refresh-token reuse detection (PRODUCTION_READINESS #5): persist current `jti` on `refresh_sessions`, stale-`jti` refresh revokes the session + audit event; migration `0015`.
4. Security headers in base `deploy/docker/nginx.conf` (PRODUCTION_READINESS #4) — CSP starts `Report-Only`, flipped to enforcing after smoke.
5. Tighten CORS to enumerated methods/headers (PRODUCTION_READINESS #9).
6. Pin compose data-tier image tags (PRODUCTION_READINESS #8).
7. ~~Execute the held W4-T2 bite proof and promote the live kind-harness gates.~~ **DROPPED (2026-07-03, audit-W2 T7 — ADR-0048 Rejected):** the live kind harness cannot reach green without booting a slice of the whole platform in kind, and the two controls are already protected by blocking static gates; the live jobs are now opt-in (`ci-kind` label / manual dispatch). See ADR-0048 "Rejection" (PRODUCTION_READINESS #1 → WONTFIX).

**Files affected (~16):**
- `frontend/src/components/ErrorBoundary.tsx` (new), `frontend/src/App.tsx`, `frontend/src/__tests__/ErrorBoundary.test.tsx` (new)
- `frontend/src/api/client.ts`, `frontend/src/__tests__/api-client.test.ts`
- `backend/app/api/v1/auth.py`, `backend/app/models/identity.py`, `backend/alembic/versions/0015_refresh_jti_reuse_detection.py` (new)
- `backend/tests/api/test_auth_refresh.py` (extend), `backend/tests/pg/test_refresh_reuse.py` (new — PG semantics per the tests/pg routing rule)
- `deploy/docker/nginx.conf`
- `backend/app/main.py` (CORS lists)
- `deploy/docker/docker-compose.yml` (tag pins)
- `.github/workflows/ci.yml` (gate promotion)

**Dependencies:** Wave 1 merged (both touch `main.py` and `test_agents.py`-adjacent surfaces). Internal ordering: item 2 → item 3 (parallel legitimate refreshes would otherwise trip reuse detection); item 7 requires one red-proof CI run (plant violation → job fails → revert) before the promotion commit merges.

**Test plan:**
- Reuse detection: unit (stale `jti` → 401 + session revoked + audit row), PG-backed test in `tests/pg/`, concurrency test (two rapid refreshes with single-flight active → no false revocation).
- ErrorBoundary: render-throw test → fallback visible, navigation intact.
- Headers: compose up → `curl -I` asserts header set; SPA + `/api/` proxy + WS ticket flow smoke under CSP Report-Only; check console for violation reports before enforcing.
- Gate promotion: documented red→green bite-proof evidence attached to the PR (repo discipline: gate must RUN and BITE).
- Full backend + frontend suites; `pg-integration` green.

**Rollback plan:** items 1–6 independently revertible. Migration `0015` is additive (nullable column) — code revert leaves a harmless column; no down-migration needed in an emergency. CSP: flip enforcing → Report-Only via one-line nginx change. Item 7 rollback = restore `continue-on-error` (explicitly logged as a readiness regression in `PRODUCTION.md` if taken).

**Success criteria:**
- Stolen-refresh replay (stale `jti`) terminates the session within one request and produces an audit event.
- Quickstart `curl -I` shows nosniff/frame/referrer/CSP headers; no CSP violations in the 5 core pages.
- mTLS-handshake, collector-egress-deny, and HA bring-up failures **fail CI** (bite proof evidence recorded).
- Forced render error shows fallback UI, not a blank page.

---

## Wave 3 — Architecture cleanup — ✅ DONE (2026-07-03, PR #108)

> **Completed 2026-07-03** (PR #108; self-review in [wave3/PR_REVIEW.md](wave3/PR_REVIEW.md)). All five items landed. Deviations from plan: the auth split shipped as an `api/v1/auth/` *package* (`_shared`/`login`/`oidc`/`account`/`users`/`settings`, largest 468 LOC) rather than the sibling modules sketched below, and item 3 went further than "decision only" — ADR-0049 was Accepted after dual-strong review and the executor-split **implementation** shipped in the same PR (see out-of-wave table). One success criterion remains open: `pg-test-routing` is **advisory** pending its one-week false-positive soak; promote to blocking (one-line `all-gates` `needs` edit) ~2026-07-10. Note: the PR squash-merged Wave 3 together with the packet implementation into one commit (`a8ee95c`), so the per-item rollback plan below is not executable for this wave as merged.

**Goal:** Shrink the highest-risk review surfaces and retire tracked debt: auth module split, fastapi unpin, packet-analysis design decision on paper, PG-test routing enforcement, doc-drift fixes.

**Work items (audit refs):**
1. Split `api/v1/auth.py` (1,548 LOC) into `auth_login` / `auth_tokens` / `auth_oidc` / `users` + shared helpers; router prefix stable; pure motion (ARCH_DEBT #4). **After** Wave 2 item 3 so security changes don't rebase across the split.
2. Lift the `fastapi<0.137` cap: adapt route-introspection tests to the 0.137+ router model, refresh lockfile (ARCH_DEBT #3).
3. Packet-analysis resolution **ADR** (ARCH_DEBT #1): decide executor-split (sandboxed capture child) vs. superseding ADR with compensating controls. Decision document only — implementation is deliberately out-of-wave (see Backlog).
4. PG-test routing enforcement: policy in `backend/tests/pg/README` + CI heuristic step flagging PG-semantic diffs (`postgresql_where`, `SET LOCAL`, advisory locks, partition DDL) without matching `tests/pg/` changes (ARCH_DEBT #2).
5. Fix operating-fact drift: `CLAUDE.md` migration range et al. (ARCH_DEBT #8).

**Files affected (~16):**
- `backend/app/api/v1/auth.py` (shrinks to re-export or removed), + 4–5 new modules under `backend/app/api/v1/`
- `backend/app/api/v1/__init__.py` (router wiring)
- Test import updates (~3 files, mechanical)
- `backend/pyproject.toml`, `backend/requirements.lock.txt`, route-introspection test module
- `docs/adr/0049-packet-analysis-sandbox-resolution.md` (new; number = next free)
- `backend/tests/pg/README.md`, `ci/scripts/check-pg-test-routing.sh` (new) + `ci.yml` step
- `CLAUDE.md`

**Dependencies:** Wave 2 merged (auth.py content final before motion). Item 2 independent. Item 3's ADR gates the future packet implementation, nothing in-wave.

**Test plan:**
- Auth split: zero-behavior-change bar — full auth test suite green with only import-path edits; `lint-imports` module-boundary contract green; OpenAPI schema diff empty (route inventory identical before/after).
- fastapi unpin: full suite on 0.137+; smoke the versioned router + problem-details rendering; lockfile gate green.
- PG heuristic: prove it bites — synthetic diff with `SET LOCAL` and no `tests/pg/` change → step fails.
- ADR: dual-strong review (secret/security-adjacent design per repo policy).

**Rollback plan:** auth split is one commit — clean revert. fastapi unpin revert = restore cap + lockfile (both in one commit). Heuristic step ships non-blocking for one week of signal, then flips blocking (rollback = flip back).

**Success criteria:**
- No auth module >600 LOC; route inventory + OpenAPI schema byte-identical.
- CI on fastapi ≥0.137; cap removed from `pyproject.toml`.
- ADR-0049 Accepted-or-Proposed with a named implementation owner/wave.
- PG-routing step demonstrated red on synthetic violation, then blocking.

---

## Wave 4 — UI/UX polish — ✅ MERGED 2026-07-04 (PR #109, squash `c87d79c` — all five items)

**Goal:** Shared component vocabulary, responsive baseline, enforced a11y floor, perceived-performance polish — concentrated on the five highest-traffic pages.

**Work items (audit refs):**
1. Extract shared primitives: `StatusPill`, `ErrorBanner` (ApiError-aware), `FormField`, `Skeleton`/`Spinner` (UI_UX #3, #7).
2. Responsive baseline: collapsible sidebar below `lg:`, `overflow-x-auto` table wrappers (UI_UX #2).
3. A11y floor: `eslint-plugin-jsx-a11y` (recommended, blocking), label associations on Login/ChangePassword, `aria-expanded` + keyboard toggle on expandable rows, text/icon beside color on status pills (UI_UX #5).
4. Loading/motion pass: skeleton table rows, mutation spinners, 150 ms expand transitions, `prefers-reduced-motion` respected (UI_UX #4).
5. Toast channel on the existing `ui.ts` store + portal in `Layout`; route mutation outcomes through it (UI_UX #6).

**Scope control:** shared-component adoption limited to **five pages** this wave (Login, ChangePassword, Devices, Dashboard, Changes). Remaining pages adopt opportunistically in later touches — full-fleet adoption would bust the file budget.

**Files affected (~19):**
- `frontend/src/components/`: `StatusPill.tsx`, `ErrorBanner.tsx`, `FormField.tsx`, `Skeleton.tsx`, `Toaster.tsx` (new ×5)
- `frontend/src/stores/ui.ts`, `frontend/src/components/Layout.tsx`
- `frontend/eslint.config.js`
- Pages ×5: `LoginPage.tsx`, `ChangePasswordPage.tsx`, `DevicesPage.tsx`, `DashboardPage.tsx`, `ChangesPage.tsx`
- Tests: new component tests (~3 files consolidated) + updated page tests (~4)

**Dependencies:** Wave 2 item 1 (ErrorBoundary exists; ErrorBanner composes with it). Independent of Waves 3/5.

**Test plan:**
- vitest for each new component (variants, keyboard interaction, reduced-motion).
- Updated page tests keep passing (visual-regression proxy).
- jsx-a11y blocking in `eslint`; manual axe pass on the five pages — zero serious/critical findings.
- Manual viewport check at 375 px / 768 px / 1280 px: sidebar collapses, no horizontal page scroll, tables scroll internally.

**Rollback plan:** per-page adoption commits — revert any single page without touching the primitives; primitives themselves are additive (unused components are inert). jsx-a11y can drop to warn-level in one line if it blocks unrelated work.

**Success criteria:**
- Five pages consume shared primitives; zero raw `status-*` pill composition on them.
- jsx-a11y blocking + axe-clean on core pages; Login/ChangePassword fully labeled.
- Skeletons replace text-only loading on the five pages; all motion respects `prefers-reduced-motion`.
- App usable (navigate + read tables + submit forms) at 768 px.

---

## Wave 5 — Performance & scale optimization — ✅ MERGED 2026-07-04 (PR #110, `05dd460`)

> **Implemented 2026-07-04** per the revised spec below, one atomic commit per item: neighborhood read (`319796c`), `topology_max_nodes` cap → 413 (`003358e`), frontend scoped-by-default adoption (`8101d87`). Item 4 was dropped to backlog by the revision. All gates green at each commit (ruff/format/mypy/lint-imports, backend suite, vitest/eslint/tsc). Success criteria met: UI default load is scoped (site or neighborhood), the unscoped fetch is explicit and 413-bounded, and all new Cypher lives in `app.knowledge` (lint-imports enforced).

> **Plan revision (2026-07-04, pre-implementation validation against `main` @ `c87d79c`).** The section below is the revised, executable spec; four corrections vs. the original text:
> 1. **ARCH_DEBT #7's premise is partially stale.** `GET /topology/graph` already accepts `site` / `vrf` / `layer` (server-side and in the typed client `frontend/src/api/topology.ts`) — it is the *UI* that never passes them (`TopologyPage.tsx` fetches by `layer` only). By-site scoping therefore needs **no new endpoint**; the new backend work is the neighborhood query and the cap.
> 2. **Query placement corrected.** New Cypher goes in `app/knowledge/` — `app.knowledge` is the only package that talks to Neo4j (REPO-STRUCTURE §3.2, enforced by the `lint-imports` contract). The original file list (`engines/topology/` query module) would have failed that gate; `engines/topology/` is not touched.
> 3. **File list completed.** The cap needs a new 413-class problem-details error (`app/core/errors.py` has none today) and a `NETOPS_TOPOLOGY_MAX_NODES` setting (`config.py` + `.env.example`, 1:1 rule) to honor the "config-tunable cap" rollback plan.
> 4. **The perf fixture the original test plan cited does not exist.** The drill harness's topology fixture is a fixed 42-node count-only dry-run stub; the 5,000-device seeded dataset is a named GA-phase artifact (ADR-0047). This wave ships **functional** tests (cap bites, depth bounds, scope membership); latency/scale assertions land at P5 with that dataset. Former item 4 (hot-list-endpoint query review) is demoted to backlog — it cites no audit finding and every list endpoint already paginates (`limit ≤ 500`).
>
> Discipline carry-over from Wave 3: one revertible commit per item **must survive the merge** (no bundling/squash across items), or the rollback plan below is void.

**Goal:** Remove the known scale ceiling before certification finds it: scoped topology queries end-to-end, bounded `/graph`.

**Work items (audit refs):**
1. Device-neighborhood-at-depth-N subgraph read (ARCH_DEBT #7): new Cypher in `app/knowledge/topology_read.py` (or a sibling module) + `GET /topology/graph/neighborhood` (device key, `depth` 1–N bounded, same `layer` families). By-site scoping already exists via the `site` query param — reuse, don't rebuild.
2. Cap the unscoped `/graph`: `max_nodes` guard (count pre-check before serialization; setting `NETOPS_TOPOLOGY_MAX_NODES`) returning a new 413-class problem-details error with guidance to the `site`/neighborhood variants.
3. Frontend adoption: TopologyPage default-loads a scoped view — site picker (wires the *existing* `site` param) + device-neighborhood mode; full-graph fetch becomes an explicit action and renders the 413 guidance when over cap. `vrf` is not a scoping dimension (it only constrains `ROUTES_TO` edges) — site/neighborhood are.
4. ~~Query-efficiency review of the hot list endpoints~~ **DEMOTED TO BACKLOG (2026-07-04 revision):** no audit finding cites it, all list endpoints already paginate, and there is no profiling harness to satisfy its own "measure first" bar. Re-open only with profiling evidence.

**Files affected (~14):**
- `backend/app/knowledge/topology_read.py` (neighborhood query + cap pre-check)
- `backend/app/api/v1/topology.py`, `backend/app/schemas/topology.py`
- `backend/app/core/errors.py` (413 problem-details class), `backend/app/core/config.py`, `.env.example`
- `backend/tests/knowledge/test_topology_read.py` (new), `backend/tests/api/test_topology.py` (extend)
- `frontend/src/api/topology.ts`, `frontend/src/pages/TopologyPage.tsx`, `frontend/src/pages/topology-graph.ts`
- `frontend/src/__tests__/TopologyPage.test.tsx`, `frontend/src/__tests__/topology.test.ts` (extend)

**Dependencies:** none hard; scheduled last because risk-to-value is lowest at current scale and it should land close to the G-SCA certification work (P5) it enables. The 5,000-device seeded dataset remains a P5/GA deliverable (ADR-0047) — this wave makes the G-SCA mechanism ("UI uses scoped queries, no full-graph fetch") true in code; P5 measures it at scale.

**Test plan:**
- Unit/integration on the neighborhood query (correct subgraph membership, depth bounds honored, empty scopes) in `tests/knowledge/` + API-level tests.
- Cap test: seeded graph over `max_nodes` → 413 problem details, never a truncated 200; under-cap responses byte-identical to today.
- Frontend: TopologyPage tests for scoped default, explicit full-graph path, and over-cap 413 guidance rendering.
- Latency/scale assertion **deferred to P5** with the ADR-0047 5,000-device dataset (revision note 4) — not faked at unit scale.
- Full backend + frontend suites green.

**Rollback plan:** the neighborhood endpoint is additive — revert the frontend adoption commit to restore the full-graph default while keeping the new endpoint; cap is config-tunable (`NETOPS_TOPOLOGY_MAX_NODES`, raise or disable) before any code revert.

**Success criteria:**
- UI default topology load fetches a scoped subgraph; unscoped fetch is explicit and bounded (413 over cap).
- G-SCA's "UI uses scoped queries, no full-graph fetch" criterion satisfiable in code (certification itself remains a GA item).
- No regression on current-lab-scale topology UX.
- `lint-imports` green — all new Cypher confined to `app.knowledge`.

---

## Deliberately out-of-wave (tracked, not dropped)

| Item | Why excluded | Home |
|---|---|---|
| ~~Packet-analysis **implementation** (post-ADR-0049)~~ **DONE** (2026-07-03, `feat/packet-executor-split`) | Executor-split shipped: self-confining executor child (T1) + dispatcher rewire (T2) + tshark/libseccomp image & dispatcher seccomp profile + lockstep/policy gates (T3) + Linux bite-proof & re-enable-by-default & docs (T4). ARCH_DEBT #1 resolved. | Landed on its own follow-on wave after ADR-0049 acceptance |
| `ci.yml` modularization (ARCH_DEBT #5) | Every moved gate needs individual red→green re-proof; bundling it with feature waves risks masked gates | Standalone DX effort; schedule after Wave 2's gate promotion settles |
| Vendor plugin rollback-driver lift (ARCH_DEBT #6) | One-plugin-per-maintenance-wave cadence by design | Amortized across future vendor waves |
| Pen test, 30-day soak, certified-scale runs, OIDC two-IdP live, break-glass drill | External resources / GA-phase items, already ledgered | `PRODUCTION.md` GA gates |
| P3 W5 phase-exit (ADR 0042–0048 flips) | Existing roadmap milestone, not audit remediation | `P3-PLATFORM-PLAN.md` W5 |
| Trivy/pip-audit allowlist monthly review | Recurring process, not a wave | Calendar-owned ops task (PRODUCTION_READINESS #6) |

## Sequencing picture

```
W1 (bugs) ──► W2 (functional/security) ──► W3 (architecture)
                       │                      
                       └────► W4 (UI/UX, after W2 ErrorBoundary)   W5 (perf) — independent, land near P5 scale work
```

W1→W2→W3 strictly ordered (shared files: `main.py`, `auth.py`). W4 needs only W2 item 1. W5 free-floating. Estimated total: ~72 files across 5 waves, every wave ≤ 20.
