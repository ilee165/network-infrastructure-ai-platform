# Testing strategy review — 2026-07-10

- **Scope:** backend pytest suite, frontend vitest suite, CI test gates (`.github/workflows/ci.yml`).
  Three parallel audit passes (backend, frontend, CI) plus cross-reference against
  `docs/reviews/2026-07-10-repo-review.md` and `docs/roadmap/LESSONS.md`.
- **Method:** every claim verified against cited file:line by the auditing agent; no tests were
  created or modified as part of this review.
- **Companion doc:** the same-day full-repo review — its "test-blind seams" root-cause theme is
  the strategic frame for this document.

## Verdict

The suite is large, disciplined, and mostly honest: **~3,279 backend tests across 222 files**,
**~490 frontend cases across 41 files**, 16 CI jobs (11 blocking in `all-gates`), zero
`unittest.mock`/`MagicMock` usage (hand-written fakes throughout), an enforced 80% backend
coverage floor, and planted-negative "bite" proofs on the lockfile, observability, and infra
gates. Well above average for a project of this size.

The core weakness is **test-blind seams**: every CRITICAL in the 2026-07-10 repo review lives
where the suite structurally cannot see it — Helm render vs real `Settings`, fixture SSH vs real
netmiko/Tcl, `httpx.MockTransport` vs real connection pooling, a synthetic auth probe route vs
real protected routes. One security-relevant test file was additionally found to **run in no CI
job at all** (F1 below).

---

## 1. Findings

### F1 (CRITICAL) — `tests/pg/test_refresh_reuse.py` executes in NO job

- The file is missing `pytestmark = pytest.mark.integration` (the other 10 of 11 `tests/pg/`
  files carry it).
- The `pg-integration` job selects with `pytest tests/pg/ -m integration` (`ci.yml:1901`) →
  the file is **deselected** there.
- The unit `backend` job skips all of `tests/pg/` via the PG-unreachable collection hook
  (`backend/tests/pg/conftest.py:114-137`, `add_marker(skip)`).
- The empty-run guard (`ci.yml:1904-1908`) greps only `skipped|no tests ran` — it does **not**
  match `deselected`, so the gate stays green.
- Net effect: refresh-token reuse/replay semantics and `test_migration_0015_column_shape_on_pg`
  are verified nowhere. This is a live instance of the known marker landmine
  (see `pg-integration marker required` standing rule).

**Resolution path:** add the marker to the file, then harden the guard so the class cannot
recur — either fail the pg-integration job when pytest output contains `deselected`, or add a
`pytest tests/pg/ -m integration --collect-only -q` step asserting the collected count covers
every `tests/pg/test_*.py` file.

### F2 (HIGH) — Frontend has no coverage measurement at all

- No `test.coverage` block in `frontend/vite.config.ts:27-31`; no `@vitest/coverage-*`
  dependency in `package.json`; CI runs plain `npm test` = `vitest run` (`ci.yml:188`).
- Backend enforces `--cov-fail-under=80` (`ci.yml:125`); the frontend enforces nothing —
  coverage regressions in untested branches ship silently.

**Resolution path:** add `@vitest/coverage-v8`, a starting threshold (~70%), and a CI flag;
ratchet upward over time.

### F3 (HIGH) — Test-blind seams: contract gaps where all repo-review CRITICALs live

- Helm-rendered config keys are never checked against the real `Settings` model (repo review
  C5/C6); `.env.example` drift is unchecked.
- Frontend and backend enums drift with no contract test and no OpenAPI-generated types
  (repo review H14/M25).
- `httpx.MockTransport` hides real connection-pool semantics (repo review H9 crashed only in
  production); fixture SSH hides vendor-syntax divergence (C2/C3); the auth middleware test
  mounts a synthetic probe route and proves nothing about real routes (C1).

**Resolution path:** (a) a config-contract CI check — rendered ConfigMap/env keys ⊆ `Settings`
field names, `.env.example` ⊇ `Settings`; (b) frontend↔backend enum contract tests or
OpenAPI-generated client types; (c) one auth test hitting a real protected route.

### F4 (HIGH) — Neo4j and Redis have zero pytest integration coverage

- Graph tests self-skip when Neo4j is unreachable (`tests/knowledge/test_topology_impact.py:391`,
  `test_projector.py:759`, `engines/topology/test_rebuild_exit_criteria.py:370,438`).
- Redis-backed rate-limit/stream code is faked in-memory; no real-Redis test exists.
- Only coverage is shell drills inside the **opt-in** kind jobs (never on PRs).

**Resolution path:** clone the pg-integration pattern — a CI job with neo4j + redis service
containers that unskips the self-skipping tests and adds real-Redis rate-limit/stream cases.

### F5 (MEDIUM) — Frontend mocking fragility (L-FE-1 class fully exposed)

- 16 partial `vi.mock('../api/*')` factories, `vi.importActual` used **0** times, no MSW, no
  shared mock factory or test-utils module.
- `../api/auth` is partially mocked in **7 sibling files** (ChangePasswordPage, Layout,
  LoginPage, ProfilePage, SettingsPage, SettingsRoute, UsersPage) — one new auth export breaks
  up to 7 suites at once ("No X export is defined on the mock"; already bit PR #125).
- `QueryClientProvider`/`new QueryClient` inlined 101× across 22 files.
- Structural blind spot: module-boundary mocks bypass the real `api/client.ts` fetch →
  problem+json error mapping entirely; it is only exercised where `fetch` is stubbed
  (ApplicationsPage/AdcPage group).

**Resolution path:** one shared test-utils module — an auth-api mock factory (single source for
the 7 siblings) and a shared QueryClient render wrapper. Prefer `importActual` spreads in mock
factories so new exports are absorbed automatically.

### F6 (MEDIUM) — No per-test timeout; a few real-clock tests

- Neither pytest (`ci.yml:125`) nor the vitest config sets a per-test timeout; a hung await
  burns the full 15–20 min job budget before failing.
- Real `asyncio.sleep(5)` in `tests/test_health.py:117` and
  `tests/agents/framework/test_tools.py:121`; timing-sensitive SSE sleeps in
  `tests/api/test_agents.py:552,661,812,1012`; clock-granularity assert in
  `tests/models/test_mixins.py:50`.
- Frontend: polling tested with real timers + `waitFor` (`DevicesPage`, `DashboardPage`) rather
  than fake timers; documented `setTimeout(0)` object-URL-revoke teardown races
  (`IncidentReportsPage.test.tsx:206-208`, `DocumentsPage.test.tsx:370-420`).

**Resolution path:** add `pytest-timeout` (~60s default); replace the two `sleep(5)` tests with
event-driven waits; move polling tests to fake timers.

### F7 (MEDIUM) — Thin coverage areas

- `app/agents/master_architect/agent.py`: no dedicated test file (indirect only).
- REST vendor plugins `bluecat`, `fortios`, `panos`, `f5_bigip`, `vmware`: conformance-shell
  only; `client.py` parsing/auth/error/timeout paths thinly tested. F5/VMware functional paths
  exist only in env-gated live tests that never run in CI. (Contrast: the 5 CLI vendors each
  have parser + config-change + protocol suites.)
- Compliance engine/loader/schema share one test file; malformed-YAML edges thin.
- Frontend: 12 of 16 api modules have no direct test; `api/agents.ts:114-184` (WebSocket
  ticket-auth/streaming) untested; `roles` store, `PageHeader`, `EmptyState` untested;
  `SettingsPage` has 32 tests but ~2 failure-state tests; route guards ~1 denied-path test each.
- No E2E layer of any kind (no Playwright/Cypress).

### F8 (MEDIUM) — Coverage gate semantics

- The 80% floor applies to the **unit job only** and is **line** coverage with no
  `[tool.coverage]` config (no branch coverage, no omit list). Code reachable only under
  pg-integration/kms/live jobs counts as missed; the headline number is misleading in both
  directions.

### F9 (MEDIUM) — CI reliability gaps

- First-party actions float on major tags with no SHA pinning (`checkout@v7`,
  `setup-python@v6`, `setup-node@v6`, `build-push-action@v7`, `upload-artifact@v7`);
  `docker-publish` runs them with `id-token: write` + `packages: write` (`ci.yml:456-463`) — a
  re-pointed tag is code execution in the signing job.
- `kubeconform` and `kube-linter` binaries are downloaded with no checksum verification
  (`ci.yml:741-751`), unlike gitleaks/promtool which are SHA256-verified.
- No bounded retry on egress steps (pip, npm, pip-audit/OSV, npm-audit) — only the kms compose
  bring-up has one (`ci.yml:1756-1771`). Transient registry 5xx = hard red.
- CI builds/tests the frontend on **Node 20** while the production image runs **Node 22**
  (repo review M46) — the prod runtime is never exercised.
- Verified sound (non-risks): `continue-on-error` confined to opt-in signal-only jobs with
  correct `outcome` (not `conclusion`) handling; cosign `:main` retag race fixed
  (`ci.yml:638-661`); `all-gates` fails on skipped results; service containers health-gated;
  every job time-boxed; concurrency cancel-in-progress on.

### Flakiness state (good)

The StaticPool shared-connection landmine (root of the WS fan-out flake, PR #90) is remediated:
exactly one intentional, documented survivor (`tests/agents/eval/test_p1_prompt_injection.py:280`,
single-connection offline eval). Concurrency-sensitive tests use file-backed NullPool engines;
the pg layer TRUNCATEs per test. No rerun/retry plugins exist — and none are currently needed.
Residual flake surface is F6 plus egress-dependent CI steps (F9).

---

## 2. Recommendations, ranked by ROI

1. **F1 fix + deselect guard** — add the marker to `test_refresh_reuse.py`; make the
   pg-integration guard fail on `deselected` or add a collect-only count assert. Minutes of
   work; a currently-dark security test lights up and the silent-drop class closes permanently.
2. **Frontend coverage floor (F2)** — coverage-v8 + threshold in CI. Cheap; restores gate
   symmetry with the backend.
3. **Contract tests for the blind seams (F3)** — config-contract check + enum contract tests +
   one real-route auth test. Highest defect-prevention per line: every escaped CRITICAL this
   cycle was a seam defect, not a unit defect.
4. **`pytest-timeout` + de-sleep the two `sleep(5)` tests (F6)** — trivial; converts hangs into
   named failures instead of 15-minute job burns.
5. **Shared frontend mock factory + QueryClient wrapper (F5)** — structurally ends L-FE-1
   recurrence and removes ~100 duplicated setup blocks.
6. **Neo4j + Redis pytest integration job (F4)** — medium effort; closes the largest remaining
   semantic blind spot.
7. **REST vendor client error-path fixtures (F7)** — one shared parametrized MockTransport
   harness (auth-fail / malformed / timeout) across the 5 REST vendors.
8. **CI hardening batch (F9)** — SHA-pin actions, checksum kubeconform/kube-linter, bounded
   retry on egress steps, CI Node 20 → 22.
9. **(Deferred, larger) Playwright smoke against the compose quickstart** — the only layer that
   would exercise real client error-mapping and the auth flow end-to-end. Do after 1–8.

Items 1, 2, and 4 together are roughly an afternoon of work with disproportionate payoff.
Item 3 is the strategic investment.
