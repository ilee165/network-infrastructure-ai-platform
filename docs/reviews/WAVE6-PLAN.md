# Wave 6 Implementation Plan — FE Platform Kit + Read-Facade

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source:
[`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W2-T2 + AR-W3,
[`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) M26–M33, M35, M37–M41,
[`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md) F5.

**Theme:** structural refactor wave — agents and routers stop touching the DB
directly (backend), and the frontend gets the shared platform kit that ends
the copy-paste/mock-fragility classes. Zero endpoint-contract or visual
behavior change; existing suites are the regression harness.

**Shape:** two independent PRs. PR-A backend (`refactor/review-wave6-backend`),
PR-B frontend (`refactor/review-wave6-frontend`). Atomic commit per task.
**Coordination rule (AR1 collision matrix):** PR-A collides with P4-W3
compliance endpoints (`api/` + `services/`), PR-B with any P4 UI task — run
this wave **before or after** P4-W3, never concurrently with it.

**Prerequisites:** Wave 4 merged (import-linter contracts + generated types —
the burn-down target and the type source both exist). Wave 5 merged
(code-splitting already landed there; ChatPage/TopologyPage render fixes
inform T6's hook shapes).

---

## PR-A — Backend: read-facade + router extraction

### T1 — AR-W2-T2: agent read-facade
`wf-implementer`, strong.

Read-only repository/service functions (extend the
`knowledge/topology_read.py` pattern) replace raw `app.db` use in
`agents/discovery/tools.py` + `agents/troubleshooting/tools.py`.
- Shrink the Wave 4 import-linter allowlist to `framework/traces.py` only;
  tighten the forbidden contract. Outcome: **agents structurally cannot
  write outside `services/change_requests`** — the R1 safety boundary
  becomes machine-enforced instead of conventional.
- Tool outputs byte-identical for identical data (agent evals + tool tests
  are the harness); READ_ONLY tool semantics unchanged.
- Sweep the automation/ddi/security tools' model imports listed in the
  allowlist: migrate the trivial ones, leave a burn-down note per survivor.

### T2 — AR-W3-T1: inline-ORM extraction to services, worst 3 routers
One commit per router; endpoint contracts unchanged (route-gate tests are
the harness). Services own sessions/writes + audit; routers keep
validation/response shaping (per the Wave 4 services-vs-engines charter).

| Commit | Router | Session ops | Model |
|--------|--------|-------------|-------|
| a | `api/v1/applications.py` | 20 | strong |
| b | `api/v1/devices.py` | 13 | strong |
| c | `api/v1/auth/users.py` | 13 | **STRONG pinned** — auth surface |

- Wave 2's H1 fix (IntegrityError→409) moves with the code — keep the
  regression tests passing unmodified.
- Any new PG-semantic tests → `tests/pg/` with
  `pytestmark = pytest.mark.integration` + collection proof.
- The real-route auth contract matrix from Wave 4 T6 must stay green —
  that's the gate proving extraction didn't reorder auth dependencies.

## PR-B — Frontend: platform kit

### T3 — Primitives (AR-W3-T2)
`wf-implementer-light`. Shared `components/` primitives; replace known
duplicates, migrate pages opportunistically (full migration not gating):
- `Modal`/`ConfirmDialog` — dedupe the verbatim-drifted pair
  (ApplicationsPage vs UsersPage, M27; 6 hand-rolled modal shells total).
- `DataTable` — the `panel overflow-x-auto > table` shell ×31 across 15
  files (M32); header/skeleton/empty/pagination wiring in one place.
- `EmptyState` — rename the VirtualizationPage local shadow, extend the
  shared one to the common case (M33).
- `StatusPill` migration for the 5 re-rolled `PILL_BASE` badges (M30).
- Export `ErrorBanner.messageFor`; replace the 4 narrower `errorMessage()`
  copies (M28) and the 8 hand-rolled error alerts (M31).
- M26: clipboard `.catch` + visible copy-failed state on UsersPage while
  touching it.

### T4 — Query layer (AR-W3-T3)
`wf-implementer`. `src/hooks/` per-domain query hooks + central `queryKeys`
registry.
- Migrate the 4 imperative pages (Adc, Chat, Devices, Topology) onto
  react-query; standardize hand-rolled pending/error/result trios on
  `useMutation` (M37: PacketPage, TopologyPage, AuditPage).
- `useAgentStream` hook wrapping the ChatPage WebSocket lifecycle
  (`ChatPage.tsx:160-224`) — absorbs Wave 2's M24 unmount fix and Wave 5's
  rAF batching; the hook owns socket open/close/replay.
- `useChangePassword()` hook deduping the ChangePasswordPage/ProfilePage
  validation flow (M29).
- Hooks thread `AbortSignal` from react-query into the client (Wave 2 M34
  plumbing) — cancellation now reaches `fetch` app-wide.
- Consume Wave 4's generated types where the module is codegen-backed;
  expand codegen adoption opportunistically (mechanical follow-on).

### T5 — Central mocks / test-utils (AR-W3-T4 + F5)
`wf-implementer-light`. Kills the L-FE-1 class structurally:
- One shared test-utils module: auth-api mock factory (single source for the
  7 sibling files partially mocking `../api/auth`) + shared QueryClient
  render wrapper (replaces the 101 inline `new QueryClient` across 22
  files).
- Mock factories use `vi.importActual` spreads so **new exports are absorbed
  automatically** — the "No X export is defined on the mock" failure mode
  becomes impossible.
- Migrate the 7 hand-mocked auth files first (highest blast radius), then
  the 19 fetch-stub files incrementally; migration of stragglers is
  opportunistic, the shared module is the gate.
- Keep at least one suite exercising the real `api/client.ts` fetch →
  problem+json mapping (the F5 structural blind spot) — do not
  module-boundary-mock it away.

### T6 — SettingsPage split (M35) — **conditional**
Standing decision: deferred to "first time the settings hub is touched
again" (`docs/features/settings-hub` plan folder exists). T3/T4 touch
SettingsPage (modal shell, errorMessage, mock migration) — **if** those
diffs turn non-trivial, execute the split (`pages/settings/*.tsx` thin
shell) as its own commit in this wave; if the touches stay mechanical,
the deferral stands. Decide at implementation time, record the call in the
PR body.

---

## Ordering & dependencies

```
PR-A: T1 → T2a → T2b → T2c     (facade first — extraction reuses its service seams)
PR-B: T3 → T4 → T5 (→ T6)      (primitives before hooks before mock migration)
```

- PR-A and PR-B fully independent — parallelizable.
- L-FE-1 discipline until T5 lands: every FE module gaining an export →
  sweep sibling `vi.mock`s. After T5, the importActual factories absorb it.
- Import-linter allowlist shrink (T1) is the bite evidence for PR-A: planted
  `app.db` import in an agent tool → RED.

## Model & review policy

| Task | Implementer | Notes |
|------|-------------|-------|
| T1, T2a, T2b, T4 | strong | boundary/refactor correctness |
| T2c | **STRONG pinned** | auth surface |
| T3, T5 | light | mechanical dedupe/migration |

Quality + spec review per task; escalate STRONG on T2c review.

## Gates (per task and PR exit)

- Backend: full unit + pg-integration; static gates incl. the tightened
  import-linter contract. Route-gate + auth-matrix tests pass unmodified.
- Frontend: vitest + coverage floor + typecheck + lint; chunk-count build
  gate (from Wave 5) stays green through the refactor.
- No visual regression on migrated pages (existing page tests unmodified
  except where a task explicitly migrates scaffolding — mock migration is
  scaffolding, assertions are not).
- `graphify update .` after each PR merge.

## Exit criteria (AR-W2/W3 exits combined)

- Agents↛db allowlist = `framework/traces.py` only; contract proven to bite.
- 3 routers ORM-free (services own the writes) with route-gate tests green.
- FE duplicates gone (ConfirmDialog/DataTable/EmptyState/StatusPill/
  ErrorBanner consolidated); 4 pages on react-query; central mock module +
  QueryClient wrapper in use with importActual factories; full FE suite
  green.
- SettingsPage decision recorded (split executed or deferral re-affirmed).
- `REVIEW-WAVES-PLAN.md` status table updated with both PR numbers.
