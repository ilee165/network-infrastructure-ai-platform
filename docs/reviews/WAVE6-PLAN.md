# Wave 6 Implementation Plan — FE Platform Kit + Read-Facade

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source:
[`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W2-T2 + AR-W3,
[`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) M26–M33, M35, M37–M41,
[`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md) F5.

**Theme:** structural refactor wave — agents and routers stop touching the DB
directly (backend), and the frontend gets the shared platform kit that ends
the copy-paste/mock-fragility classes. Zero endpoint-contract or visual
behavior change; existing suites are the regression harness.

**Shape:** two PRs. PR-A backend (`refactor/review-wave6-backend`), PR-B
frontend (`refactor/review-wave6-frontend`). Atomic commit per task.

**Coordination rule (AR1 collision matrix):** PR-A ∥ PR-B — independent **of
each other**, and neither is independent of P4. Both serialize against P4-W3:
PR-A collides with the P4-W3 compliance endpoints (`api/` + `services/`), PR-B
with any P4 UI task. Run this wave **before or after** P4-W3, never
concurrently.

That rule is a **pre-flight gate, not a note** — run it at branch creation
*and* again at every rebase (P4-W3 can open mid-wave):

```bash
gh pr list --state open --json number,headRefName,files \
  | jq -r '.[] | select(.headRefName|test("p4")) | .files[].path'
# intersect against  backend/app/api/v1/*, backend/app/services/*      (PR-A)
#                    frontend/src/pages/*, frontend/src/components/*   (PR-B)
# non-empty intersection -> ABORT, wait for P4-W3 to merge
```

Current call: P4-W2 is merged and P4-W3 (compliance reporting) is **not yet
open** — so Wave 6 runs **first**, ahead of P4-W3.

**Prerequisites:** Wave 4 merged (PR #159 / #160) — import-linter contracts +
generated types, the burn-down target and the type source both exist. Wave 5
merged (PR #161, `255f159`) — code-splitting + the chunk-count build gate
landed there; the ChatPage/TopologyPage render fixes inform T4's hook shapes.
Both are satisfied on `main`; branch off `main`, never off an unmerged wave
branch.

---

## PR-A — Backend: read-facade + router extraction

### T1 — AR-W2-T2: agent read-facade
`wf-implementer`, strong.

Read-only repository/service functions (extend the
`knowledge/topology_read.py` pattern) replace raw `app.db` use in
`agents/discovery/tools.py` + `agents/troubleshooting/tools.py`.
- Shrink the Wave 4 import-linter allowlist to `framework/traces.py` only;
  tighten the forbidden contract. Outcome, stated exactly: **no specialist
  has a direct `app.db` / `app.models` / `app.services` edge — agents reach
  persistence only through the framework's tool wrappers and the read
  facade.**
- **This is NOT the write-safety claim.** Contract 2 in
  `backend/pyproject.toml` runs with `allow_indirect_imports = true` and
  excludes `app.agents.framework` from `source_modules`; import-linter is
  module-granular and cannot distinguish a read function from a write
  function inside a permitted module. `framework/tools.py` already imports
  `app.models.change_requests` (`tools.py:59`) and is the sanctioned seam —
  shrinking the allowlist does not, and cannot, prove an agent tool is
  unable to reach a write-capable path. The write boundary is proven by T1b,
  not by the contract.
- Tool outputs byte-identical for identical data (agent evals + tool tests
  are the harness); READ_ONLY tool semantics unchanged.
- Sweep the automation/ddi/security tools' model imports listed in the
  allowlist: migrate the trivial ones, leave a burn-down note per survivor.

### T1b — Agent write-boundary negative test (NEW)
`wf-implementer`, strong. Makes the R1 claim machine-enforced for real. Two
layers, both gating:

- **Runtime write-guard (primary — covers the indirect case).** A SQLAlchemy
  `before_execute` / `do_execute` event listener bound to the test session
  fixture that raises on any INSERT / UPDATE / DELETE. Drive **every tool in
  the agent registry carrying READ_ONLY semantics** through it and assert
  zero write statements are emitted — regardless of how many modules deep the
  call goes. Exactly one path is whitelisted: the
  `services/change_requests` create path, which gets its own positive test
  asserting it *does* write (a guard that never fires on anything is not a
  guard).
- **Static facade check (secondary — fast feedback).** AST test over the read-
  facade module: no `session.add` / `.delete` / `.commit` / `.flush`, no
  `insert()` / `update()` / `delete()` constructs.

Bite evidence for T1b: a planted `session.add(...)` in a READ_ONLY tool's call
path → RED. (The planted-`app.db`-import → RED bite stays as T1's evidence;
the two prove different properties and both are required.)

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
`wf-implementer-light`. Shared `components/` primitives.

**Scope is the enumerated set below — and only that set.** The long tails (31
table shells, 17 empty-state blocks, 8 error alerts) are *not* a migration
target this wave; full burn-down is a mechanical follow-on. What this wave
guarantees for the tails is **no regression**, via a count ratchet.

Gating — these go to zero:
- `Modal`/`ConfirmDialog` — dedupe the verbatim-drifted pair
  (ApplicationsPage vs UsersPage, M27) and the 6 hand-rolled modal shells.
- `EmptyState` — rename the VirtualizationPage local shadow, extend the
  shared one to the common case (M33).
- `StatusPill` — the 5 re-rolled `PILL_BASE` badges (M30).
- `ErrorBanner.messageFor` exported; the 4 narrower `errorMessage()` copies
  (M28) replaced.
- M26: clipboard `.catch` + visible copy-failed state on UsersPage while
  touching it.

Built + adopted opportunistically, **not** burned down:
- `DataTable` — the `panel overflow-x-auto > table` shell ×31 across 15 files
  (M32). The primitive ships with header/skeleton/empty/pagination wiring in
  one place and is adopted where T3/T4 already touch a page; the other call
  sites stay.
- The 8 hand-rolled error alerts (M31) — migrated where touched.

**Count ratchet (gating, replaces "full migration").** Record the baseline for
each tail in the PR body (table shells / empty-state blocks / error alerts) and
add a CI script asserting each count `<=` baseline. Migration is non-gating;
*regression* is gating. New code may not re-roll a primitive that now exists.

### T4 — Query layer (AR-W3-T3)
`wf-implementer`. `src/hooks/` per-domain query hooks + central `queryKeys`
registry.

**State taxonomy — binding.** "Migrate page X to react-query" means migrate its
*server reads and writes*, nothing else. Four buckets, each with exactly one
sanctioned tool; a refactor that moves state across a bucket boundary is out of
scope and a review-reject:

| Bucket | Tool | Applies to |
|--------|------|------------|
| Server reads (cacheable GET) | `useQuery` + `queryKeys` | Adc / Devices / Topology fetches; Chat session list, history, trace fetch |
| Server writes (POST/PATCH/DELETE) | `useMutation` + targeted invalidate | The imperative actions with hand-rolled pending/error/result trios (M37): PacketPage capture start, TopologyPage refresh/derive, AuditPage export |
| Streaming / WebSocket | `useAgentStream` **only** — local reducer + rAF batching | ChatPage socket lifecycle (`ChatPage.tsx:160-224`) |
| Local / ephemeral UI | `useState` / `useReducer` | filters, selections, form drafts, modal open |

- **WS↔cache seam, pinned:** the stream never writes tokens into the query
  cache. On terminal event the hook invalidates the relevant `queryKeys` so
  the persisted record is refetched. Streaming state is not server state.
- **TopologyPage / AuditPage:** `useMutation` covers the *actions*. Filter and
  selection state stays local — do not route it through react-query.
- `useAgentStream` absorbs Wave 2's M24 unmount fix and Wave 5's rAF batching;
  the hook owns socket open/close/replay.
- `useChangePassword()` hook deduping the ChangePasswordPage/ProfilePage
  validation flow (M29).
- Hooks thread `AbortSignal` from react-query into the client (Wave 2 M34
  plumbing) — cancellation now reaches `fetch` app-wide.
- Consume Wave 4's generated types where the module is codegen-backed;
  expand codegen adoption opportunistically (mechanical follow-on).

### T5 — Central mocks / test-utils (AR-W3-T4 + F5)
`wf-implementer-light`. Closes the L-FE-1 class **for modules the shared
factories cover**:
- One shared test-utils module: auth-api mock factory (single source for the
  7 sibling files partially mocking `../api/auth`) + shared QueryClient
  render wrapper (replaces the 101 inline `new QueryClient` across 22
  files).
- Mock factories use `vi.importActual` spreads so new exports are absorbed
  automatically. **Scope of that guarantee, stated exactly:** it eliminates
  *one* failure mode — a factory mock omitting a newly added export ("No X
  export is defined on the mock"). It does **not** protect against a wrong
  override shape or return type, drift in the real module's behavior, or a
  test that mocks a module the shared factories don't cover. Not "impossible";
  "structurally closed for covered modules."
- **L-FE-1 discipline stays alive** for every module outside the factories:
  a new export → sweep sibling `vi.mock`s, as before.
- Teeth for the coverage claim: a lint/test that fails on a bare
  `vi.mock('../api/*')` not routed through a factory — otherwise "covered"
  silently decays.
- Migrate the 7 hand-mocked auth files first (highest blast radius), then
  the 19 fetch-stub files incrementally; migration of stragglers is
  opportunistic, the shared module is the gate.
- Keep at least one suite exercising the real `api/client.ts` fetch →
  problem+json mapping (the F5 structural blind spot) — do not
  module-boundary-mock it away.

### T6 — SettingsPage split (M35) — **conditional**
Standing decision: deferred to "first time the settings hub is touched
again" (`docs/features/settings-hub` plan folder exists). T3/T4 touch
SettingsPage (modal shell, errorMessage, mock migration). "Non-trivial" is
**measured, not judged** — execute the split (`pages/settings/*.tsx` thin
shell, own commit in this wave) if **any** of:

1. the T3/T4 diff touches **more than one settings section** region; **or**
2. it changes **shared state or prop threading** — any state var read by 2+
   sections, or a new prop plumbed through the hub; **or**
3. **net LOC delta in `SettingsPage.tsx` > 50**.

Otherwise the deferral stands. Record the **measured values** in the PR body
(sections touched, shared-state yes/no, net LOC delta) — not just the verdict.

---

## Ordering & dependencies

```
PR-A: T1 → T1b → T2a → T2b → T2c   (facade first; write-guard before extraction moves writes)
PR-B: T3 → T4 → T5 (→ T6)          (primitives before hooks before mock migration)
```

- PR-A ∥ PR-B — independent of each other, parallelizable. **Neither is
  independent of P4-W3** — see the pre-flight gate at the top.
- L-FE-1 discipline until T5 lands, and **after it for every module the
  factories don't cover**: FE module gains an export → sweep sibling
  `vi.mock`s.
- Two distinct bite proofs for PR-A, both required — they prove different
  properties:
  - **T1** (no direct edge): planted `app.db` import in an agent tool → RED.
  - **T1b** (no indirect write): planted `session.add(...)` in a READ_ONLY
    tool's call path → RED.

## Model & review policy

| Task | Implementer | Notes |
|------|-------------|-------|
| T1, T2a, T2b, T4 | strong | boundary/refactor correctness |
| T1b | **STRONG pinned** | the R1 safety boundary is only as good as this test |
| T2c | **STRONG pinned** | auth surface |
| T3, T5 | light | mechanical dedupe/migration |

Quality + spec review per task; escalate STRONG on T1b + T2c review.

## Gates (per task and PR exit)

- Backend: full unit + pg-integration; static gates incl. the tightened
  import-linter contract **and** the T1b write-guard suite. Route-gate +
  auth-matrix tests pass unmodified.
- Frontend: vitest + coverage floor + typecheck + lint; chunk-count build
  gate (from Wave 5) stays green through the refactor; **T3 count ratchet**
  (tail counts ≤ baseline).
- No visual regression on migrated pages (existing page tests unmodified
  except where a task explicitly migrates scaffolding — mock migration is
  scaffolding, assertions are not).
- Pre-flight P4-W3 collision check clean at branch creation and at each
  rebase.
- `graphify update .` after each PR merge.

## Exit criteria (AR-W2/W3 exits combined)

- **Boundary (two claims, two proofs):** agents↛db import allowlist =
  `framework/traces.py` only, contract proven to bite (T1); **and** every
  READ_ONLY agent tool emits zero INSERT/UPDATE/DELETE under the runtime
  write-guard, with `services/change_requests` the sole whitelisted write
  path and its positive test green (T1b). Neither claim substitutes for the
  other.
- 3 routers ORM-free (services own the writes) with route-gate tests green.
- **FE — enumerated duplicates gone** (the drifted ConfirmDialog pair + 6
  modal shells, VirtualizationPage `EmptyState` shadow, 5 `PILL_BASE`
  badges, 4 `errorMessage()` copies). `DataTable` primitive exists and is
  adopted where touched; the 31/17/8 tails are **not** required to be zero —
  the count ratchet holds them at ≤ baseline.
- 4 pages on react-query **per the T4 state taxonomy** (server reads/writes
  only; WS state in `useAgentStream`, local UI state untouched).
- Central mock module + QueryClient wrapper in use with importActual
  factories; bare `vi.mock('../api/*')` lint in place; full FE suite green.
- SettingsPage decision recorded **with its measured values** (sections
  touched, shared-state yes/no, net LOC delta), split executed or deferral
  re-affirmed.
- `REVIEW-WAVES-PLAN.md` status table updated with both PR numbers.
