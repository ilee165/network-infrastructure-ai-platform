# Wave 6 Implementation Plan — FE Platform Kit + Read-Facade

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Historical source
input: [`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W2-T2 + AR-W3,
[`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) M26–M33, M35, M37–M41,
[`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md) F5.

This document, not the historical AR1 draft, is the execution authority for
Wave 6.

**Theme:** structural refactor wave — discovery/troubleshooting specialist
tools stop owning persistence reads and operational SQL directly, the three
target routers stop owning ORM work, and the frontend gets the shared platform
kit that ends the enumerated copy-paste/mock-fragility classes. The Automation
Agent's deterministic ChangeRequest write path remains an explicit residual;
extracting that safety-critical port is deferred to its own STRONG-reviewed
task. Zero endpoint-contract or visual behavior change; existing suites are the
regression harness.

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
gh pr list --state open --json number,title,headRefName,files \
  | jq -r '.[]
      | select((.headRefName + " " + .title)
          | test("p4[-_/ ]?w3|compliance"; "i"))
      | .files[].path'
# intersect against  backend/app/api/** or backend/app/services/**     (PR-A)
#                    frontend/src/**                                   (PR-B)
# non-empty intersection -> ABORT, wait for P4-W3 to merge
```

**`gh` is not guaranteed on the executing host** (it is absent from the Codex
harness). If `gh` is unavailable or unauthenticated, perform the same
open-PR-and-files query through the authenticated GitHub REST/GraphQL API. A
remote-branch scan is **not** an equivalent fallback: it cannot identify open
PR state, misses fork heads, and includes stale branches. If neither `gh` nor
authenticated API access is available, obtain operator attestation covering
all open P4-W3/compliance PRs and their changed files. Record the command/API
result or attestation in both PR bodies; the check is never skipped silently.

Planning snapshot (2026-07-13): P4-W2 is merged and P4-W3 (compliance
reporting) is **not yet open** — so Wave 6 runs **first**, ahead of P4-W3.

**Prerequisites:** Wave 4 merged (PR #159 / #160) — import-linter contracts +
generated types, the burn-down target and the type source both exist. Wave 5
merged (PR #161, `255f159`) — code-splitting + the chunk-count build gate
landed there; the ChatPage/TopologyPage render fixes inform T4's hook shapes.
Both are satisfied on `main`; branch off `main`, never off an unmerged wave
branch.

---

## PR-A — Backend: read-facade + router extraction

### T1 — AR-W2-T2: agent read-facade

`wf-implementer`, **STRONG pinned** — audited credential-access seam.

Read-only repository functions — mirroring the `knowledge/topology_read.py`
*pattern* — replace raw persistence/knowledge reads in discovery and
troubleshooting specialist wrappers. Operational writes and audited secret
access use separate, explicitly named seams; they are not hidden inside a
module called "read".

**Framework homes (binding):**

- `app/agents/framework/read_facade.py` — inventory, normalized-route, and
  topology/application-impact reads. This module is genuinely read-only: no
  write-function exemptions.
- `app/agents/framework/discovery_jobs.py` — only the sanctioned
  `discovery_runs` create/failure lifecycle used by `trigger_discovery_run`.
  Celery dispatch stays at the existing seam; this module does not introduce a
  new `framework -> workers` edge.
- `app/agents/framework/credential_access.py` — audited credential acquisition
  for troubleshooting live reads. It owns the service/DB access needed for the
  append-only `audit_log` side effect; plugin/transport type edges are not
  disguised as repository reads.

These live under `app.agents.framework`, not `app.services` or `app.knowledge`,
because specialists may import only the framework seam. Framework is excluded
from contract 2's `source_modules` (`pyproject.toml:287-298`), and row 10 of
REPO-STRUCTURE §3.2 designates it as the bridge.

**Current contract-2 census and T1 exit, stated exactly.** The allowlist has
**23 entries**, grouped as follows; calling all of them "persistence" was
incorrect:

| Group | Current entries | T1 disposition |
|---|---:|---|
| Discovery/troubleshooting read + operational access — `db/models` ×4, credential service ×1, knowledge ×3 | 8 | **→ zero.** Move behind the three framework seams above. |
| Automation deterministic write path — CR model ×2, audit service ×1, CR service ×1 | 4 | **Residual.** Keep explicit with one-line safety justification; owner = a separate future **STRONG-reviewed automation-port extraction**, deliberately deferred from Wave 6. |
| DDI/security `ChangeRequestKind` decorator metadata | 2 | **Residual.** Type/value coupling, not a read-facade concern; owner = future framework/schema metadata seam. |
| Engine/plugin type + capability imports — engines ×4, plugins ×5 | 9 | **Residual.** Keep each entry with a one-line imported-symbol justification and follow-on owner. |

The separate `app.agents.discovery.tools -> app.workers.celery_app` layers
exception is **not** one of those 23 contract-2 entries and is not a fifth
class. T1 documents it with its own burn-down owner but does not move it into
`read_facade.py` or create a new framework-to-worker exception.

The earlier draft's "shrink the allowlist to `framework/traces.py` only" was
incoherent and is retracted: `app.agents.framework` is not in contract 2's
`source_modules`, so it never had — and cannot have — an allowlist entry.

- **This is NOT the write-safety claim.** Contract 2 runs with
  `allow_indirect_imports = true`; import-linter is module-granular and cannot
  distinguish a read function from a write function inside a permitted module.
  Removing the direct edges does not, and cannot, prove an agent tool is unable
  to reach a write-capable path. The write boundary is proven by T1b, not by
  the contract.
- Tool outputs byte-identical for identical data (agent evals + tool tests
  are the harness); READ_ONLY tool semantics unchanged.
- `read_facade.py` is write-free. `discovery_jobs.py` owns the named
  `discovery_runs` mutations, and `credential_access.py` owns the audited
  credential path. Automation's CR lifecycle/audit imports do not pass through
  any of these files and remain unchanged in this wave.

### T1b — Agent write-boundary negative test (NEW)

`wf-implementer`, **STRONG pinned**. Makes the R1 claim machine-enforced for real.

**What READ_ONLY actually means — pinned before the guard is written.** Per
ADR-0003/0014 (`framework/tools.py:205-218`), the classification tier governs
**device/configuration mutation and the ChangeRequest approval gate**, not SQL.
`STATE_CHANGING` is the tier that requires an approved CR (`tools.py:504-508`);
`READ_ONLY` executes directly. Under a **direct tool invocation** (the harness
defined below), the current legitimate PostgreSQL writes are exactly:

| Write | Site | Why it is legitimate |
|---|---|---|
| INSERT + UPDATE `discovery_runs` | `discovery/tools.py:38`, incl. the broker-failure FAILED salvage at `:111-116` | READ_ONLY job-launch: queues work, mutates no device |
| INSERT `audit_log` | `troubleshooting/tools.py:182,242` | Every credential decryption leaves an audit row, incl. the fail-closed refusal row |

`reasoning_traces`, `reasoning_trace_steps`, and `agent_sessions` belong to the
agent-graph/session lifecycle, not direct tool invocation. Their existing
lifecycle suites remain the proof for those writes; they are not pre-allowed in
this guard.

So a **zero-SQL-write guard cannot pass and must not be written.** The exact
claim is: **every registered READ_ONLY tool, when directly invoked, may
INSERT/UPDATE `discovery_runs`, may INSERT `audit_log`, and may not perform any
other relational operation.** In particular, append-only audit evidence may
not be updated or deleted. This does not prove the absence of Neo4j, Redis,
Celery, filesystem, cloud, or device side effects. Those dependencies are faked here for
hermeticity; device/configuration safety remains covered by the approval-gate
and transport suites.

- **Runtime write-guard (primary — covers the indirect relational case).** A
  SQLAlchemy `before_execute` event listener bound to the test engine used by
  the patched application sessionmaker inspects the operation and target table
  of every INSERT / UPDATE / DELETE and raises unless that pair is allowlisted.
  Drive **every tool in the default agent registry carrying READ_ONLY
  semantics** through it — regardless of how many modules deep the SQL call
  goes.

  The harness is a `tool.name -> invocation fixture` map. Build the registry at
  test runtime and assert exact keyset equality between that map and the
  registry's READ_ONLY census; a newly registered tool without a fixture fails
  before execution. Fixtures provide valid minimal arguments and fake SSH,
  Celery, Neo4j, LLM, credential-provider, filesystem, and cloud boundaries so
  no external side effect is mistaken for SQL proof.

  ```
  ALLOWED (write permitted under a READ_ONLY drive) — each entry justified:
    discovery_runs  INSERT/UPDATE; operational READ_ONLY job-launch lifecycle
    audit_log       INSERT only; append-only credential-access/tool audit
  DENIED (deny-by-default) — everything else, and these by name:
    change_requests, approvals, devices, device_credentials, users,
    config_snapshots / config_archives / compliance_policies, applications,
    normalized_*, topology_snapshots, ...
  ```

  **`change_requests` is DENIED, not whitelisted.** CR creation belongs to the
  *approval gate* on `STATE_CHANGING` tools (`tools.py:504-508`) — a READ_ONLY
  tool reaching it is precisely the bug this guard exists to catch.

  New allowlist entries need a justification of the same shape (operational job
  row / append-only audit), a dedicated positive test that exercises the write,
  and STRONG review. Anything that is relational domain state = review-reject.

- **Guard-bites positive test** (a guard that never fires is not a guard): a
  permanent synthetic **READ_ONLY** test tool executes
  `session.add(Device(...))`; assert the listener raises on `devices`. This
  proves the READ_ONLY policy itself bites without treating a legitimate
  STATE_CHANGING ChangeRequest write as erroneous behavior.

- **Static facade check (secondary — fast feedback).** AST test over
  `framework/read_facade.py`: only the exact SQLAlchemy read imports
  (`Select`, `func`, `select`) are accepted; mutation session methods are
  rejected; and every `session.execute(...)` argument must be rooted in a
  recognized `select()` expression. Synthetic textual-DML and aliased-update
  fixtures prove the guard bites, while an ordinary `dict.update()` proves it
  does not blacklist unrelated method names. Separate focused tests pin
  `discovery_jobs.py` to `discovery_runs`; credential-audit behavior remains
  covered by the credential service tests plus the runtime table guard.

Bite evidence for T1b: the permanent synthetic READ_ONLY
`session.add(Device(...))` case → RED. (The planted-`app.db`-import → RED bite
stays as T1's evidence; the two prove different properties and both are
required.)

### T2 — AR-W3-T1: inline-ORM extraction to services, worst 3 routers

One commit per router; endpoint contracts unchanged (route-gate tests are
the harness). Services own sessions/writes + audit; routers keep
validation/response shaping (per the Wave 4 services-vs-engines charter).

The router AST guards make a deliberately narrow claim: no direct
`app.models*` imports, no direct session mutation/execution, and no `Any`-erased
boundary annotations. SQLAlchemy session *type* imports are allowed, and an
API schema may still expose a wire enum that originates in the model layer;
those facts do not perform ORM work in a router.

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
- `Modal`/`ConfirmDialog` — replace the **6 hand-rolled modal shells total**.
  Two of those six are the verbatim-drifted ConfirmDialog pair
  (ApplicationsPage vs UsersPage, M27); the target is six, not the pair plus six.
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

**Count ratchet (gating, replaces "full migration").** A CI script asserts each
tail count `<=` baseline. Migration is non-gating; *regression* is gating. New
code may not re-roll a primitive that now exists.

**The baseline is the POST-migration count, measured at the last T3/T4 commit —
not the branch-point count.** A pre-migration baseline would let the
opportunistic adoptions be silently un-done later and still pass the gate.
Record both numbers in the PR body (branch-point → post-migration) so the
in-wave reduction is visible and the ratchet is pinned to the lower one.

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
factories cover** — and the covered set is *all of them*, because the surface
turned out to be small enough to finish in-wave.

**Full census (measured, not estimated): 13 bare `vi.mock('../api/*')` calls,
8 files, 4 modules.** The earlier "migrate the 7 auth files, stragglers
opportunistic" split was written before anyone counted; a 6-call tail across 3
modules is not a tail. **All 13 migrate in T5**, so the lint ships global with
**no allowlist and no ratchet**.

| Module | Calls | Files |
|---|---|---|
| `../api/auth` | 7 | ChangePasswordPage, Layout, LoginPage, ProfilePage, SettingsPage, SettingsRoute, UsersPage |
| `../api/changes` | 2 | axe-core-pages, ChangesPage |
| `../api/credentials` | 2 | SettingsPage, SettingsRoute |
| `../api/integrations` | 2 | SettingsPage, SettingsRoute |

- One shared test-utils module: a mock factory per module above (auth first —
  highest blast radius) + shared QueryClient render wrapper. The measured
  test-only census is **24 `new QueryClient` constructions across 22 files**;
  all 24 migrate. The production construction in `src/main.tsx` remains.
- The render helper returns both the Testing Library render result **and** the
  created `QueryClient`, so tests that inspect, clear, refetch, or seed cache
  state do not create a private client. A lint/test forbids `new QueryClient`
  under `src/__tests__/` outside the shared helper; `src/main.tsx` is the only
  production exemption.
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
  `vi.mock('../api/*')` not routed through a factory. It ships **hard — zero
  allowlist, zero ratchet** — because all 13 call sites migrate in this task.
  If a 14th surfaces mid-wave (a P4 branch adds one), migrate it too; the lint
  does not gain an exception.
- The **19 global-`fetch`-stub files are a separate surface** and stay
  opportunistic — the lint targets `vi.mock` of an `api/*` module, not fetch
  stubbing.
- Keep at least one suite exercising the real `api/client.ts` fetch →
  problem+json mapping (the F5 structural blind spot) — do not
  module-boundary-mock it away.

### T6 — SettingsPage split (M35) — **conditional**
Standing decision: deferred to "first time the settings hub is touched
again" (`docs/features/settings-hub` plan folder exists). T3/T5 touch
SettingsPage (modal shell, errorMessage, mock migration). "Non-trivial" is
**measured, not judged** — execute the split (`pages/settings/*.tsx` thin
shell, own commit in this wave) if **any** of:

1. the combined T3/T5 diff touches **more than one settings section** region; **or**
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
  - **T1b** (no prohibited indirect relational write): the permanent
    synthetic READ_ONLY `session.add(Device(...))` case → RED.

## Model & review policy

| Task | Implementer | Notes |
|------|-------------|-------|
| T1 | **STRONG pinned** | persistence boundary + credential-access secret surface |
| T1b | **STRONG pinned** | the R1 safety boundary is only as good as this test |
| T2a, T2b, T4 | strong | boundary/refactor correctness |
| T2c | **STRONG pinned** | auth surface |
| T3, T5 | light | mechanical dedupe/migration |

Quality + spec review per task; T1, T1b, and T2c reviews are STRONG-pinned.

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
- Pre-flight P4-W3 collision check clean at branch creation and at each rebase
  (`gh`, authenticated GitHub API, or recorded operator attestation — see the
  top of this doc; remote-branch scans are not accepted as PR-state evidence).
- `graphify update .` after each PR merge. **This is an operator step on the
  Claude Code host, not a CI gate and not a workflow-runner step** — `graphify`
  is not installed on every harness (it is absent from Codex). It never blocks
  a task.

## Exit criteria (AR-W2/W3 exits combined)

- **Boundary (two claims, two proofs):**
  - **T1 (no direct read/operational persistence edge in scope):** zero
    `app.db` / `app.models*` / `app.services*` / `app.knowledge*` entries
    remain for discovery and troubleshooting (8 current entries → zero). The 4
    automation write-path, 2 CR-kind metadata, and 9 engine/plugin entries
    remain explicitly enumerated with per-entry justification and burn-down
    owner; automation-port extraction is deferred to a separate STRONG-reviewed
    task. Contract proven to bite.
  - **T1b (no indirect relational-domain write under direct tool invocation):**
    the fixture map exactly matches the registry's READ_ONLY census, and every
    driven tool may INSERT/UPDATE `discovery_runs` and INSERT `audit_log` under
    the runtime operation/table guard. Everything else — explicitly including
    audit UPDATE/DELETE, `change_requests`, and `devices` — is denied; the
    synthetic READ_ONLY writes prove the guard bites. Agent-session/trace
    persistence remains covered separately.
  - Neither claim substitutes for the other.
- 3 routers have no direct model imports, session operations, or `Any`-erased
  boundary types (services own the writes), with route-gate tests green.
- **FE — enumerated duplicates gone** (all 6 modal shells total, including the
  drifted ConfirmDialog pair; VirtualizationPage `EmptyState` shadow,
  5 `PILL_BASE` badges, 4 `errorMessage()` copies). `DataTable` primitive
  exists and is adopted where touched; the 31/17/8 tails are **not** required to be zero —
  the count ratchet holds them at ≤ baseline.
- Four primary pages (Adc, Chat, Devices, Topology) migrate their server
  state per the T4 taxonomy; Packet capture start and Audit export also migrate
  to `useMutation`. Streaming stays in `useAgentStream`, and local UI state
  stays untouched.
- Central mock module + QueryClient wrapper in use with importActual
  factories; **all 13 bare `vi.mock('../api/*')` call sites migrated (auth ×7,
  changes ×2, credentials ×2, integrations ×2)**; the lint is in place with no
  allowlist; all **24 test-only QueryClient constructions across 22 files** use
  the shared helper and its lint bites; full FE suite green.
- SettingsPage decision recorded **with its measured values** (sections
  touched, shared-state yes/no, net LOC delta), split executed or deferral
  re-affirmed.
- `REVIEW-WAVES-PLAN.md` status table updated with both PR numbers.
