# Wave 4 Implementation Plan — Drift Gates (AR-W0 + AR-W1 + F3)

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source findings:
[`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W0 + AR-W1,
[`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) H3 (+ M25 as codegen
beneficiary), [`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md) F3.

**Theme:** every repo-review CRITICAL lived in a *test-blind contract seam*
(F3): Helm/env keys never checked against `Settings` (C5/C6), FE/BE enums
drifting with no codegen (H14/M25), synthetic-probe auth tests proving nothing
about real routes (C1). This wave converts those conventions into enforced,
machine-checked contracts.

**Shape:** two PRs — PR-A (AR-W0 contracts & hygiene, small) then PR-B (AR-W1
drift gates + F3 contract tests, medium). Atomic commit per task.
**Every new gate must prove it bites**: plant violation → RED → revert →
GREEN; run URLs in the PR body — and per the standing lesson, plant **valid**
tamper data (an unparseable plant proves the parser aborts, not that the gate
bites). PR-body green claims re-verified at final HEAD before merge.
Dependency additions regenerate lockfiles in the same commit. Do **not**
restructure `ci.yml` here — decomposition is Wave 7.

---

## PR-A — Contracts & hygiene (AR-W0)

### T1 — Import-linter layer stack (AR-W0-T1)
`wf-implementer`, strong.

In `backend/pyproject.toml`:
- `layers` contract: `api | workers` → `services | engines | agents` →
  `plugins | knowledge | llm` → `schemas | models | db` → `core`.
- `forbidden` contract `app.agents ↛ app.db, app.models` with an explicit
  allowlist of current offenders (`agents/discovery/tools.py`,
  `agents/troubleshooting/tools.py`, `agents/framework/traces.py`,
  automation/ddi/security tools' model imports) and a written
  no-new-entries rule. Burn-down of the allowlist is Wave 6 (read-facade).
- Expect iteration: first `lint-imports` run will surface edges the review
  did not enumerate — resolve each as (a) legal → adjust contract, or
  (b) illegal → allowlist + burn-down note. Do not weaken the layer order to
  make an edge pass silently.
- **Bite proof:** scratch commit with `from app.db import ...` in a fresh
  agent module → `lint-imports` RED → revert → GREEN.

### T2a — Hygiene sweep
`wf-implementer-light`.
- Delete empty `app/services/config_archives/` package dir.
- Regenerate `docs/README.md` ADR index (0001–0053, statuses current).

### T2b — Dashboards single-source
`wf-infra`.
- Keep `deploy/observability/dashboards/` (ADR-0046 source of truth); chart
  consumes it at package/render time (copy step or configmap sourcing);
  delete `deploy/kubernetes/netops/dashboards/`.
- **Exit check:** `helm template` output byte-identical for the dashboards
  configmap before/after.

### T3 — Services-vs-engines charter (doc)
`wf-implementer-light`, reviewed strong.
- `docs/architecture/REPO-STRUCTURE.md`: **engines = stateless domain
  computation, no session ownership; services = stateful orchestration +
  persistence + audit.** Add the rule to the PR-review checklist.
- Freezes *new* code placement only; migration of existing misplacements is
  Wave 6.

## PR-B — Drift gates (AR-W1) + contract tests (F3)

### T4 — Config single-source generator + `config-drift` gate (AR-W1-T1, closes H3)
`wf-implementer`, **STRONG pinned** — secret-adjacent (KMS/KEK, OIDC,
rate-limit/lockout, SIEM, mTLS, retention knobs are exactly the fields
currently missing from `.env.example`).

- Generator introspects `Settings` → emits `.env.example` and the Helm
  configmap env-block (or their canonical fragments).
- Explicit allowlist: `NETOPS_ADMIN_PASSWORD` (migration-read, the one
  documented exception) and secret-ref fields (**never emitted into the
  configmap**).
- Field metadata (description, default, quickstart-vs-advanced grouping)
  carried into the generated `.env.example` so the operator doc quality goes
  up, not down; update the `.env.example` header + CLAUDE.md 1:1 claim to
  "generated, checked in CI".
- New CI job `config-drift`: regenerate, diff vs committed → fail on drift.
- **Bite proof:** plant an orphan field in `config.py` → RED → revert →
  GREEN.
- Closes the C5/C6-class seam (Helm-rendered keys ⊆ `Settings`) and H3
  (`.env.example` ⊇ `Settings`).

### T5 — OpenAPI→TS codegen + `contract-drift` gate (AR-W1-T2)
`wf-implementer`, strong.

- Deterministic spec export from the app factory:
  `backend/scripts/export_openapi.py` (stable ordering — sort keys/routes so
  the diff is meaningful).
- `openapi-typescript` dev-dep — lockfile regenerated same commit.
- Generate types for the `devices` + `applications` modules and **adopt
  them** in the FE source (remaining 14 modules stay hand-written this wave;
  expansion is a mechanical follow-on once the loop is proven).
- Fix M25 while adopting (`AgentSessionStatus` `"succeeded"` vs wire
  `"completed"`) only if the agents module lands in scope; otherwise leave
  for the expansion — do not hand-patch what codegen will own.
- New CI job `contract-drift`: re-export spec, regenerate types, diff → fail
  on drift.
- **Bite proof:** plant an enum mismatch → RED → revert → GREEN.
- **L-FE-1 sweep:** any FE module whose exports change → sweep every sibling
  `vi.mock` of that module.

### T6 — F3 residual contract tests
`wf-implementer`, strong. The two F3 seams not structurally closed by T4/T5:

- **Real-route auth contract test:** one test hitting a real protected route
  (not a synthetic probe) asserting the full dependency chain
  (auth → active-user guard → role) — pins the C1 class. Wave 1 already
  added real-route coverage for the forced-password-change guard; extend the
  pattern to a role-gated route matrix (one representative route per
  router × role tier), so a future router wired around `require_role`
  fails a test, not a review.
- **Transport-fixture honesty note:** `httpx.MockTransport` (hid H9) and
  fixture SSH (hid C2/C3) limitations documented in the testing guide with
  the compensating controls (H9's loop-teardown test shape from Wave 2;
  C2/C3's command-sequence asserts from Wave 3). No new harness this wave —
  live-lab/kind coverage stays the P-phase track.

### T7 — Gate wiring (AR-W1-T3)
`wf-infra`.
- `config-drift` + `contract-drift` added to the `all-gates` needs list
  (`ci.yml` `all-gates.needs`). No other `ci.yml` restructuring.
- Confirm both gates RUN and BITE post-wiring (a gate failing at setup masks
  the findings it would have produced) — re-run the bite evidence at final
  HEAD.

---

## Ordering & dependencies

```
PR-A: T1 ∥ T2a ∥ T2b ∥ T3          (independent; single small PR)
PR-B: T4 ∥ T5 → T6 → T7            (T6 rides on T5's generated types where applicable;
                                    T7 wires last)
```

- PR-A merges before PR-B (PR-B's new jobs assume the ADR index + charter
  landed; T1's contracts catch any layering the generator work introduces).
- Wave 4 before Wave 6 (FE refactors consume generated types; allowlist
  burn-down needs T1's contract in place).
- Wave 2's T16 (SHA-pinning) already merged — new jobs in this wave must use
  SHA-pinned actions from the start.
- No P4-W3 collision: touches `pyproject.toml`, generators, `ci.yml` job
  list, FE `devices`/`applications` types.

## Model & review policy

| Task | Implementer | Notes |
|------|-------------|-------|
| T1, T5, T6 | strong | contract design quality gates the whole track |
| T4 | **STRONG pinned** | secret-adjacent generator (secret-ref exclusion logic) |
| T2a, T3 | light | mechanical / doc |
| T2b, T7 | `wf-infra` | helm/CI wiring |

## Gates (per task and PR exit)

- Backend: `pytest` + `pg-integration`; `ruff check . && ruff format
  --check . && mypy && lint-imports` (T1's new contracts included).
- Frontend: vitest + typecheck + lint + coverage floor (active since W2).
- Helm: `helm template` byte-identical check for T2b; chart lint green.
- Bite-proof evidence (run URLs, valid tamper data) in both PR bodies.
- `graphify update .` after each PR merge.

## Exit criteria

- `lint-imports` layer + forbidden contracts active and proven to bite;
  allowlist enumerated with no-new-entries rule (AR-W0 exit).
- `config-drift` + `contract-drift` RED on planted drift, GREEN at HEAD,
  wired into `all-gates`; devices/applications on generated types; lockfiles
  regenerated in the same commits (AR-W1 exit). H3 closed — `.env.example`
  and Helm configmap generated from `Settings`.
- Real-route auth contract matrix in place (F3 residual closed).
- Dashboards single-sourced byte-identically; ADR index current; charter
  merged and in the review checklist.
- `REVIEW-WAVES-PLAN.md` status table updated with both PR numbers.
