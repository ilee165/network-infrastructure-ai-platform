# AR1 Build Plan — Architecture Remediation

> **Historical source plan — superseded for execution.** Use
> [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md) for current sequencing/status
> and the linked per-wave plans (including
> [`WAVE6-PLAN.md`](WAVE6-PLAN.md)) for binding scope, censuses, PR shape, and
> gates. The details below preserve the 2026-07-10 proposal and must not be used
> as current execution instructions.

**Status:** Historical / superseded | **Date:** 2026-07-10 | **Source:** staff-architect repository review at `main` HEAD `477b51e` (3 parallel code surveys + knowledge-graph analysis, 18,370 nodes / 53,975 edges)

Original standalone remediation track derived from the review's prioritized
action list. It is retained as source history; later consolidated/per-wave
plans resolve its stale status, scope, and one-PR-per-wave assumptions.

## Source findings (condensed)

The review's verdict: a well-governed modular monolith — zero multi-file import cycles, clean plugin boundary (all 12 vendors import only `core.errors` + `schemas.discovery`), LLM providers fully isolated behind `app/llm/`, fully async DB with reader/writer split, strong CI/supply-chain/test machinery — whose weaknesses are all **conventions without enforcing contracts**.

Risks (ranked):

| # | Risk | Evidence |
|---|------|----------|
| R1 | Safety boundary conventional, not structural — agents hold raw DB sessions; import-linter enforces only 2 of ~12 packages | `app/agents/discovery/tools.py:73`, `app/agents/troubleshooting/tools.py:96`, `app/agents/framework/traces.py:21`; `backend/pyproject.toml:239-260` |
| R2 | Silent FE/BE contract drift — 16 hand-written API type modules, enums duplicated as TS string unions, no codegen | `frontend/src/api/devices.ts:12` vs Python `DeviceStatus` |
| R3 | One config knob lives in 5 surfaces (config.py, .env.example, compose, values.yaml, configmap.yaml); "1:1" contract unenforced | `deploy/kubernetes/netops/templates/configmap.yaml:16-109` |
| R4 | CLI vendor plugin copy-paste — config-mgmt lifecycle duplicated 4× (ios/eos/junos/nxos), parser helpers 3× | `plugins/vendors/*/plugin.py`, `*/parsers.py` |
| R5 | Helm default posture single-replica on every stateful tier (CNPG/sentinel toggles off); reads as GA | `deploy/kubernetes/netops/values.yaml` L332–673 |
| R6 | Unbounded append-only growth (hash-chained `audit_log`, traces, snapshots); no partitioning in 19 migrations; chain blocks naive pruning | `app/services/audit/chain.py` |
| R7 | CI monolith — one 2,449-line `ci.yml`, 16 jobs, zero composite actions | `.github/workflows/ci.yml` |
| R8 | Cross-tree code + doc sprawl — deploy-tree Python imports `app.*`; dashboards JSON duplicated in two dirs; stale ADR index | `deploy/kubernetes/netops/drills/pcap/snapshot.py:42-44`; `docs/README.md` |

Notable debt not in the risk list: god files (`core/crypto.py` 1,182 L; `api/v1/agents.py` 1,150; `plugins/base.py` 1,031; `SettingsPage.tsx` 1,598; `Settings` 503 L / ~85 fields), routers with inline ORM writes (`applications.py` 20 session ops, `devices.py` 13, `auth/users.py` 13), `services/` vs `engines/` with no placement rule, FE with no shared primitives / no query-hook layer / no code-splitting / per-file hand-rolled test mocks (L-FE-1), leftover empty `app/services/config_archives/` package dir.

Explicitly rejected by the review: microservice split; HA-defaults flip (ADR-0048 rejection stands — ship a documented `values-prod-ha.yaml` profile instead); router-prefix renames.

## 0. Scope discipline

- One PR per wave. Atomic commit per task (unit of resumability — kill-safe).
- Zero behavior change except where a task says otherwise. Refactor waves ride on existing test suites as the regression harness; suites pass **unmodified** except where a task explicitly migrates test scaffolding.
- Every **new CI gate must prove it bites**: plant a violation → gate RED → revert → GREEN; evidence (run URLs) in the PR body. A gate failing at setup is not a gate biting.
- Architecture changes get ADRs (numbers assigned at authoring — P4 may consume 0054+ first).
- Dependency additions regenerate `requirements.lock.txt` / `package-lock.json` in the **same commit** (lockfile gate).

## 0a. Lessons carried (LESSONS.md + phase history — applied here)

- **L-FE-1**: any FE module gaining a new `api/*` export → sweep every sibling `vi.mock` of that module. AR-W1-T2 and all of AR-W3 are exposed; AR-W3-T4 kills the class.
- **pg-marker rule**: new `tests/pg/*.py` must carry `pytestmark = pytest.mark.integration`; prove via `-m integration --collect-only`.
- **Secret-surface → STRONG model, pinned explicitly** (never "inherit") — auth router extraction, config/secrets generator, any `crypto.py` split.
- **Parallel-build shares bug classes**: a fix landed in one refit vendor is swept to siblings in the same commit series.
- **After any mid-run kill: trust git, not the result object** — salvage gates-green trees, focused-rerun only the gaps.

## 1. Scope

| In | Out |
|---|---|
| Import-layer contracts + agent DB-access facade (R1) | Microservice split |
| FE/BE contract codegen + drift gate (R2) | HA default flip (documented `values-prod-ha.yaml` profile only, if requested) |
| Config single-source + drift gate (R3) | Router prefix renames |
| `cli_common` vendor dedupe (R4) | SettingsPage split (deferred to opportunistic policy) |
| Router ORM-write extraction, worst 3 (partial R1) | New product features |
| FE platform kit: primitives, query hooks, lazy routes, central mocks | |
| Retention/partitioning ADR (R6, design only) | Retention implementation (needs the ADR first) |
| CI decomposition + drill relocation (R7, R8) | |

## 2. Agent capability review (roles per `.claude/agents/`)

| Role | Used for | Tier |
|---|---|---|
| `wf-implementer` | contracts, generators, codegen, facade, cli_common, router extraction | strong (pin explicitly) |
| `wf-implementer-light` | hygiene sweep, FE primitives, drill relocation, mock centralization | cheap |
| `wf-infra` | CI job wiring, dashboards single-source, composite actions | strong |
| `wf-quality-reviewer` / `wf-spec-reviewer` → `wf-fixer` → `wf-verifier` | per-task review cycle, as in P2–P4 | escalate STRONG on auth/config/crypto tasks |

Escalation triggers in this plan: AR-W1-T1 (touches secret refs in `Settings`), AR-W3-T1c (`auth/users.py`), any future `crypto.py` split.

## 3. Build waves (dependency-ordered)

### AR-W0 — Contracts & hygiene (S, ~1–2 days, 1 PR)

- **T1 — Import-linter layer stack** (`wf-implementer`, strong). In `backend/pyproject.toml`: add a `layers` contract — `api | workers` → `services | engines | agents` → `plugins | knowledge | llm` → `schemas | models | db` → `core` — plus a `forbidden` contract `app.agents ↛ app.db, app.models` with an explicit allowlist of the current offenders (`agents/discovery/tools.py`, `agents/troubleshooting/tools.py`, `agents/framework/traces.py`, automation/ddi/security tools' model imports) and a written no-new-entries rule. Expect iteration: the first `lint-imports` run will surface edges the review did not enumerate — resolve each as (a) legal → adjust contract, or (b) illegal → allowlist + burn-down. **Bite proof**: scratch commit with `from app.db import ...` in a fresh agent module → `lint-imports` RED.
- **T2a — Hygiene** (`wf-implementer-light`). Delete empty `app/services/config_archives/` package dir; regenerate `docs/README.md` ADR index (0001–0053).
- **T2b — Dashboards single-source** (`wf-infra`). Keep `deploy/observability/dashboards/` (ADR-0046 source of truth); the chart consumes it at package/render time (copy step or configmap sourcing); delete `deploy/kubernetes/netops/dashboards/`. **Exit check**: `helm template` output byte-identical for the dashboards configmap before/after.
- **T3 — Services-vs-engines charter** (doc, `wf-implementer-light`, reviewed strong). In `docs/architecture/REPO-STRUCTURE.md`: **engines = stateless domain computation, no session ownership; services = stateful orchestration + persistence + audit.** Add the rule to the PR-review checklist. Freezes *new* code placement; migration is AR-W3.

### AR-W1 — Drift gates (M, ~3–5 days, 1 PR; T1 ∥ T2)

- **T1 — Config single-source** (`wf-implementer`, **STRONG pinned** — secret-adjacent). Generator introspects `Settings` → emits `.env.example` and the Helm configmap env-block (or their canonical fragments). Explicit allowlist for the one documented exception (`NETOPS_ADMIN_PASSWORD`, migration-read) and for secret-ref fields (never emitted into the configmap). New CI job `config-drift` diffs generated vs committed. **Bite proof**: plant an orphan field in `config.py` → RED.
- **T2 — OpenAPI→TS codegen** (`wf-implementer`, strong). Deterministic spec export from the app factory (`backend/scripts/export_openapi.py`); `openapi-typescript` dev-dep (lockfile same-commit); generate types for the `devices` + `applications` modules and adopt them (remaining 14 modules stay hand-written this wave). CI job `contract-drift` regenerates and diffs. **Bite proof**: plant an enum mismatch → RED. Sweep sibling `vi.mock`s (L-FE-1) for any changed exports.
- **T3 — Gate wiring** (`wf-infra`). Both jobs added to the `all-gates` needs list (`ci.yml` `all-gates.needs`). Do **not** restructure `ci.yml` here — that is AR-W4-T2.

### AR-W2 — Structural dedupe & agent boundary (L, ~1.5–2 weeks, 1–2 PRs; T1 ∥ T2)

- **T1 — `plugins/vendors/cli_common/`** (`wf-implementer`, **STRONG** — the config-mgmt lifecycle is a change-safety surface). Extract the shared lifecycle mixin (`_run/_execute/_diff_summary/_rollback_to_baseline/_require_executing/_replace_config/_send_config`) + textfsm parser helpers (`_parse_with_template/_int_or_none/_address_or_none/_statuses`). Refit **one vendor per atomic commit**: base → cisco_ios → eos → cisco_nxos → junos. Per-vendor parity/plugin suites (35 test files) stay green **unchanged** after each commit. Any behavioral divergence discovered between the 4 copies is a *finding*, not a silent unification — surface it, decide, document in the commit message. Must land **before** the next CLI vendor wave.
- **T2 — Agent read-facade** (`wf-implementer`, strong; depends on W0-T1). Read-only repository/service functions (extend the `knowledge/topology_read.py` pattern) replace raw `app.db` use in `agents/discovery/tools.py` + `agents/troubleshooting/tools.py`; shrink the W0 allowlist to `framework/traces.py` only and tighten the contract. Outcome: agents structurally cannot write outside `services/change_requests`.

### AR-W3 — Router extraction & frontend platform kit (L, ~1.5 weeks, 2 PRs — backend and frontend independent)

**PR-A (backend):**
- **T1 — Inline-ORM extraction to services**, one commit per router: (a) `applications.py` (20 session ops), (b) `devices.py` (13), (c) `auth/users.py` (13 — **STRONG pinned**, auth surface). Endpoint contracts unchanged (route-gate tests are the harness); any new PG-semantic tests go in `tests/pg/` with the integration marker.

**PR-B (frontend):**
- **T2 — Primitives** (`wf-implementer-light`): shared `Table/Badge/Modal/ConfirmDialog/EmptyState`; replace the known duplicates (ConfirmDialog ×2, KindBadge ×2, EmptyState shadow) and migrate pages opportunistically.
- **T3 — Query layer** (`wf-implementer`): `src/hooks/` per-domain query hooks + central queryKeys registry; migrate the 4 imperative pages (Adc, Chat, Devices, Topology) onto react-query; `useAgentStream` hook wrapping the ChatPage WebSocket lifecycle (`ChatPage.tsx:160-224`).
- **T4 — Mocks + splitting** (`wf-implementer-light`): central `api/*` test-mock module; migrate the 7 hand-mocked auth files + 19 fetch-stub files incrementally (kills the L-FE-1 class); route-level `React.lazy` with cytoscape as its own chunk; verify the `dist/` chunk split in the build gate.

### AR-W4 — Design & background (M, ~1 week, 1 PR + 1 ADR)

- **T1 — Retention/partitioning ADR** (STRONG + dual-strong review, per audit-surface rule). Checkpoint-anchored pruning against `audit_chain_checkpoint`; partitioning vs archival-via-SIEM-export tradeoff; covers `audit_log`, reasoning traces, discovery/config snapshots. Design only — implementation is a follow-on phase.
- **T2 — CI decomposition** (`wf-infra`; **after** W1-T3 lands its jobs). Composite actions for the repeated setup blocks (checkout ×33, setup-python ×4, setup-node ×2); split job families into reusable workflows; consolidate the triplicated `ci/{cnpg,mtls,redis-sentinel}` helpers (`render-twice.sh` ×3, two parallel secret-extract scripts). **Exit**: all pre-existing jobs + the two W1 gates run, `all-gates` intact, one fully green run at HEAD; validate reusable-workflow compatibility with `services:` containers before committing to that shape. Re-verify one planted failure per *moved* gate (a relocated gate that no longer bites is a silent regression).
- **T3 — Drill relocation** (`wf-implementer-light`): `deploy/kubernetes/netops/drills/*` Python → `backend/app/ops/drills/` (manifests stay under `deploy/`); update `drill-bite-proofs` paths; the code comes under import-linter, mypy, and pytest.
- **Standing policy (no task)**: god-file splits (`crypto.py` → `core/kms/{providers,envelope,rotation}`, `api/v1/agents.py` → sessions/stream/tickets routers, `plugins/base.py` → per-capability modules, `SettingsPage.tsx` → per-section files, `Settings` → nested groups) happen opportunistically when a file is next touched — no dedicated refactor PRs. `crypto.py` is always STRONG.

## 4. Sequencing & P4 collision matrix

```
AR-W0 ──► AR-W1 ──► AR-W2 ──► AR-W3 ──► AR-W4
 (W2-T2 needs W0-T1; W4-T2 needs W1-T3; other tasks parallelize within their wave)
```

- **Safe to run now**: AR-W0, AR-W1, AR-W2 touch files P4-W3/W4 (compliance reporting) will not — pyproject contracts, generators, `plugins/vendors/*`, agent tools.
- **Coordinate**: AR-W3 PR-A (routers/services) vs P4-W3 (compliance endpoints land in `api/` + `services/`) — run AR-W3 **before or after** P4-W3, not concurrently. AR-W3 PR-B (frontend-wide) vs any P4 UI task — same rule.
- **Last**: AR-W4-T2 restructures `ci.yml` — schedule when no other wave is adding jobs.
- Run `graphify update .` after each wave (AST-only, no API cost).

## 5. Per-wave exit criteria

| Wave | Exit |
|---|---|
| W0 | `lint-imports` bites on a planted violation (evidence in PR); helm dashboards render byte-identical; ADR index current; charter merged and in the review checklist |
| W1 | `config-drift` + `contract-drift` RED on planted drift, GREEN at HEAD, wired into `all-gates`; devices/applications on generated types; lockfiles regenerated in the same commits |
| W2 | 4 vendors on `cli_common` with parity suites green unchanged; agents↛db allowlist = `framework/traces.py` only |
| W3 | 3 routers ORM-free (services own the writes) with route-gate tests green; FE duplicates gone; 4 pages on react-query; central mock module in use; ≥2 JS chunks with cytoscape split; full FE suite green |
| W4 | Retention ADR through dual-strong review; CI green at HEAD post-decomposition with moved gates re-bite-verified; drills under backend gates |

## 6. Open items (non-blocking, carry forward)

- `values-prod-ha.yaml` documented HA profile (R5) — operator decision; one `wf-infra` task when wanted.
- Codegen expansion from 2 to all 16 FE API modules — mechanical follow-on after W1 proves the loop.
- Retention ADR **implementation** — next phase after W4-T1 acceptance.
- `SettingsPage.tsx` split — first time the settings hub is touched again (`docs/features/settings-hub` plan folder already exists).

**Estimated elapsed**: ~5–6 weeks serial; ~3–4 weeks with W1/W2 internal parallelism and the W3 FE/BE PR split.
