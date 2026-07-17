# Wave 7 Implementation Plan — Retention ADR + Integration CI + CI Decomposition

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source:
[`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W4,
[`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md)
F4/F7/F8/F9, [`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) R6/R7 + M46.

**This is the closing wave** — design work (retention), the last integration
blind spot (PostgreSQL/Neo4j/Redis), and the CI restructure that must run when
nothing else is adding jobs. **Hard scheduling rule:** T4 (decomposition)
starts only after Waves 2–6 and the first Wave 7 PR are merged and no other
branch is touching `ci.yml`.

**Shape:** one PR for T1–T3 + T5 and whichever T6 items fit
(`fix/review-wave7`), then the CI decomposition (T4) as its own follow-up PR
so a revert stays clean. T6 is explicitly optional: any unlanded F7/F8 item
must be named in the residual backlog, but does not block track closure.
Atomic commit per task; moved gates re-prove they bite.

---

## T1 — Retention/partitioning ADR (AR-W4-T1, risk R6)

**STRONG + dual-strong review** (audit-surface rule). Design only —
implementation is a follow-on phase.

Scope of the ADR:
- Unbounded append-only growth: hash-chained `audit_log`, reasoning traces,
  discovery/config snapshots. The chain blocks naive pruning.
- **Checkpoint-anchored pruning** against `audit_chain_checkpoint` as the
  candidate mechanism; evaluate against archival-via-SIEM-export (the SIEM
  exporter from P3 already streams the rows out).
- Partitioning tradeoff: `audit_log`, `raw_artifacts`, `reasoning_traces`, and
  `reasoning_trace_steps` already have monthly partitions + the Wave 1
  pre-creation beat task. The ADR decides drop-old-partition vs
  archive-then-drop semantics for those parents and row-prune vs future
  partitioning for unpartitioned discovery/config snapshot tables.
- Record the audit-lock throughput ceiling (perf #7, deliberate
  ADR-0038/0042 design) as a **noted constraint** with its escape hatches
  (sharded chain keys / async outbox) — per the Wave 5 deferral this ADR is
  the venue; no implementation.
- Retention windows become `Settings` fields (Wave 4 generator picks them up
  when implemented) — name them in the ADR now.
- Number assigned at authoring (0054+, whatever P4 has consumed).

**Exit:** ADR Accepted-or-Proposed after dual-strong review; all covered table
classes have named retention windows and disposition semantics; checkpoint
continuity, the audit-lock ceiling, and sharded-chain/async-outbox escape
hatches are recorded. No retention implementation is included.

## T2 — F4: PostgreSQL + Neo4j + Redis pytest integration CI job

`wf-implementer` + `wf-infra`. Clone the proven pg-integration pattern:
- One new CI job, `graph-integration`, with **three** service containers:
  `pgvector/pgvector:pg16`, Neo4j, and Redis. Pin versions, health-gate every
  service, time-box the job, run `alembic upgrade head`, and wire
  `NETOPS_DATABASE_URL` plus the Neo4j/Redis settings to the services. Set a
  throwaway `NETOPS_ADMIN_PASSWORD` explicitly for the migration bootstrap.
- Run the formerly self-skipping graph set in this job:
  - `tests/knowledge/test_topology_impact.py::TestLiveImpactIpReach`
  - `tests/engines/topology/test_projector.py::test_live_project_then_mutate_then_incremental_sync`
  - both tests in `tests/engines/topology/test_rebuild_exit_criteria.py`
  The rebuild tests seed PostgreSQL before projecting to Neo4j, so PostgreSQL
  is a required part of this gate rather than an optional fixture.
- Add real-Redis cases for the rate-limiter (Wave 5's Lua path) and stream
  relay (pub/sub fan-out) — the in-memory fakes stay for the unit job.
- Marker discipline is mandatory and store-specific:
  - register `neo4j` and `redis` markers in `backend/pyproject.toml`;
  - mark only the live test functions/classes with both `integration` and the
    store marker — never apply module-level `pytestmark` to these mixed
    unit/integration files;
  - run `-m "integration and (neo4j or redis)"`; normalize `--collect-only`
    node IDs and diff them against a checked-in expected-node manifest so a
    dropped marker or silently deselected required test makes the job RED;
  - emit JUnit XML and fail if any selected test is skipped or if the executed
    node set differs from the collection manifest.
- Wire into `all-gates`. **Bite proof:** plant a failing assertion in a
  selected graph test → capture the RED run URL → revert in a named commit →
  capture the final GREEN run URL.
- Expect first-run failures in the previously-dark tests (F1 precedent:
  MissingGreenlet) — budget a fix commit.

**Exit:** all three services are healthy; the exact Neo4j/Redis manifest is
collected and executed with zero selected skips; real-Redis Lua + pub/sub cases
pass; `graph-integration` blocks through `all-gates`; planted-failure evidence
is recorded in the PR body.

## T3 — Drill relocation (AR-W4-T3)

`wf-implementer-light`.
- Relocate the deploy-tree production Python into `backend/app/ops/drills/`;
  move the five `test_*.py` files →
  `backend/tests/ops/drills/` so normal `testpaths = ["tests"]` collection
  includes them. Manifests stay under `deploy/`.
- Update executable paths, module/PYTHONPATH examples, and any
  `drill-bite-proofs`/harness references. Code comes under import-linter,
  mypy, and pytest (the Wave 4 layer contract must accommodate `app.ops` —
  decide its layer explicitly, don't allowlist).

**Exit:** no deploy-tree production Python imports `app.*`; all relocated
tests are collected by the normal backend suite; import-linter, mypy, targeted
drill tests, and `drill-bite-proofs` are green; the `app.ops` layer decision is
documented in the existing architecture contract.

## T4 — CI decomposition (AR-W4-T2, risk R7) — separate PR, scheduled last

`wf-infra`. Review-time baseline on main `86979cce` (2026-07-15): 2,653
lines, 18 jobs, `actions/checkout` ×17, `setup-python` ×6, `setup-node` ×3.
T2/T5 (and T6-F8 if landed) change this denominator, so T4 starts by recording
a fresh post-first-PR census in its PR body; that census is authoritative.

**Entry gate:** Waves 2–6 and the first Wave 7 PR are merged, and no other
branch is touching `ci.yml`.

- Composite actions for repeated **post-checkout** Python/Node/tool setup.
  Initial checkout remains in each job unless the whole job moves into a
  reusable workflow; a repository-local composite is not a pre-checkout
  deduplication mechanism.
- Split job families into reusable workflows — **validate reusable-workflow
  compatibility with `services:` containers first** (T2's new job included);
  if incompatible, composite-actions-only is the fallback shape, not a
  blocker.
- Consolidate the triplicated `ci/{cnpg,mtls,redis-sentinel}` helpers
  (`render-twice.sh` ×3, two parallel secret-extract scripts).
- **Exit:** every job/gate in the fresh post-first-PR census runs, including
  prior-wave coverage/config-drift/contract-drift/chunk gates; Wave 7's own
  `graph-integration` and optional `coverage-combined` gate are accounted for
  separately. `all-gates` has the complete blocking needs-list and one fully
  green run at final HEAD.
- **Re-verify one planted failure per MOVED gate** — a relocated gate that
  no longer bites is a silent regression. Check step OUTCOME, not
  conclusion, anywhere `continue-on-error` appears (T7-harness lesson).

## T5 — F9 remainder: CI hardening batch

`wf-infra`. (SHA-pinning + Node 22 shipped in Wave 2 T16.)
- Checksum-verify **every** `kubeconform` + `kube-linter` binary-download
  occurrence before extraction/install, matching the gitleaks/promtool SHA256
  pattern (refer to step names, not line numbers, because T2 moves the file).
- Bounded retry on egress steps (pip, npm, pip-audit/OSV, npm-audit) —
  reuse the KMS emulator bring-up shape: at most 3 attempts with bounded
  backoff/timeout. Retry only transient network/registry 5xx failures; a
  genuine failure must still go RED (no retry-until-green on assertions).
- **Bite proofs:** a wrong digest fails before extraction; a stubbed persistent
  5xx exhausts attempt 3 and stays RED; an assertion failure is never retried.
- Land **before** T4 so the decomposition moves hardened steps.

**Exit:** all relevant binary downloads verify trusted pinned digests; all
listed egress commands use the bounded retry policy; checksum mismatch,
persistent 5xx, and genuine tool/test failures remain blocking.

## T6 — F8 + F7 (capacity permitting; non-blocking if backlogged)

- **F8 — coverage gate semantics** (`wf-implementer-light`): add
  `[tool.coverage]` config with branch coverage, `parallel = true`,
  `relative_files = true`, and an explicit generated/migration omit list.
  Unit, `pg-integration`, and `graph-integration` emit context-labelled raw
  `.coverage.*` artifacts. A blocking `coverage-combined` job downloads all
  three, runs `coverage combine`, produces the headline XML/terminal report,
  and owns the authoritative `fail_under`; wire it into `all-gates`. Remove
  the headline floor from the unit-only step so integration-only lines are
  neither falsely missed nor omitted. Set the combined line+branch threshold
  from a green measured baseline, never below the existing 80% ratchet; add
  tests rather than lowering the floor.
- **F7 — REST vendor client error paths** (`wf-implementer-light`): one
  shared parametrized `MockTransport` fixture driving
  parsing/auth/error/timeout paths across `bluecat`, `fortios`, `panos`,
  `f5_bigip`, `vmware` clients. (Master-architect test file, compliance
  malformed-YAML edges, FE api-module tests: opportunistic; E2E layer:
  out of scope, note as backlog.)

**Exit:** if F8 lands, `coverage-combined` consumes all three artifacts,
blocks in `all-gates`, reports branch coverage, and enforces the ratcheted
threshold. If F7 lands, all five named clients exercise parsing, auth, HTTP
error, and timeout paths through the shared fixture. Any unlanded F7/F8 item
is explicitly carried into `REVIEW-WAVES-PLAN.md`'s residual backlog before
the track is marked complete.

---

## Ordering & dependencies

```
T1 ∥ T2 ∥ T3 ∥ T6-F7
     T2 ─────────► T6-F8 final coverage wiring
     [required tasks + any selected T6 work] → T5 → [PR merge] → T4 (own PR, last)
```

- T5 lands after the other first-PR CI edits and before that PR merges; T4
  therefore moves already-hardened steps.
- T6-F8 may start in parallel, but its final aggregate wiring depends on T2's
  `graph-integration` artifact. T6-F7 is independent.
- Waves 2–6 are merged on current main as of 2026-07-15. T4 still waits for
  the first Wave 7 PR and a fresh check that no branch is adding/moving jobs.
- T3's move must keep the Wave 4 import-linter green with an explicit layer
  decision for `app.ops`.
- No P4 collision for T1/T5/T6; T2 adds a CI job (coordinate with any
  in-flight P4 wave the same way); T4 blocks on every first-PR task by design.

## Model & review policy

| Task | Implementer | Review |
|------|-------------|--------|
| T1 | **STRONG pinned** | **dual-strong** (audit surface) |
| T2 | strong (+`wf-infra` wiring) | standard |
| T3, T6 | light | standard |
| T4, T5 | `wf-infra` | standard; T4 gets a moved-gate bite checklist |

## Gates (per task and PR exit)

- Standard backend/frontend/static gates. T2's PR body contains the planted
  assertion/diff, RED run URL, revert commit SHA, and final GREEN run URL.
- T4 PR body: table of moved gates × re-bite evidence; one fully green run
  at final HEAD (PR-body green claims re-verified on any edit).
- `graphify update .` after each PR merge.

## Exit criteria (closes the review-wave track)

- Retention ADR Accepted-or-Proposed through dual-strong review; retention
  windows named; audit-lock ceiling + escape hatches recorded (R6 designed).
- PostgreSQL/Neo4j/Redis integration job blocking in `all-gates`; the exact
  marker manifest runs on every PR with zero selected skips (F4 closed).
- Drill production code + tests under normal backend gates (R8 closed).
- `ci.yml` decomposed with all gates re-bite-verified (R7 closed); checksum
  + retry hardening active (F9 closed).
- Combined coverage config honest (branch + cross-job artifacts); REST vendor
  error paths covered (F8/F7 addressed or explicitly carried to backlog).
- **`REVIEW-WAVES-PLAN.md` status table updated — all 7 waves merged;
  review-remediation track complete.** Residual backlog (E2E layer, codegen
  expansion, god-file opportunistic splits, retention implementation)
  recorded there as the handoff.
