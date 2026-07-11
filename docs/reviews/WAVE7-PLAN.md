# Wave 7 Implementation Plan — Retention ADR + Integration CI + CI Decomposition

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source:
[`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W4,
[`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md)
F4/F7/F8/F9, [`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) R6/R7 + M46.

**This is the closing wave** — design work (retention), the last integration
blind spot (Neo4j/Redis), and the CI restructure that must run when nothing
else is adding jobs. **Hard scheduling rule:** T4 (decomposition) starts only
after Waves 2–6 are merged and no other branch is touching `ci.yml`.

**Shape:** one PR for T1–T3 + T5/T6 (`fix/review-wave7`), the CI
decomposition (T4) as its own follow-up PR so a revert stays clean.
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
- Partitioning tradeoff: the four partitioned tables already have monthly
  partitions + the Wave 1 pre-creation beat task — the ADR decides
  drop-old-partition vs archive-then-drop semantics per table class.
- Record the audit-lock throughput ceiling (perf #7, deliberate
  ADR-0038/0042 design) as a **noted constraint** with its escape hatches
  (sharded chain keys / async outbox) — per the Wave 5 deferral this ADR is
  the venue; no implementation.
- Retention windows become `Settings` fields (Wave 4 generator picks them up
  when implemented) — name them in the ADR now.
- Number assigned at authoring (0054+, whatever P4 has consumed).

## T2 — F4: Neo4j + Redis pytest integration CI job

`wf-implementer` + `wf-infra`. Clone the proven pg-integration pattern:
- New CI job `graph-integration` (or two: neo4j/redis) with neo4j + redis
  **service containers**, health-gated, time-boxed.
- Unskip the self-skipping graph tests
  (`tests/knowledge/test_topology_impact.py:391`, `test_projector.py:759`,
  `engines/topology/test_rebuild_exit_criteria.py:370,438`) in this job —
  and make the job **fail on deselection/skip** of its marked set, mirroring
  the pg-integration guard (the F1 lesson: a dark test set reads green).
- Add real-Redis cases for the rate-limiter (Wave 5's Lua path) and stream
  relay (pub/sub fan-out) — the in-memory fakes stay for the unit job.
- Marker discipline: `pytestmark = pytest.mark.integration` (+ a
  `neo4j`/`redis` marker if the job splits); prove collection via
  `-m integration --collect-only`.
- Wire into `all-gates`. **Bite proof:** plant a failing assertion in an
  unskipped graph test → job RED → revert.
- Expect first-run failures in the previously-dark tests (F1 precedent:
  MissingGreenlet) — budget a fix commit.

## T3 — Drill relocation (AR-W4-T3)

`wf-implementer-light`.
- Move `deploy/kubernetes/netops/drills/*` Python →
  `backend/app/ops/drills/` (manifests stay under `deploy/`); kills the
  deploy-tree `app.*` import (risk R8).
- Update `drill-bite-proofs` paths; code comes under import-linter, mypy,
  pytest (the Wave 4 layer contract must accommodate `app.ops` — decide its
  layer explicitly, don't allowlist).

## T4 — CI decomposition (AR-W4-T2, risk R7) — separate PR, scheduled last

`wf-infra`. The 2,449-line 16-job `ci.yml`:
- Composite actions for repeated setup blocks (checkout ×33,
  setup-python ×4, setup-node ×2).
- Split job families into reusable workflows — **validate reusable-workflow
  compatibility with `services:` containers first** (T2's new job included);
  if incompatible, composite-actions-only is the fallback shape, not a
  blocker.
- Consolidate the triplicated `ci/{cnpg,mtls,redis-sentinel}` helpers
  (`render-twice.sh` ×3, two parallel secret-extract scripts).
- **Exit:** all pre-existing jobs + every gate added in Waves 2–6 (coverage
  floor, config-drift, contract-drift, chunk gate, graph-integration) run;
  `all-gates` needs-list intact; one fully green run at HEAD.
- **Re-verify one planted failure per MOVED gate** — a relocated gate that
  no longer bites is a silent regression. Check step OUTCOME, not
  conclusion, anywhere `continue-on-error` appears (T7-harness lesson).

## T5 — F9 remainder: CI hardening batch

`wf-infra`. (SHA-pinning + Node 22 shipped in Wave 2 T16.)
- Checksum-verify `kubeconform` + `kube-linter` binary downloads
  (`ci.yml:741-751`), matching the gitleaks/promtool SHA256 pattern.
- Bounded retry on egress steps (pip, npm, pip-audit/OSV, npm-audit) —
  reuse the kms compose bring-up retry shape (`ci.yml:1756-1771`). Retries
  bound transient 5xx only; a genuine failure must still go RED (no
  retry-until-green on assertions).
- Land **before** T4 so the decomposition moves hardened steps.

## T6 — F8 + F7 (capacity permitting)

- **F8 — coverage gate semantics** (`wf-implementer-light`): add
  `[tool.coverage]` config — branch coverage on, explicit omit list
  (generated/migration code), and per-job coverage contexts so
  pg/graph-integration-only code stops counting as missed in the headline.
  Keep the floor a ratchet (never lower it to make branch coverage pass —
  set the branch floor at current-actual and ratchet up).
- **F7 — REST vendor client error paths** (`wf-implementer-light`): one
  shared parametrized `MockTransport` fixture driving
  parsing/auth/error/timeout paths across `bluecat`, `fortios`, `panos`,
  `f5_bigip`, `vmware` clients. (Master-architect test file, compliance
  malformed-YAML edges, FE api-module tests: opportunistic; E2E layer:
  out of scope, note as backlog.)

---

## Ordering & dependencies

```
T1 ∥ T2 ∥ T3 ∥ T6  →  T5  →  [PR merge]  →  T4 (own PR, last)
```

- T5 before T4 (decomposition moves already-hardened steps).
- T4 strictly after Waves 2–6 merged + T2's job exists (nothing else adding
  CI jobs — the standing "schedule last" rule).
- T3's move must keep the Wave 4 import-linter green with an explicit layer
  decision for `app.ops`.
- No P4 collision for T1/T5/T6; T2 adds a CI job (coordinate with any
  in-flight P4 wave the same way); T4 blocks on everything by design.

## Model & review policy

| Task | Implementer | Review |
|------|-------------|--------|
| T1 | **STRONG pinned** | **dual-strong** (audit surface) |
| T2 | strong (+`wf-infra` wiring) | standard |
| T3, T6 | light | standard |
| T4, T5 | `wf-infra` | standard; T4 gets a moved-gate bite checklist |

## Gates (per task and PR exit)

- Standard backend/frontend/static gates; T2's job green with bite proof
  (run URLs, valid tamper data) in the PR body.
- T4 PR body: table of moved gates × re-bite evidence; one fully green run
  at final HEAD (PR-body green claims re-verified on any edit).
- `graphify update .` after each PR merge.

## Exit criteria (closes the review-wave track)

- Retention ADR Accepted-or-Proposed through dual-strong review; retention
  windows named; audit-lock ceiling + escape hatches recorded (R6 designed).
- Neo4j/Redis integration job blocking in `all-gates`; formerly self-skipping
  tests run on every PR; deselection guard active (F4 closed).
- Drill code under backend gates (R8 closed).
- `ci.yml` decomposed with all gates re-bite-verified (R7 closed); checksum
  + retry hardening active (F9 closed).
- Coverage config honest (branch + contexts); REST vendor error paths
  covered (F8/F7 addressed or explicitly carried to backlog).
- **`REVIEW-WAVES-PLAN.md` status table updated — all 7 waves merged;
  review-remediation track complete.** Residual backlog (E2E layer, codegen
  expansion, god-file opportunistic splits, retention implementation)
  recorded there as the handoff.
