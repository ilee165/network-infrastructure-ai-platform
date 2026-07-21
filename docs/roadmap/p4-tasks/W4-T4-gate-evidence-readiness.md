# W4-T4 — `P4-RELEASE-READINESS.md` G-* evidence; flip ADRs 0050–0053 Accepted; `PRODUCTION.md` P4 exit marker + P5 inheritance

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-release-auditor` (strong) |
| **Review tier** | **strong** quality |
| **Depends on** | W4-T1..T3 + all P4 waves merged; runs on the release HEAD |
| **ADRs** | ADR-0050…0053 (flipped here on green), ADR-0033 §1 (named-deferral discipline) |
| **PRODUCTION.md** | §1, §2.6, §11 (the P4-scoped gate slice), §12 |
| **Status** | Complete — final PR HEAD `4707f09a`, run `29840145528` green |
| **Candidate composition** | Seven pre-T4 commits: six planned task commits plus bounded dependency-audit remediation `71cd249d`; T4 is the eighth planned commit, followed by an atomic validated review follow-up |

## Objective

Close the phase: author **`docs/roadmap/P4-RELEASE-READINESS.md`** with the
P4-scoped §11 gate evidence passing simultaneously on the release HEAD, **flip
ADRs 0050–0053 Proposed → Accepted** on their green, biting implementing
evidence, and add the **`PRODUCTION.md` §1 P4 EXIT marker with the P5
inheritance recorded** (mirrors P1-W7/P2-W5/P3-W5). Builds the *proof*, not new
features.

## Scope

**In** — the readiness doc with per-gate evidence (CI run URLs, `all-gates`
green at the release HEAD): **G-SEC** (P1–P3 controls no-regression;
credential-leak tests extended to report artifacts + plugin fixtures; plugin
write paths CR-only; four-eyes remains a no-regression invariant for
ChangeRequest-governed writes; manual tagging and report generation/access are
direct RBAC-controlled, fully audited, and not four-eyes gated), **G-MNT** (D16
green incl. both plugins ≥80%; ADRs current; docs/API docs per feature;
new-plugin onboarding validated this wave — first wave since the harness
shipped; lockfile green), **G-OBS P4 slice** (report-generation metrics with
their biting alert suite; the application layer preserves the existing
topology projection-lag recording rule and biting burn-rate alerts; no
derivation-specific metric/alert claim), **G-SCA/G-REL no-regression** (P3
drill suite + `drill-bite-proofs` green with the application layer present;
rebuild drill explicitly re-verified;
certified-scale numbers stay deferred-accepted → GA unchanged), **evals**
(W4-T1 no-regression, W4-T2/T3 green AND biting with their negative
controls); every deferred-accepted item named with its promotion path
(ADR-0033 §1 — live F5/VMware golden-paths → live lab); ADR status flips +
index updates; `PRODUCTION.md` §1 P4 EXIT marker + **P5 inheritance** (Wave 4
AWS incl. Route53 + Azure; hybrid topology stitching; scale certification; GA
items riding unchanged; G-OBS reconciliation rows 5/6/9 carried
drift-guarded); the evidence ledger's T4-owned top-level final-revalidation
lifecycle/status and final-release-HEAD table populated with the single release
HEAD plus each landed T1/T2/T3 task commit SHA, blocking run/job URL, and
result.

**Out** — new controls/features/evals (proof only); flipping on anything but
green, biting evidence; un-deferring live-lab items.

## Requirements (grounded in P4-PLAN §5 phase exit, house exit-gate pattern)

1. **Simultaneous green at one HEAD** — all cited evidence resolves to the
   release HEAD's CI run(s), not a mix of commits. T4 records that single final
   release HEAD once for the table and records each suite's landed task commit
   SHA in its row.
2. **Verify evidence, don't trust assertions** — check
   `docs/roadmap/evidence/P4-W4-evals-evidence.md`: T1/T2/T3 sections are
   non-self-referential records of task status, focused commands/results, bite
   test node IDs, and blocking-CI collection paths only. T4 independently owns
   the ledger's top-level lifecycle/status and populates the final table with
   each landed task commit SHA, the single final release HEAD, blocking run/job
   URL, and result before flipping. Each negative control is a checked-in
   assert-red-inside-green test, so the bite is re-proven on the release HEAD;
   temporary red branches or commits are not accepted.
3. **Named, never silent** — every deferral (bare `send_task` durable-dispatch
   sweep, transactional report outbox, live lab, certified scale, calendar
   soak, pentest, break-glass cadence) is named with its P5/live-lab/GA
   promotion path.
4. **The two must agree** — the §1 exit marker mirrors the readiness doc and
   P4-PLAN; ADR index statuses match the flipped files.

## Contracts / artifacts

- `docs/roadmap/P4-RELEASE-READINESS.md`; the T4-owned final-release-HEAD
  revalidation table in `docs/roadmap/evidence/P4-W4-evals-evidence.md`;
  ADR-0050…0053 status flips + index; `PRODUCTION.md` §1 P4 EXIT marker + P5
  inheritance.

## Test & gate plan

- D16 docs gates; full CI green at the release HEAD is the *subject* of the
  doc; cross-checks: ADR statuses ↔ index ↔ marker consistent; every §11
  criterion in the P4 slice has evidence or a named deferral.
- Revalidate T1/T2/T3 at the final combined release HEAD. Record the single
  final release HEAD and top-level lifecycle/status, then for each suite verify
  that the blocking run/job collected the expected nodes and record its landed
  task commit SHA, URL, and result in T4's final table. Task-local pre-commit
  evidence is not a substitute for final revalidation.
- The dispatch guarantee is recorded exactly: both report request paths commit
  durable `report.generation_requested` audit evidence before attempting
  best-effort, untracked Celery publication. Duplicate requests or publication
  retries can enqueue duplicate tasks; the deterministic worker claim makes
  generation idempotent. A crash between commit and publication, or broker
  uncertainty, can leave durable requested-but-unclaimed work. Transactional
  outbox plus relay/recovery is a named P5 deferral.

## Exit criteria

- [x] `P4-RELEASE-READINESS.md` complete: every P4-scoped §11 criterion evidenced (run URLs) or named-deferred with promotion path.
- [x] T4 owns and completes the top-level lifecycle/status; its final revalidation table records each landed T1/T2/T3 task commit SHA, one final release HEAD, and a resolving blocking run/job URL and green result for each suite.
- [x] ADRs 0050–0053 flipped Accepted on verified green, biting evidence; index updated.
- [x] `PRODUCTION.md` P4 EXIT marker + P5 inheritance recorded; marker/plan/readiness agree.
- [x] One atomic commit.

## Workflow

`wf-release-auditor` (strong) → **strong** quality review → fixer if findings → verifier → one atomic commit.

## Risks

- **Fabricated/never-executed proof** — verify that standing blocking jobs
  collect and run each checked-in mutation assertion at the final release SHA;
  task-local pre-commit evidence or a one-shot red result that cannot be
  re-proven at the release HEAD is not accepted.
- **Silent deferral** — any criterion neither evidenced nor named-deferred is
  a gate failure, not an omission.
