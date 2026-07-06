# W4-T4 — `P4-RELEASE-READINESS.md` G-* evidence; flip ADRs 0050–0053 Accepted; `PRODUCTION.md` P4 exit marker + P5 inheritance

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-release-auditor` (strong) |
| **Review tier** | **strong** quality |
| **Depends on** | W4-T1..T3 + all P4 waves merged; runs on the release HEAD |
| **ADRs** | ADR-0050…0053 (flipped here on green), ADR-0033 §1 (named-deferral discipline) |
| **PRODUCTION.md** | §1, §2.6, §11 (the P4-scoped gate slice), §12 |
| **Status** | Proposed |

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
write paths CR-only; four-eyes + audit invariants over tagging and report
access), **G-MNT** (D16 green incl. both plugins ≥80%; ADRs current; docs/API
docs per feature; new-plugin onboarding validated this wave — first wave since
the harness shipped; lockfile green), **G-OBS P4 slice** (report-generation +
derivation metrics with biting alerts; projection-lag SLO unbroken), **G-SCA/
G-REL no-regression** (P3 drill suite + `drill-bite-proofs` green with the
application layer present; rebuild drill explicitly re-verified;
certified-scale numbers stay deferred-accepted → GA unchanged), **evals**
(W4-T1 no-regression, W4-T2/T3 green AND biting with their negative
controls); every deferred-accepted item named with its promotion path
(ADR-0033 §1 — live F5/VMware golden-paths → live lab); ADR status flips +
index updates; `PRODUCTION.md` §1 P4 EXIT marker + **P5 inheritance** (Wave 4
AWS incl. Route53 + Azure; hybrid topology stitching; scale certification; GA
items riding unchanged; G-OBS reconciliation rows 5/6/9 carried
drift-guarded).

**Out** — new controls/features/evals (proof only); flipping on anything but
green, biting evidence; un-deferring live-lab items.

## Requirements (grounded in P4-PLAN §5 phase exit, house exit-gate pattern)

1. **Simultaneous green at one HEAD** — all cited evidence resolves to the
   release HEAD's CI run(s), not a mix of commits.
2. **Verify evidence, don't trust assertions** — check evidence docs + run
   URLs + green-at-HEAD before flipping (the agent-fabricated-bite-proof
   lesson); bite proofs must show the red run, not just the green one.
3. **Named, never silent** — every deferral (live lab, certified scale,
   calendar soak, pentest, break-glass cadence) named with its promotion path.
4. **The two must agree** — the §1 exit marker mirrors the readiness doc and
   P4-PLAN; ADR index statuses match the flipped files.

## Contracts / artifacts

- `docs/roadmap/P4-RELEASE-READINESS.md`; ADR-0050…0053 status flips + index;
  `PRODUCTION.md` §1 P4 EXIT marker + P5 inheritance.

## Test & gate plan

- D16 docs gates; full CI green at the release HEAD is the *subject* of the
  doc; cross-checks: ADR statuses ↔ index ↔ marker consistent; every §11
  criterion in the P4 slice has evidence or a named deferral.

## Exit criteria

- [ ] `P4-RELEASE-READINESS.md` complete: every P4-scoped §11 criterion evidenced (run URLs) or named-deferred with promotion path.
- [ ] ADRs 0050–0053 flipped Accepted on verified green, biting evidence; index updated.
- [ ] `PRODUCTION.md` P4 EXIT marker + P5 inheritance recorded; marker/plan/readiness agree.
- [ ] One atomic commit.

## Workflow

`wf-release-auditor` (strong) → **strong** quality review → fixer if findings → verifier → one atomic commit.

## Risks

- **Fabricated/never-executed proof** — the standing lesson: verify run URLs
  and red-runs personally; a bite proof that never ran red is not a bite
  proof.
- **Silent deferral** — any criterion neither evidenced nor named-deferred is
  a gate failure, not an omission.
