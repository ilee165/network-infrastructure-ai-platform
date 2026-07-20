# W4-T1 — Plugin conformance + cross-vendor eval re-run: vendor matrix extended; nine-agent routing roster unchanged

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** |
| **Depends on** | **W1** (both plugins shipped), **W4-T0** |
| **ADRs** | ADR-0050 §8 / ADR-0051 §8 (conformance obligations), P3 W5-T2 (the previous roster baseline) |
| **PRODUCTION.md** | §2.6 ("no regression in the cross-vendor eval suite"), §11 |
| **Status** | Proposed |

## Objective

Extend the vendor/plugin conformance matrix with the two Wave-3 vendors and
prove **no regression**: the M3 agent evals + supervisor-routing suite re-run
across all installed plugins with `f5_bigip` and `vmware` added, and the plugin
conformance families confirmed complete (no silently-skipped fixture case) for
both. The nine-agent routing roster remains unchanged.

## Scope

**In** — the P3 W5-T2 cross-vendor/plugin-conformance matrix is the baseline
and grows by two vendor entries, `f5_bigip` and `vmware`; the separate
**nine-agent routing roster remains unchanged** with no regression. New routing
cases exercise the new vendor surfaces (ADC-inventory and
virtualization-inventory questions) through existing agents at the deterministic
CI layer; conformance-completeness check: every
declared capability of both plugins has its `fixtures:*` family attached
(guards the ADR-0025 §8 silent-skip failure mode); no-regression assertion
against the recorded pre-P4 results; evidence doc section for W4-T4.

**Out** — new agent behaviors (evals prove, not build); real-LLM runs (stay
the documented opt-in manual gate — no LLM provider on the authoring host,
P4-PLAN §0); derivation/report evals (W4-T2/T3).

## Requirements (grounded in PRODUCTION.md §2.6, P4-PLAN §5)

1. **Vendor/plugin conformance matrix genuinely extended** — the two vendors
   appear in the matrix with real cases, not placeholder rows; the nine-agent
   routing roster remains unchanged.
2. **No-regression is comparative** — results compared against the recorded
   P3-era baseline; any delta named and justified or fixed.
3. **Conformance completeness bites continuously** — an in-suite test
   monkeypatches out an `_INTERFACE_SPECS` entry and asserts the completeness
   gate rejects the mutation (assert-red-inside-green). No temporary red commit
   or branch is evidence.
4. **Deterministic CI layer only is blocking**; the real-LLM gate stays
   opt-in, documented.

## Contracts / artifacts

- Extended vendor/plugin eval corpora + unchanged routing roster config;
  conformance-completeness check; baseline-comparison record for the readiness
  doc.

## Test & gate plan

- Full gate suite; the extended eval suites green in CI.
- Baseline-comparison mechanics: the recorded pre-P4 (P3-era) result set is
  pinned as a fixture and the suite explicitly compares current results
  against it, failing on any regression delta — green-in-CI alone is
  insufficient.
- Bite proof: the checked-in suite asserts the completeness check fails on a
  monkeypatched missing `_INTERFACE_SPECS` entry while the containing test
  remains green.
  In the ledger's T1 section, record only task status, focused verification
  commands/results, bite test node IDs, and the blocking-CI collection path.
  These are non-self-referential pre-commit records. T1 must not add its own
  commit SHA, a final release HEAD, or a blocking run/job URL; T4 records the
  landed T1 commit SHA and owns final revalidation evidence.

## Exit criteria

- [ ] Vendor matrix includes `f5_bigip` + `vmware`; the nine-agent routing roster remains unchanged and new vendor-surface routing cases are green.
- [ ] No regression vs the recorded baseline (deltas named).
- [ ] Conformance-completeness check in place and proven to bite.
- [ ] T1 ledger section records only task status, focused commands/results, bite test node IDs, and the blocking-CI collection path; landed-task and final-release evidence remain pending for T4.
- [ ] One atomic commit.

## Workflow

`wf-eval-designer` (strong) → **strong** review → fixer if findings → verifier → one atomic commit.

## Risks

- **Green-at-setup** — an eval that never ran looks passed; focused results and
  collected node IDs are part of T1's deliverable, while T4 independently owns
  the final blocking run/job URL and result.
- **Baseline drift** — comparing against a moving baseline hides regressions;
  pin the pre-P4 result set explicitly.
