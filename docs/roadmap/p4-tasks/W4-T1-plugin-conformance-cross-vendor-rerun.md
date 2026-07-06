# W4-T1 — Plugin conformance + cross-vendor eval re-run: roster extended with `f5_bigip`/`vmware`; routing no-regression

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** |
| **Depends on** | **W1** (both plugins shipped) |
| **ADRs** | ADR-0050 §8 / ADR-0051 §8 (conformance obligations), P3 W5-T2 (the previous roster baseline) |
| **PRODUCTION.md** | §2.6 ("no regression in the cross-vendor eval suite"), §11 |
| **Status** | Proposed |

## Objective

Extend the eval roster with the two Wave-3 vendors and prove **no regression**:
the M3 agent evals + supervisor-routing suite re-run across all installed
plugins with `f5_bigip` and `vmware` added, and the plugin conformance families
confirmed complete (no silently-skipped fixture case) for both.

## Scope

**In** — roster extension in the cross-vendor/routing eval corpora (the P3
W5-T2 matrix is the baseline; roster grows by two); routing cases exercising
the new vendors' surfaces (ADC inventory questions, virtualization inventory
questions) at the deterministic CI layer; conformance-completeness check: every
declared capability of both plugins has its `fixtures:*` family attached
(guards the ADR-0025 §8 silent-skip failure mode); no-regression assertion
against the recorded pre-P4 results; evidence doc section for W4-T4.

**Out** — new agent behaviors (evals prove, not build); real-LLM runs (stay
the documented opt-in manual gate — no LLM provider on the authoring host,
P4-PLAN §0); derivation/report evals (W4-T2/T3).

## Requirements (grounded in PRODUCTION.md §2.6, P4-PLAN §5)

1. **Roster genuinely extended** — the two vendors appear in the matrix with
   real cases, not placeholder rows.
2. **No-regression is comparative** — results compared against the recorded
   P3-era baseline; any delta named and justified or fixed.
3. **Conformance completeness bites** — a plugin capability without its
   fixture family fails the check (negative control: temporarily drop an
   `_INTERFACE_SPECS` entry ⇒ check goes red; the P1-W4 lesson).
4. **Deterministic CI layer only is blocking**; the real-LLM gate stays
   opt-in, documented.

## Contracts / artifacts

- Extended eval corpora + roster config; conformance-completeness check;
  baseline-comparison record for the readiness doc.

## Test & gate plan

- Full gate suite; the extended eval suites green in CI.
- Bite proof: the completeness check red on a planted missing spec entry;
  restored green at HEAD (evidence with run URLs — verify before trusting,
  2026-07 audit lesson).

## Exit criteria

- [ ] Roster includes `f5_bigip` + `vmware` with real routing/eval cases; suites green.
- [ ] No regression vs the recorded baseline (deltas named).
- [ ] Conformance-completeness check in place and proven to bite.
- [ ] One atomic commit.

## Workflow

`wf-eval-designer` (strong) → **strong** review → fixer if findings → verifier → one atomic commit.

## Risks

- **Green-at-setup** — an eval that never ran looks passed; run URLs +
  bite proofs are part of the deliverable, not optional.
- **Baseline drift** — comparing against a moving baseline hides regressions;
  pin the pre-P4 result set explicitly.
