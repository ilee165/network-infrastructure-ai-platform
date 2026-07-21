# W4-T3 — Report conformance evals: golden CSV/PDF-structure fixtures, evidence completeness, planted-secret redaction control

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** |
| **Depends on** | **W3** (engine + four reports shipped), **W4-T0** |
| **ADRs** | ADR-0053 §1/§6/§7 (the contracts being proven) |
| **PRODUCTION.md** | §7, §11 G-SEC (P4-PLAN §5 W3/W4) |
| **Status** | Proposed |

## Objective

Build the reporting proof: **golden CSV/PDF-structure fixtures for all four
reports, evidence-completeness checks, and the redaction eval with its
planted-secret negative control proven to bite** — the load-bearing G-SEC
extension to artifacts that leave the platform.

## Scope

**In** — golden fixtures asserting on **extracted structure** (rows, headings,
table content — not raw PDF bytes; ADR-0053 §1 names PDF as structure-stable,
not byte-golden); evidence-completeness checks per kind (change: every CR in
the period; posture: trend series present incl. gap handling; access review:
break-glass events present; audit-integrity: gap-day findings + attestation
present); **redaction eval**: a deny-class field AND a PEM-formatted value
planted in a fixture payload ⇒ generation fails closed
(`redaction_violation`, exact field path plus bounded rule/type metadata only —
never the secret value or a free-form exception — and no partial artifact); **bite proof**:
a checked-in test disables the filter and asserts the independent emitted-text
scanner rejects the mutation (assert-red-inside-green); extraction
sweep: no deny-pattern match in any emitted CSV/PDF text; digest-bearing
audit-integrity fixtures do NOT false-positive (the anti-entropy decision);
CSV formula-injection cases covering `=`, `+`, `-`, `@`, TAB, CR, and LF
(hostile hostname/synthetic-cell fixtures neutralized; `ChangeRequest` has no
title field);
determinism check (same payload ⇒ same artifact content).

**Out** — changes to engine/report logic (findings route back to W3-owned
files); regime-mapping content checks beyond tag presence (W3-T6 doc is
authoritative); SIEM/report-distribution surfaces (out of P4).

## Requirements (grounded in ADR-0053 §6, P4-PLAN §0a)

1. **The planted-secret control RUNS and BITES continuously** — checked-in
   tests assert planted secrets fail closed and disabling the filter makes the
   independent emitted-text scan reject the mutation inside the otherwise-green
   blocking job. Temporary red commits are not evidence.
2. **Fail-closed verified end-to-end** — failed run recorded with typed
   `error_class`, failure names the exact field path plus a bounded rule/type
   token only (never the secret value or a free-form exception), no artifact row written,
   `netops_report_failures_total{error_class="redaction_violation"}`
   incremented.
3. **Structure-stable fixtures** — extraction-based assertions that survive
   renderer point upgrades; byte-diffs rejected as fixture form.
4. **Digests pass, secrets fail** — the SHA-256/false-positive boundary is a
   named test case in both directions.

## Contracts / artifacts

- Golden fixture set + extraction helpers; redaction eval + bite proof;
  completeness checks; evidence for the readiness doc.

## Test & gate plan

- Full gate suite; report evals green in CI at HEAD; `tests/pg/` where the
  checks query run history.
- Bite proofs run as assert-red-inside-green tests. In the ledger's T3 section,
  record only task status, focused verification commands/results, bite test
  node IDs, and the blocking-CI collection path. These are non-self-referential
  pre-commit records. T3 must not add its own commit SHA, a final release HEAD,
  or a blocking run/job URL; T4 records the landed T3 commit SHA and owns that
  final revalidation evidence. The
  fail-closed redaction assertion goes beyond the red result: the typed
  `error_class` is asserted, NO artifact row is written, and the failure
  counter increments.

## Exit criteria

- [ ] Golden structure fixtures green for all four reports (CSV + PDF, extraction-based).
- [ ] Evidence-completeness checks green per kind.
- [ ] Planted-secret redaction control + filter-disabled independent-scan mutation assert failure inside green; T3 records only task status, focused commands/results, bite test node IDs, and the blocking-CI collection path, leaving landed-task and final-release evidence to T4; digest boundary tested both ways.
- [ ] CSV formula-injection cases green; determinism check green.
- [ ] One atomic commit.

## Workflow

`wf-eval-designer` (strong) → **strong** review → fixer if findings → verifier → one atomic commit.

## Risks

- **Eval mirrors the filter** — planting only patterns the filter is known to
  catch proves nothing beyond the unit tests; the eval also sweeps emitted
  artifacts independently (extraction sweep).
- **Fixture rot on renderer upgrade** — extraction-based form is the
  mitigation; a WeasyPrint bump must not require re-golding content.
