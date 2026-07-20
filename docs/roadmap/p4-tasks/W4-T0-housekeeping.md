# W4-T0 — Execution-contract housekeeping and LF CSV-prefix closure

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | implementer |
| **Review tier** | sonnet |
| **Depends on** | W3 merged at `7298f4b8` |
| **ADRs** | ADR-0033 §1 (named deferrals), ADR-0053 §6–§7 (report export contract) |
| **Status** | Approved |

## Objective

Establish the authoritative W4 execution contract and close W3's remaining LF
CSV-injection gap before the eval suites are authored. T0 is deliberately split
into one documentation task and one code-plus-test task so architectural work
does not hide in housekeeping and each atomic commit remains independently
resumable.

## Scope

### T0A — planning and handoff contract

**In** — correct stale W3 status; commit the W4 handoff; distinguish the
cross-vendor/plugin-conformance matrix from the unchanged nine-agent routing
roster; bind T2 to precision `1.0` and recall `1.0`; standardize all W4 negative
controls on checked-in assert-red-inside-green tests; seed
`docs/roadmap/evidence/P4-W4-evals-evidence.md` with explicitly pending,
section-owned T1/T2/T3 placeholders for task status, focused commands/results,
bite test node IDs, and the blocking-CI collection path, plus a T4-owned
top-level lifecycle/status and final-release-HEAD revalidation table containing
landed task commit SHAs; name the bare `send_task` sweep and transactional
outbox as P5 deferrals under ADR-0033 §1; record the current report-dispatch
guarantee exactly.

**Out** — product code, eval implementation, dispatch refactors, outbox schema
or relay, and release-readiness status flips.

**Commit:** `docs(p4): establish W4 execution contract`

### T0B — mandatory LF CSV-prefix fix

**In** — add LF to the report renderer's dangerous spreadsheet-formula prefix
set and add a regression test for an LF-leading cell. This closes W3's own CSV
injection contract before W4-T3 authors conformance fixtures against the
complete prefix set.

**Out** — sibling dispatch routes, an outbox, or unrelated report changes.

**Commit:** `fix(reports): neutralize LF-prefixed CSV cells`

## Decisions and deferrals

- **Mandatory in P4:** LF-leading CSV cells are neutralized and tested in T0B.
- **P5 durable-dispatch sweep:** pre-P4 bare `send_task` sites outside the
  remediated report request paths are a named no-regression deferral, with a P5
  sweep as the promotion path.
- **P5 transactional outbox:** both report request paths commit durable
  `report.generation_requested` audit evidence before attempting best-effort,
  untracked Celery publication. Duplicate requests or publication retries can
  enqueue duplicate tasks; the deterministic worker claim makes generation
  idempotent. A crash between commit and publication, or broker uncertainty,
  can leave durable requested-but-unclaimed work. Transactional outbox plus
  relay/recovery is promoted to P5 rather than added to the proof-only W4 wave.

## Test and gate plan

- T0A: focused stale-language and Markdown-link scan; verify W4 specs agree on
  roster semantics, exact-match thresholds, task-local versus final-release
  evidence ownership, evidence path, and named deferrals; run
  `git diff --check`.
- T0B: add `"\npayload"` to the dangerous-prefix parametrization and observe
  the focused test fail; add LF to `_FORMULA_PREFIXES`; run the focused renderer
  tests, Ruff on the implementation and test files, and `git diff --check`.

## Exit criteria

### T0A

- [ ] W3 is recorded as merged-green PR #166; superseded mid-review status is absent.
- [ ] W4 handoff and task specs agree: vendor matrix +2, routing roster remains nine.
- [ ] T2 gates the curated corpus at precision `1.0` and recall `1.0`.
- [ ] T1–T3 negative controls are checked-in assert-red-inside-green tests; T4 records final blocking run/job URLs and results in `docs/roadmap/evidence/P4-W4-evals-evidence.md`.
- [ ] The explicitly pending ledger limits T1/T2/T3 sections to task status, focused commands/results, bite test node IDs, and blocking-CI collection paths; T4 alone owns the top-level lifecycle/status and records landed task commit SHAs plus the single final release HEAD, run/job URLs, and results.
- [ ] Bare `send_task` sweep and transactional outbox are named P5 deferrals with the exact current dispatch guarantee.
- [ ] Documentation checks pass and exactly one docs commit is created.

### T0B

- [ ] LF-leading CSV cells are neutralized by the same contract as every other formula lead.
- [ ] The regression test is proven red before the implementation change and green after it.
- [ ] Focused tests, Ruff, and `git diff --check` pass and exactly one code-plus-test commit is created.

## Sequencing

T0A and T0B land first as separate atomic commits. W4-T1, W4-T2, and W4-T3 are
logically independent, but execute sequentially on the shared branch because
each updates its own task-local section of one evidence ledger. W4-T4 audits
their combined release HEAD and alone populates the final revalidation table.

## Risks

- **Housekeeping scope creep** — T0 contains only the contract repair and the
  one-character W3 contract closure; durable dispatch architecture stays named
  and visible in P5.
- **Threshold theater** — curated-corpus misses are adjudicated as fixture or
  pipeline defects; the `1.0`/`1.0` gate is never lowered for convenience.
- **Rotting bite evidence** — negative controls execute inside green blocking
  jobs at every HEAD rather than relying on one-shot red commits.
