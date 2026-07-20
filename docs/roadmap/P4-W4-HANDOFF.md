# P4 Status Report & W4 Handoff — 2026-07-20

**Audience:** agents executing P4 W4. Read this, then
[`P4-PLAN.md`](P4-PLAN.md), the [W4 task index](p4-tasks/README.md), and the
[formal T0 spec](p4-tasks/W4-T0-housekeeping.md).

## 1. Verified starting point

| Wave | State | Evidence |
|---|---|---|
| W0 — design | Merged | PR #117 |
| W1 — F5 BIG-IP + VMware | Merged | PR #118 |
| W2 — application dependencies | Merged | PRs #119 and #123 |
| W3 — compliance/audit reports | Merged | PR #166, squash `7298f4b8` (2026-07-19); 27 validated findings remediated in four fix waves; 18/18 required checks green before merge |
| W4 — evals + phase exit | Ready | T0A/T0B first, T1–T3 sequential on the shared evidence ledger, T4 last |

The W3 review report is historical evidence. Its interim grade and remediation
queue do not describe the merged state.

## 2. Owner decisions that govern W4

1. **T0 is split.** T0A is one documentation-only commit. T0B is the mandatory
   LF CSV-prefix code-plus-test commit. Architectural work does not ride in
   housekeeping.
2. **The two evaluation surfaces are distinct.** The cross-vendor/plugin-
   conformance matrix gains `f5_bigip` and `vmware`. The agent-routing roster
   remains nine with no regression; new ADC- and virtualization-inventory
   questions exercise existing agents. Do not invent agent number ten.
3. **T2 is exact-match.** The curated contract-authored corpus gates at
   precision `1.0` and recall `1.0`. Misses are adjudicated, not hidden by
   lowering the threshold. Genuinely ambiguous cases may enter a labeled
   known-hard non-gating partition only with rationale in release readiness;
   contract-defined exclusions are expected exclusions.
4. **Bite proofs live inside green.** T1's missing `_INTERFACE_SPECS` mutation,
   T2's wrong-edge and suppressed-source mutations, and T3's filter-disabled
   secret mutation are checked-in assertions that the relevant gate rejects
   mutated input. Blocking CI reruns them at every HEAD. Before their atomic
   commits exist, T1–T3 record only task status, focused commands/results, bite
   test node IDs, and the blocking-CI collection path in
   `docs/roadmap/evidence/P4-W4-evals-evidence.md`. T4 later records each
   landed task commit SHA, the single final release HEAD, and each suite's
   blocking run/job URL and result. Do not use temporary red commits or
   branches.
5. **T1, T2, and T3 are logically independent but are sequential writers.**
   After both T0 commits land, execute them in order on the shared branch
   because all three update `P4-W4-evals-evidence.md`. Each task owns only its
   named task-local ledger section. T4 runs last on the combined release HEAD
   and exclusively owns the ledger's top-level final-revalidation
   lifecycle/status and final-release-HEAD revalidation table.

## 3. Mandatory closure and named deferrals

- **Mandatory before W4-T3:** add LF to the report renderer's CSV formula-prefix
  set and cover it with a focused regression test. This is a W3 contract gap,
  delivered in its own T0B commit.
- **P5 durable-dispatch sweep:** remaining pre-P4 bare `send_task` sites are a
  named no-regression deferral. Report request paths already commit durable
  request-audit evidence before a best-effort publication attempt; P5 owns a
  platform-wide durable-dispatch sweep.
- **P5 transactional report outbox:** both request paths commit durable
  `report.generation_requested` audit evidence before attempting best-effort,
  untracked Celery publication. Duplicate requests or publication retries can
  enqueue duplicate tasks; the deterministic worker claim makes generation
  idempotent. A crash between commit and publication, or broker uncertainty,
  can leave durable requested-but-unclaimed work. Transactional outbox plus
  relay/recovery is the P5 promotion path.

These are risk-accepted, named deferrals under ADR-0033 §1, never silent
omissions. T4 must repeat them in `P4-RELEASE-READINESS.md`.

## 4. Release-readiness inheritance

T4 fills the ledger's final-release-HEAD revalidation table with each landed
T1/T2/T3 task commit SHA, one final release HEAD, and a blocking run/job URL
and result for each suite. T4 also owns the ledger's top-level lifecycle/status
and names every deferral with a promotion path: the bare `send_task` sweep and
report outbox → P5; live F5/VMware golden paths → live lab; scale certification
and the carried GA items (certified scale, 30-day soak, external pentest,
break-glass cadence) → P5/GA. ADRs 0050–0053 flip to Accepted only after all P4
gates are green and biting.
