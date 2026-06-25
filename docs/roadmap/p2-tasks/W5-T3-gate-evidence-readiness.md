# W5-T3 — G-* Gate Evidence + P2-Security Readiness; Flip ADRs 0034–0041 → Accepted

| | |
|---|---|
| **Wave** | P2 W5 — Evals + phase-exit gate (the phase-exit gate itself) |
| **Owner** | `wf-release-auditor` (strong — phase-exit gate evidence + readiness synthesis) |
| **Review tier** | **strong** quality (the release verdict; cited evidence per gate) |
| **Depends on** | **W5-T1** + **W5-T2** (eval proof) + **W4** (hardening controls) + W1/W2/W3 (capability + vendors + agent) |
| **ADRs** | flips **ADR-0034…0041** Proposed → Accepted; ADR-0033 §1 deferred-accepted discipline (named, never silent) |
| **PRODUCTION.md** | §11 (G-SEC / G-MNT / G-OBS / G-SCA / G-REL), §1 (amended by W0-T9) |
| **Status** | Proposed |

## Objective

The **phase-exit gate**. Re-evaluate each named **G-*** gate against **live
repo/CI/sign-off evidence** on the release HEAD, write the **P2-Security
release-readiness evidence doc**, and on green flip **ADRs 0034–0041 → Accepted**
and the roadmap. Records **G-SCA + G-REL-live drills as deferred-accepted →
P3-Platform** — named, never silent. Mirrors P1-W7's release gate / M5-T20. Builds
the *proof*; edits no product code.

## Scope

**In** (`docs/roadmap/P2-RELEASE-READINESS.md` + ADR status flips + roadmap/index
updates — docs only)
- **Per-gate re-eval on the P2 slice** of §11, each with cited evidence:
  - **G-SEC PASS**: firewall analysis (W5-T1 thresholds met) + injection boundary on
    the new agent (W5-T2 / ADR-0033) + hash-chain verify bites (W4-T1) + cred-rotation
    no-leak + scope-deny (W4-T2) + mTLS handshake/plaintext-refused on kind (W4-T4) +
    collector deny on kind (W4-T5). **Inherits all P1 G-SEC controls.**
  - **G-MNT PASS** (continuous): D16 green, ADR currency (0034–0041 Accepted on
    flip), Wave-2 plugin onboarding validated from template, `PRODUCTION.md` amended
    (W0-T9).
  - **G-OBS PASS** (continuous slice): `/metrics` + probes + trace correlation
    unchanged; **no new SLO enforcement claimed** (that is P3-Platform).
  - **G-SCA — DEFERRED-ACCEPTED → P3-Platform** (HA/scale-out moved out, §0). Named.
  - **G-REL — P1 baseline holds; live failover/soak/scale drills DEFERRED →
    P3-Platform.** Named.
- **ADR flips**: 0034–0041 Proposed → Accepted (only on the corresponding evidence
  being green); update the ADR index.
- **Roadmap update**: mark P2-Security exit; record the P3-Platform inheritance
  (HA/scale-out + SIEM export + obs-SLO enforcement) so nothing is silently dropped.
- **Evidence cited, not asserted**: every gate verdict links the commit / CI run /
  test / eval that proves it (the wf-release-auditor contract).

**Out**
- Building any control or eval → W1–W5-T2 (this audits them).
- The P3-Platform plan itself → authored when P2-Security exits.

## Requirements (grounded in §11, ADR-0033 §1, prior P1-W7 gate)

1. **Every gate verdict cites live evidence** (commit / CI run / test / eval) — no
   verdict on assertion alone.
2. **A gate flips green only on its evidence** being green; a missing/red control
   blocks the flip (the gate **bites** — P1 lesson: confirm a gate RUNS and BITES).
3. **Deferrals are named, never silent** (ADR-0033 §1): G-SCA + G-REL-live drills are
   explicitly recorded as deferred → P3-Platform with rationale (§0 / no hardware).
4. **ADR flips are conditional**: 0034–0041 → Accepted only when the implementing
   wave's evidence is green; do not flip a paper ADR.
5. **Rebase the W5 branch onto `origin/main` first** (sequencing note) so the audit
   runs against true HEAD.

## Contracts / artifacts

- `docs/roadmap/P2-RELEASE-READINESS.md` — per-gate evidence table + verdicts +
  named deferrals (mirror `P1-RELEASE-READINESS.md` structure).
- ADR status flips 0034–0041 → Accepted (+ ADR index).
- Roadmap / `PRODUCTION.md` exit markers + P3-Platform inheritance note.

## Validation / Test & gate plan (release audit — strong)

- Each §11 gate re-run against live evidence; the readiness doc reproduces the
  verdict from the cited artifact (a reviewer can re-derive it).
- **Gate-bites check** (P1 lesson): confirm each gate actually ran and would fail on
  a regression — not green-at-setup masking the findings it should produce.
- markdownlint; ADR index + roadmap consistent; no product-code diff in the commit.
- All five §11 gates' P2 slice passes **simultaneously** on the release HEAD (or is
  named-deferred).

## Exit criteria

- [ ] `P2-RELEASE-READINESS.md` written; every gate verdict cites live evidence.
- [ ] G-SEC / G-MNT / G-OBS **PASS** on the P2 slice (simultaneously on HEAD).
- [ ] G-SCA + G-REL-live drills recorded **deferred-accepted → P3-Platform** (named).
- [ ] ADRs 0034–0041 flipped → Accepted (each on its green evidence); index updated.
- [ ] Roadmap exit + P3-Platform inheritance recorded; `PRODUCTION.md` amendment (W0-T9) cited.
- [ ] markdownlint green; docs-only commit; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, phase-exit gate)

`wf-release-auditor` (strong) audits + writes evidence → **`wf-quality-reviewer`
(strong)** verifies the verdicts re-derive from cited evidence → `wf-fixer` (strong)
if findings → `wf-verifier` → **one atomic commit**. Rebase onto `origin/main` first.

## Risks

- **A gate green at setup, not biting** (P1 lesson): a gate failing at setup masks
  the findings it would produce — confirm each gate RAN and would BITE on a
  regression before flipping its ADR.
- **Flipping a paper ADR**: an ADR → Accepted without green implementing evidence
  manufactures false readiness — flips are conditional on the wave's evidence.
- **Silent deferral drift** (G-MNT §308): an unnamed deferral reads as "covered."
  G-SCA + G-REL-live are named in the doc, the roadmap, and the P3-Platform inheritance.
