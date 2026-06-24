# W7-T4 — G-* Gate Evidence Doc + P1 Release Readiness

| | |
|---|---|
| **Wave** | P1 W7 — Evals + phase-exit gate |
| **Owner** | `wf-release-auditor` (strong, NEW) |
| **Review tier** | **strong** quality (G-SEC evidence is security-semantic) |
| **Depends on** | W7-T1, W7-T2, W7-T3 (cites all as evidence) |
| **ADRs** | ADR-0033 §5 (gate evidence); flips ADR-0033 Proposed→Accepted |
| **PRODUCTION.md** | §11 (gates G-SEC/G-REL/G-SCA/G-OBS/G-MNT); §10 (release blocking) |
| **Status** | Proposed |

## Objective

Produce the **P1 phase-exit evidence doc** (`docs/roadmap/P1-RELEASE-READINESS.md`, mirroring M5 T20 `docs/roadmap/M5-RELEASE-READINESS.md`): re-evaluate each named G-* gate against live repo/CI/sign-off evidence on the release HEAD, open and flip the prompt-injection control to PASS citing the green W7-T1 suite, and flip ADR-0033 Proposed→Accepted. P1 is declared complete only when all five gates pass simultaneously (ADR-0033 §5, PRODUCTION.md §11).

## Scope

**In**
- `docs/roadmap/P1-RELEASE-READINESS.md` — per-gate PASS/FAIL/PARTIAL verdict with **cited evidence** for each of G-SEC, G-REL, G-SCA, G-OBS, G-MNT.
- The new **prompt-injection control** entry (today absent from `docs/security/2026-06-19-m5-security-review-signoff.md`): flips to PASS only when the deterministic suite covers ED1–ED5 across the matrix and is 100% green in CI, and the real-LLM layer has been run once (or deferred-accepted) with its pass-rate recorded (ADR-0033 §5).
- Flip `docs/adr/0033-prompt-injection-eval-suite.md` Proposed→Accepted (mirrors PR #63 flipping 0025-0032).
- Update `docs/roadmap/P1-PLAN.md` status (W7 → Done; P1 → complete) and the vault status note.

**Out**
- Writing or fixing any eval/control code — a failing gate is reported as FAIL with the gap, not patched (`wf-release-auditor` discipline).
- New ADRs.

## Requirements (grounded in ADR-0033 §5, PRODUCTION.md §11)

1. **Evidence over assertion** — each verdict cites a concrete artifact: the green CI job + test path (G-SEC: `test_p1_prompt_injection.py`; routing: W7-T3), the W5 DR drill evidence (G-REL), the W6 supply-chain jobs + SBOM/cosign (G-SCA), observability wiring (G-OBS), maintainability gates (G-MNT). "Should pass" is not evidence.
2. **Re-evaluate on the release HEAD** — confirm each cited test is collected and green in the actual gate run, each CI job ran and bit; a gate failing at setup is FAIL, not PASS (CLAUDE.md "make the gate RUN and BITE").
3. **All five gates pass simultaneously on one HEAD** for P1-complete; any PARTIAL blocks unless named deferred-accepted with written rationale (live-lab no-hardware: W1/W2 golden-paths, ED6 real-LLM, routing live re-run).
4. **Flip statuses only on green** — ADR-0033 → Accepted and roadmap flips happen after the gates they depend on are PASS; quote the evidence.
5. **Secret hygiene** — cite the green ED4 eval as proof of non-exfiltration; never reproduce secret values.

## Contracts / artifacts

- `docs/roadmap/P1-RELEASE-READINESS.md` (new; mirrors M5-RELEASE-READINESS.md structure).
- `docs/adr/0033-prompt-injection-eval-suite.md` — status flipped.
- `docs/roadmap/P1-PLAN.md` + vault status note — W7/P1 status synced.
- (Optional) a successor security sign-off note citing the injection suite for G-SEC §275.

## Test & gate plan (doc/evidence task)

- Each gate verdict links to a re-runnable artifact (CI job URL/path, test path, sign-off note). Where the auditor re-runs a cited test, it runs that one file, not the full suite.
- Markdown lints / no broken internal links.
- ADR/roadmap status flips are consistent (no doc claims Accepted while another claims Proposed).

## Exit criteria

- [ ] `P1-RELEASE-READINESS.md` gives PASS/FAIL/PARTIAL + cited evidence for all five G-* gates on HEAD.
- [ ] Prompt-injection control opened and flipped to PASS citing the green W7-T1 suite (deterministic 100% in CI) + recorded/deferred real-LLM pass-rate.
- [ ] Deferrals (live-lab, ED6, routing live) named explicitly with rationale — none silent.
- [ ] ADR-0033 flipped Proposed→Accepted; P1-PLAN + vault status synced.
- [ ] P1 declared complete only if all five gates PASS simultaneously; else the blocking gap is named.
- [ ] One atomic commit (docs + status flips only).

## Workflow (P1-PLAN §3)

`wf-release-auditor` (strong) audits + writes → **`wf-quality-reviewer` (strong, escalated — G-SEC evidence) + `wf-spec-reviewer` (sonnet)** in parallel → `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **PASS-by-assumption** (W0 false-clean) — strong quality review checks every verdict cites a HEAD artifact, not memory; the audit re-confirms each gate ran and bit.
- **Premature status flip** — ADR/roadmap flips only after the dependent gate is green; a PARTIAL gate blocks the flip.
- **Silent deferral** — every deferred-accepted item is named with rationale in the doc, never dropped (ADR-0033 §1 "named, not silently dropped").
