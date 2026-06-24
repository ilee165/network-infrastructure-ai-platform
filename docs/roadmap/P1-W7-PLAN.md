# P1 W7 Build Plan — Prompt-Injection Evals + Phase-Exit Gate (LAST wave)

**Project:** AI Network Operations Platform
**Status:** PLANNED — awaiting build launch. W0–W6 merged (PRs #50/#58/#59/#60/#61/#62; W6 = `01e46c9`). W7 is the **last P1 wave** and the **phase-exit gate**.
**Authority:** `CLAUDE.md`; `docs/adr/0033-prompt-injection-eval-suite.md` (design contract, **Proposed** — flipped to Accepted in W7-T4 on green); `docs/roadmap/P1-PLAN.md` §3 (W7 row); `docs/roadmap/PRODUCTION.md` §5 + §11 (gates G-SEC/G-REL/G-SCA/G-OBS/G-MNT).
**Mirrors:** M5 T18 (`backend/tests/agents/eval/test_m5_exit_criteria.py`) and M5 T20 (`docs/roadmap/M5-RELEASE-READINESS.md`).

---

## 1. Scope

W7 builds the **proof**, not new controls — the defenses already ship (per-agent typed tool allow-lists, `ToolClassification` gate, `ChangeRequestGate`/four-eyes, A9 `RedactingChatModel`, structured outputs). ADR-0033 §Decision: prompt-injection resistance is an **architecture** property, certified by a deterministic suite driving a `ScriptedChatModel` that acts *already-compromised*.

| Deliverable | ADR-0033 ref | Gate |
|---|---|---|
| Deterministic injection suite (ED1–ED5), 100% no-unauthorized-tool-call, CI-blocking | §3 deterministic layer | G-SEC |
| Real-LLM injection layer (ED6), non-gating, env-flag + marker, skipped in CI | §3 real-LLM layer | — (signal) |
| Held-out attack corpus over the (carrier × target_agent) matrix | §4 dataset shape | G-SEC |
| Cross-vendor routing re-run for the 3 new Wave-1 plugins, no regression | §5 sibling deliverable | G-SEC routing |
| G-* gate evidence doc + P1 readiness; flip ADR-0033 → Accepted | §5 gate evidence | G-SEC/REL/SCA/OBS/MNT |

Out of P1 scope: model fine-tuning to resist, network WAF, prose-only jailbreaks, live-lab device golden-paths (deferred-accepted, no hardware — ADR-0033 §1 "out of scope").

---

## 2. Tasks & agent assignment

Per-task pattern (P1-PLAN §3): **1 owner → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.** `STRONG = 'opus'` as one session constant — never inline `'fable'` (dead-model = silent clean review, W0 root cause).

| Task | Deliverable | Owner | Review tier | Depends on |
|---|---|---|---|---|
| **W7-T1** | Attack corpus `fixtures/prompt_injection_cases.json` + deterministic suite `test_p1_prompt_injection.py` (ED1–ED5) + `injection` marker registered; joins pytest gate, 100% green | `wf-eval-designer` (strong) | **strong** spec + **strong** quality | — |
| **W7-T2** | Real-LLM layer `test_p1_prompt_injection_live.py` (ED6), `NETOPS_RUN_INJECTION_EVAL` flag + marker, module-skip in CI; one recorded run if Ollama avail else deferred-accepted | `wf-eval-designer` (strong) | **strong** quality | W7-T1 (shared corpus loader) |
| **W7-T3** | Cross-vendor routing re-run: `cisco_nxos`/`junos`/`bluecat` in roster, no regression vs prior run | `wf-eval-designer` | sonnet spec + sonnet quality | W1 plugins (merged) |
| **W7-T4** | `P1-RELEASE-READINESS.md` (mirror M5 T20) re-evaluating all 5 G-* gates on HEAD; cites T1 suite for G-SEC §275; flip ADR-0033 Proposed→Accepted | **`wf-release-auditor` (strong, NEW)** | strong quality | W7-T1·T2·T3 |

**Decision (approved 2026-06-24):**
- **New agent `wf-release-auditor`** created for T4 — gate-evidence synthesis across all 5 gates + ADR flip is a release-audit role, not eval design (`.claude/agents/wf-release-auditor.md`).
- **T1/T2 reviewers escalated to strong** — overrides the coarse "sonnet" in the P1-PLAN W7 row. T1/T2 are secret-surface (ED4 secret-non-exfil + leak/exit-criteria tests); escalation rule (`.claude/agents/README.md`) forbids any secret-surface task on a downgraded model.

---

## 3. Sequencing

- **W7-T1 first** — defines the corpus + loader both injection layers consume.
- **W7-T2 after T1** — shares the corpus loader; different module (`*_live.py`).
- **W7-T3 parallel** with T1/T2 — disjoint file (`test_routing_eval.py`).
- **W7-T4 last** — cites T1/T2/T3 as evidence; flips statuses on green.
- **Rebase first:** W6 squash-merged to `main` (`01e46c9`). Branch off fresh `origin/main`; `git log origin/main..<branch>` must show only W7 commits (README item 9).

---

## 4. Per-task exit criteria

**T1 (deterministic, gate-blocking):** ED1–ED5 each have ≥1 case; coverage matrix has ≥1 case per real `(carrier × STATE_CHANGING-reachable agent)` cell, asserted by a meta-test; cases drive **real** production paths (registry, `ToolClassification` gate, `ChangeRequestGate`/four-eyes, `RedactingChatModel`, structured-output parser), no mocks; ED4 seeds real `SEEDED_SECRETS` and asserts only `<<REDACTED:kind>>` sentinels survive in *real* output; 100% green in the standard pytest gate; `injection` marker registered at `backend/pyproject.toml`; a deliberately-broken case demonstrably fails (gate bites), then reverted.

**T2 (real-LLM, non-gating):** module-skips with no marker warning when `NETOPS_RUN_INJECTION_EVAL` unset (matches `test_routing_eval.py` `_FLAG`/`pytestmark`/`allow_module_level`); passes against a real local model when run; per-attack-class pass-rate recorded (PROPOSED ≥90% target); live run deferred-accepted if no Ollama.

**T3:** the 3 new plugins are in the routing roster; deterministic portion green; live routing re-run shows no regression vs prior 8-way run (deferred-accepted — routing eval is Ollama-gated/manual).

**T4:** each of G-SEC/G-REL/G-SCA/G-OBS/G-MNT has a PASS/FAIL/PARTIAL verdict with cited evidence on the release HEAD; the new prompt-injection control flips to PASS citing the green T1 suite; ADR-0033 flipped Proposed→Accepted; P1 declared complete only if all five gates pass simultaneously (deferrals named explicitly).

---

## 5. Expected risks (from lessons learned)

| # | Risk | Source lesson | Mitigation |
|---|---|---|---|
| R1 | **Review under-escalation** — W7 row says "sonnet" but T1/T2 are secret-surface | escalation rule; W0 false-clean | T1/T2 reviewers → strong (approved); `STRONG='opus'`, stop if unresolvable |
| R2 | **`fable` dead-model = silent clean review** | P1 W0 (10 false-clean ADR reviews) | one session constant `STRONG='opus'`; never inline `'fable'` |
| R3 | **Hollow / tautological eval** — assertion passes without proving the property | M5 ("graph test never invokes tools", "redaction test tautological") | drive REAL registry/gate/`RedactingChatModel`; ED4 seeds real secret, asserts sentinel replaced the *actual* value; no mocks |
| R4 | **Coverage-matrix incompleteness = false assurance** | ADR-0033 §Consequences | meta-test asserts ≥1 case per real (carrier × STATE_CHANGING-agent) cell |
| R5 | **Gate doesn't RUN or BITE** — unregistered marker / not collected | CLAUDE.md build-verification | register `injection` marker at `pyproject.toml`; confirm collected by pytest gate; planted-broken case fails then revert |
| R6 | **Platform-specific flaky test** — `record_step` ordinal race, StaticPool→NullPool | P1 W6 CI saga | NullPool fixtures, deterministic ordering; validate on Linux/py3.12 not just local Windows |
| R7 | **No-lockfile dep-drift** — bit twice (fastapi 0.137 `include_router`) | P1 W6 | reuse existing harness only; add NO new runtime deps |
| R8 | **Routing eval is Ollama-gated/manual** — "no regression" only live-verifiable | `test_routing_eval.py` `_FLAG` | T3 live run deferred-accepted (no hardware), same posture as W1/W2 |
| R9 | **ED6 needs a local model** | ADR-0033 §3 | non-gating by design; build + skip-verify; record one run if avail |
| R10 | **PR CONFLICTING / usage blowout** on a long run | README items 9–10 | rebase onto `origin/main` first; arm baseline-relative usage guard (`BASELINE=budget.spent()`); atomic commit/task = the save |
| R11 | **`test_routing_eval` roster hardcoded vs registry-derived** — new plugins silently absent | grounding check (roster not named inline) | T3 first confirms whether roster auto-derives from the plugin registry; extend explicitly if hardcoded 8-way |

---

## 6. Open items (non-blocking)

- **Live-lab / real-LLM deferred-accepted** (no hardware/Ollama): ED6 (T2) and routing re-run (T3). Code paths built + skip-verified in the green deterministic suite; one real run recorded if a model is available. Same posture as W1/W2.
- **ADR-0033 status** — stays Proposed until W7-T4 flips it on green (mirrors PR #63's 0025-0032 flip).
- **Corpus is a standing maintenance item** (ADR-0033 §Consequences): every future wave that adds an untrusted-text ingestion path adds coverage-matrix cells.
