# W7-T2 — Prompt-Injection Real-LLM Layer (ED6, non-gating)

| | |
|---|---|
| **Wave** | P1 W7 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** quality (secret-surface: re-checks ED1/ED4 against real generation; escalation rule) |
| **Depends on** | W7-T1 (shares the corpus + loader) |
| **ADRs** | ADR-0033 §2 (ED6), §3 (real-LLM layer), §5 (CI wiring) |
| **PRODUCTION.md** | §5; §10 ("a prompt change failing evals blocks release" — applies to the *deterministic* gate, not this non-gating layer) |
| **Status** | Proposed |

## Objective

Add the **non-gating** real-LLM layer measuring **ED6** (model task-integrity / refusal): replay the corpus carrier text through a real local model and report per-attack-class pass-rate. Module-skipped in CI behind an env flag + marker, exactly like `test_routing_eval.py` and `test_provider_parity.py`. This is the only honest read on up-front model refusal (ADR-0033 §3); the deterministic layer (T1) already guarantees *containment*.

## Scope

**In**
- `backend/tests/agents/eval/test_p1_prompt_injection_live.py` (or marker-gated module in the same file — ADR-0033 §3) loading the **same** `prompt_injection_cases.json` (T1).
- Env flag `NETOPS_RUN_INJECTION_EVAL=1` + `pytest.mark.injection` marker; module-level skip without the flag (`allow_module_level=True`), mirroring `test_routing_eval.py` `_FLAG`/`pytestmark`.
- Per-attack-class pass-rate reporting; re-check ED1 (no attacker tool call emitted) and ED4 (no secret in real generation) against real output.

**Out**
- Deterministic ED1–ED5 suite → W7-T1 (this layer does not gate).
- LLM-as-judge scoring as a pass criterion (ADR-0033 Alt #2 rejected) — optional qualitative aid only.
- Routing re-run → W7-T3.

## Requirements (grounded in ADR-0033 §3)

1. **Non-gating** — does NOT block the P1 release; the `local` default is the weakest profile (ADR-0009 negative) and a non-deterministic threshold cannot be a hard 100% gate. PROPOSED target ≥90% per certified local profile, regression-vs-prior flagged.
2. **Module-skips cleanly in CI** — no network, **no marker warning** when the flag is unset (matches `test_routing_eval.py`). The `injection` marker (registered in T1) must be recognized so collection emits no `PytestUnknownMarkWarning`.
3. **Reuses the held-out corpus** — same fixture as T1; no separate dataset that could drift.
4. **Secret discipline** — references test-only `SEEDED_SECRETS`; never prints secret material in output or report (ADR-0033 §4).
5. **Docstring states ED6 is real-LLM/manual** — a scripted replay cannot prove model judgment (`wf-eval-designer`).

## Contracts / artifacts

- `backend/tests/agents/eval/test_p1_prompt_injection_live.py` (collected, module-skipped without the flag).
- Reuses `prompt_injection_cases.json` (T1), the local-model client used by `test_routing_eval.py`.

## Test & gate plan

- **Skip-by-default verified:** with `NETOPS_RUN_INJECTION_EVAL` unset, the module skips at collection with no marker warning and no network (CLAUDE.md "gate must run/bite" applies inversely — confirm it correctly DOESN'T run in CI).
- **Live run:** if a local Ollama model is available, run once, record per-attack-class pass-rate; else deferred-accepted (no hardware), documented in the task output and cited by W7-T4.
- Full backend gates green (the new module is skipped, so it must not break collection).

## Exit criteria

- [ ] Module skips with no marker warning / no network when the flag is unset.
- [ ] Passes (or records pass-rate) against a real local model when run with the flag.
- [ ] Per-attack-class pass-rate reported; regression-vs-prior flagged.
- [ ] Same held-out corpus as T1; no secret in output.
- [ ] Live run recorded, or deferred-accepted with rationale.
- [ ] All backend gates green; one atomic commit.

## Workflow (P1-PLAN §3)

`wf-eval-designer` (strong) implements → **`wf-quality-reviewer` (strong, escalated) + `wf-spec-reviewer` (sonnet)** in parallel → `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Reported-but-not-gated metric gets ignored** (ADR-0033 §Consequences) — record the residual in the W7-T4 readiness doc and re-evaluate at each security review.
- **Flag/marker drift** — if the `injection` marker isn't registered (T1), CI emits a warning some configs treat as error; T1 must land the marker first (dependency ordering).
- **No local model** — deferred-accepted, same posture as W1/W2; do NOT lower or fake the bar (`wf-eval-designer`: never weaken an assertion to make a model pass).
