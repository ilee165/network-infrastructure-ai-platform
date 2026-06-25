# W7-T3 — Cross-Vendor Routing Eval Re-run (3 new Wave-1 plugins)

| | |
|---|---|
| **Wave** | P1 W7 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` |
| **Review tier** | sonnet spec + sonnet quality (no secret surface — routing roster/decision path) |
| **Depends on** | W1 Vendor Wave 1 plugins (`cisco_nxos`, `junos`, `bluecat`) — merged |
| **ADRs** | ADR-0033 §5 (sibling deliverable); ADR-0009 §5 (structured routing) |
| **PRODUCTION.md** | §2.6 (no cross-vendor eval regression); §11 G-SEC routing |
| **Status** | Proposed |

## Objective

Re-run the existing cross-vendor routing eval (`backend/tests/agents/eval/test_routing_eval.py`, M5 T14 roster) extended to the **three new Wave-1 plugins** and confirm **no routing regression** (ADR-0033 §5: "a sibling W7 deliverable, not part of [the injection] corpus").

## Scope

**In**
- Confirm whether `test_routing_eval.py`'s roster is **registry-derived** (auto-picks up new plugins) or a **hardcoded list** that must be extended for `cisco_nxos`/`junos`/`bluecat`. Grounding check: the three plugin names are not referenced inline in the test today.
- Extend the roster / reference set so each new plugin's vendor intents route to the correct specialist; add reference `(query → expected specialist)` cases for the 3 plugins if the eval is case-driven.
- Run the eval; record pass-rate vs the prior 8-way run; flag any regression.

**Out**
- Injection corpus/suite → W7-T1/T2.
- New plugin implementation (done in W1).
- Gate evidence doc → W7-T4.

## Requirements (grounded in ADR-0033 §5, PRODUCTION.md §2.6)

1. **No routing regression** — the 3 new plugins route correctly and none of the existing roster regresses.
2. **Reference cases held out** (`wf-eval-designer`) — new routing cases are not verbatim few-shot/system-prompt examples.
3. **Reconstruct the real decision path** — real prompt + real roster + structured output; do not couple the eval to a live backend unrelated to the decision.
4. **Manual/Ollama-gated, like the existing eval** — `test_routing_eval.py` is module-skipped without `NETOPS_RUN_ROUTING_EVAL=1`; the re-run for new plugins inherits that posture. Live confirmation is **deferred-accepted** if no local model (no hardware, same as W1/W2).

## Contracts / artifacts

- `backend/tests/agents/eval/test_routing_eval.py` — roster/reference set extended for the 3 plugins.
- Any roster fixture the eval reads (if registry-derived, the change may be zero-code beyond a coverage assertion that the 3 plugins are present).

## Test & gate plan

- Full backend gates green (the eval module stays skipped in CI; must not break collection).
- If a local model is available: run with `NETOPS_RUN_ROUTING_EVAL=1`, record pass-rate, confirm no regression. Else deferred-accepted, documented for W7-T4.
- Assert (deterministically, collected in CI if feasible) that the 3 new plugins are present in the routing roster — so absence is caught even without a live run.

## Exit criteria

- [ ] Roster source (registry-derived vs hardcoded) confirmed; 3 new plugins present.
- [ ] Routing reference cases for the 3 plugins added (if case-driven), held out.
- [ ] Live re-run shows no regression vs prior run, **or** deferred-accepted with rationale.
- [ ] Deterministic "plugins present in roster" assertion green in CI.
- [ ] All backend gates green; one atomic commit.

## Workflow (P1-PLAN §3)

`wf-eval-designer` implements → `wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (sonnet) in parallel → `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Roster hardcoded, new plugins silently absent** — the deterministic "plugins present" assertion is the guardrail so the gap is caught without a live model.
- **No local model** — live regression check deferred-accepted; the present-in-roster assertion still gives CI-level coverage.
