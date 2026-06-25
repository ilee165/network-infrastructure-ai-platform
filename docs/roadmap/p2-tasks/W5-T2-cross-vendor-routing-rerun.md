# W5-T2 — Cross-Vendor + Security-Agent Routing Re-Run (no regression vs prior matrix)

| | |
|---|---|
| **Wave** | P2 W5 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong — eval deliverable) |
| **Review tier** | sonnet spec + sonnet quality (no secret surface — routing labels + vendor metadata; escalate if a secret path surfaces) |
| **Depends on** | **W2** (panos / fortios plugins) + **W3** (Security Agent registered to the supervisor) |
| **ADRs** | ADR-0033 (routing-eval discipline, injection boundary), ADR-0003 (specialist framework), ADR-0037 (Security Agent), the prior routing-eval matrix (M4 5-way / M5 / P1) |
| **PRODUCTION.md** | §2.6 (no cross-vendor eval regression), §11 G-SEC / G-MNT |
| **Status** | Proposed |

## Objective

Re-run the **supervisor routing eval** with the two new vendors (`panos`,
`fortios`) and the new **Security Agent** added, proving **no regression** against
the prior routing matrix (M4's live 5-way → now extended). Confirms the Security
Agent routes correctly **and** that adding it did not perturb existing routing.
Mirrors the M4/M5/P1 routing re-runs.

## Scope

**In** (`backend/tests/evals/` routing cases extended + the no-regression assertion)
- **Add routing cases**: prompts that must route to the **Security Agent**
  (firewall-policy analysis, posture, shadowed/overly-permissive questions) and to
  the **panos/fortios** vendor paths; expected-agent labels per case.
- **No-regression run**: re-execute the **full** routing matrix (existing agents +
  new) and assert the prior cases still route to the same agents — adding the
  Security Agent must not steal routing from Troubleshooting / Config / DDI / etc.
- **Injection-boundary carry** (ADR-0033): the per-agent tool allow-list from W3-T2
  is exercised — the Security Agent cannot be prompt-coerced outside its read-only
  tool set (the ADR-0033 boundary extends to the new agent).
- **Determinism**: routing decisions scored against fixed labels; the suite is
  reproducible (no flaky model-dependent assertion in the scored gate path; use the
  same routing-eval mechanism the prior matrix used).

**Out**
- Firewall-analysis finding quality → **W5-T1**.
- Gate-evidence doc + ADR flips → **W5-T3**.
- New routing/agent behavior → **W3** (this evaluates it).

## Requirements (grounded in ADR-0033, ADR-0003, §2.6)

1. **No cross-vendor regression** (§2.6): every prior routing case still routes to
   its prior agent; the suite **fails** on any drift.
2. **New agent routes correctly**: security-domain prompts route to the Security
   Agent at the prior matrix's accuracy bar (or better) — no new failures.
3. **Injection boundary holds** (ADR-0033): an adversarial prompt cannot route the
   Security Agent to a tool outside its read-only allow-list.
4. **Same eval harness as the prior matrix**: reuse the M4/M5/P1 routing-eval
   mechanism so the comparison is apples-to-apples; pin determinism (`NullPool`).
5. **fastapi route-introspection green** (no lockfile — standing fact) after any
   incidental import change.

## Contracts / artifacts

- Extended routing-eval cases (Security Agent + panos/fortios) with expected labels.
- A no-regression assertion over the full matrix (prior + new).
- An injection-boundary case exercising the W3-T2 allow-list.

## Test & gate plan (eval — ADR-0033 / D16)

- **Full-matrix re-run**: prior cases unchanged in outcome; new cases at the
  accuracy bar; the suite fails on any prior-case drift (regression bite).
- **Security-Agent routing**: security prompts → Security Agent; non-security
  prompts never mis-route to it.
- **Injection-boundary**: an adversarial prompt does not escape the read-only
  allow-list (ADR-0033 carry).
- **Determinism**: reproducible scores; `NullPool` SQLite.
- Live model routing run **deferred-accepted** where it needs hardware/live LLM;
  deterministic fixtures gate CI (same posture as prior matrices).

## Exit criteria

- [ ] Routing cases added for the Security Agent + panos/fortios paths.
- [ ] Full-matrix re-run shows **no regression** vs the prior matrix (drift bites).
- [ ] Security-domain prompts route to the Security Agent at the accuracy bar.
- [ ] Injection-boundary case green (read-only allow-list holds).
- [ ] Determinism pinned; D16 gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-eval-designer` (strong) implements → `wf-spec-reviewer` (sonnet) +
`wf-quality-reviewer` (sonnet) in parallel → `wf-fixer` if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **New agent steals routing**: a broad Security-Agent description can pull
  Troubleshooting/Config prompts. The no-regression run is the guard; W3-T2 tunes
  the description if drift appears (loop back, don't loosen the assertion).
- **Comparing against a different harness**: re-running with a changed eval
  mechanism hides regressions. Reuse the prior matrix's harness for parity.
