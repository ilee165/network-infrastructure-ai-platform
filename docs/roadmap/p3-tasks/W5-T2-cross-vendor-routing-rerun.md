# W5-T2 — Cross-vendor + agent routing re-run (no regression vs P2 matrix)

| | |
|---|---|
| **Wave** | P3 W5 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` |
| **Review tier** | sonnet spec + quality |
| **Depends on** | **W4** (platform changes in place) |
| **ADRs** | ADR-0003 (supervisor routing), ADR-0033 (injection boundary), ADR-0016 (testing) |
| **PRODUCTION.md** | §2.6 (no cross-vendor eval regression), §11 G-MNT |
| **Status** | Proposed |

## Objective

Re-run the cross-vendor + agent-routing eval matrix to prove **P3 introduced no
regression**. P3 ships **no new vendor and no new agent** (platform-only), so the
roster is unchanged from P2 (9-way); this re-run confirms the HA/scale-out + WS
fan-out + worker changes did not perturb routing or the injection boundary.

## Scope

**In** — re-run the existing cross-vendor + Security-Agent routing suite (the P2
W5-T2 matrix) on the P3 release HEAD; confirm no routing drift and the ADR-0033
injection boundary still holds; record the result for the W5-T3 gate doc.

**Out** — new routing cases (no new agent/vendor); the SLO/SIEM corpus (W5-T1); the
gate doc (W5-T3).

## Requirements (grounded in PRODUCTION.md §2.6, ADR-0003/0033)

1. **No routing regression** — the 9-way matrix passes as in P2; any drift is a
   blocker (the WS fan-out / stateless-api change is the suspect to clear).
2. **Injection boundary intact** — per-agent allow-lists unchanged; the ED1–ED5
   deterministic suite still 100% no-unauthorized-tool-call.
3. **Roster unchanged confirmed** — assert no agent added/removed (P3 is
   platform-only); if the count changed, that's an unexpected drift to explain.
4. **Deterministic** — runs in CI on the pinned model/prompt set; byte-stable.

## Contracts / artifacts

- Routing re-run result (no-regression assertion) wired into CI; a recorded matrix
  for W5-T3.

## Test & gate plan

- Routing suite green on P3 HEAD; no drift vs the P2 matrix; injection suite 100%.
- Deterministic on the pinned set (`NullPool` SQLite where the P2 suite requires it).

## Exit criteria

- [ ] Cross-vendor + Security-Agent routing re-run green on P3 HEAD; **no regression** vs the P2 9-way matrix.
- [ ] Injection boundary intact (ED1–ED5 100%); roster unchanged confirmed.
- [ ] Deterministic in CI; result recorded for W5-T3; one atomic commit.

## Workflow

`wf-eval-designer` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **WS fan-out perturbs routing/session context** → silent routing drift; this
  re-run is the catch.
- **Non-determinism** from the platform change → flaky eval; pin the model/prompt set.
