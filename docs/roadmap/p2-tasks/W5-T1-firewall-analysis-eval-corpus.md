# W5-T1 — Firewall-Policy-Analysis Eval Corpus + Deterministic Suite (precision/recall thresholds)

| | |
|---|---|
| **Wave** | P2 W5 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong — the deliverable is Security-Agent output quality) |
| **Review tier** | **strong** spec + **strong** quality (security-semantic findings; the corpus is the agent's correctness proof) |
| **Depends on** | **W3** (Security Agent core + routing) — analyses + findings model exist to evaluate |
| **ADRs** | ADR-0037 (Security Agent — deterministic analysis), ADR-0033 (eval-suite + injection-boundary discipline), ADR-0034 (`FIREWALL_POLICY` inputs), ADR-0016 / D16 (gates) |
| **PRODUCTION.md** | §2.6 (eval suite), §11 G-SEC |
| **Status** | Proposed |

## Objective

Build the **labelled firewall-policy-analysis corpus** and the **deterministic eval
suite** that scores the Security Agent's findings (shadowed / redundant /
overly-permissive rules + posture) against **precision/recall thresholds**, proving
the W3 analyses are correct and reproducible. Mirrors P1-W7's injection-eval suite
and M5-T20's eval discipline — builds the *proof*, not new agent behavior.

## Scope

**In** (`backend/tests/evals/` corpus fixtures + a deterministic eval runner + a
threshold assertion)
- **Labelled corpus**: `FIREWALL_POLICY` fixtures (drawn from / consistent with the
  `panos` + `fortios` normalized outputs from W2) with **ground-truth labels** for
  each finding class — known shadowed, redundant, overly-permissive rules, and
  posture violations, plus clean negatives (rules that must **not** be flagged).
- **Deterministic suite**: runs the W3 analysis **service** (rule-based, not LLM
  judgment — ADR-0037) over the corpus and scores **precision/recall** per finding
  class against the labels; thresholds fixed here (justified, not arbitrary).
- **No-secret-in-corpus**: fixtures carry config metadata only — no credential /
  secret field (the A9 redaction boundary is upstream in W3; the corpus asserts the
  findings it produces are secret-free).
- **Reproducibility harness**: the suite is deterministic across runs; pinned to
  **`NullPool` SQLite** (W6 flaky-concurrency lesson) so it does not flake in CI.

**Out**
- Cross-vendor + routing re-run → **W5-T2**.
- Gate-evidence doc + ADR flips → **W5-T3**.
- Security-Agent implementation → **W3** (this evaluates it; does not change it).

## Requirements (grounded in ADR-0037, ADR-0033, §2.6, D16)

1. **Deterministic scoring** (ADR-0037): the analysis is rule-based in the service,
   so precision/recall is reproducible — no LLM-judged step in the scored path.
2. **Thresholds justified** (§2.6): per-class precision/recall floors are stated with
   rationale; the suite **fails** below floor (a biting gate, not a report).
3. **Labels cover positives + negatives**: clean rules that must not be flagged are
   in the corpus so a "flag-everything" agent fails precision.
4. **Secret-free corpus + findings** (ADR-0033): no secret in fixtures; the produced
   findings carry evidence (normalized rule refs), no secret payload.
5. **No-flake discipline**: `NullPool` SQLite pin (W6 lesson); fastapi
   route-introspection stays green (no lockfile — standing fact).

## Contracts / artifacts

- Labelled `FIREWALL_POLICY` corpus fixtures under `backend/tests/evals/`.
- A deterministic eval runner scoring precision/recall per finding class.
- A threshold-assertion test that fails below the stated floors.

## Test & gate plan (Python TDD / eval — ADR-0016 / D16)

- ruff / mypy strict / import-linter / pytest on the eval module.
- **Threshold bite**: precision/recall computed per class; the suite fails if any
  floor is missed (verify by perturbing a fixture so it would drop below floor).
- **Determinism**: two runs → identical scores; `NullPool` SQLite.
- **Negative coverage**: a clean rule is **not** flagged (precision guard).
- Live analysis against a real firewall **deferred-accepted** (no hardware) — corpus
  is fixture-verified, same posture as M4/M5/P1.

## Exit criteria

- [ ] Labelled corpus (positives + clean negatives) for all four finding classes.
- [ ] Deterministic suite scores precision/recall per class; thresholds stated + justified.
- [ ] Suite **fails below floor** (bite verified by perturbation).
- [ ] Corpus + findings secret-free; `NullPool` pin; runs are reproducible.
- [ ] D16 gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-eval-designer` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **LLM-judged scoring flakes thresholds**: keep the scored path on the deterministic
  service (ADR-0037); the agent narrates, the service decides — only the service is scored.
- **Threshold gaming**: a floor tuned down until the suite passes hides a weak agent.
  Floors are justified up front; negatives in the corpus keep precision honest.
- **Corpus drift from real vendor output**: fixtures must match the W2 normalized
  shapes — derive them from the `panos`/`fortios` conformance outputs, not by hand-guess.
