# W4-T2 — App-dependency derivation eval corpus: synthetic estates → expected graph, precision/recall, planted wrong-edge control

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** |
| **Depends on** | **W2** (derivation + impact surface shipped) |
| **ADRs** | ADR-0052 §2/§4/§6/§8 (the contracts being proven) |
| **PRODUCTION.md** | §2.4, §11 (P4-PLAN §5 W4: "green and biting") |
| **Status** | Proposed |

## Objective

Build the derivation proof: **synthetic estate fixtures (ADC rows +
virtualization rows + inventory + DNS records + manual tags) → expected
`Application`/`DEPENDS_ON` graph**, evaluated with precision/recall thresholds,
impact-analysis correctness + provenance-citation checks, and the
**prove-it-bites negative control: a planted wrong edge fails the eval**.

## Scope

**In** — synthetic estate corpus covering all four sources and their
interactions: VIP→pool→member chains (incl. FQDN members, route-domain
disambiguation, unreconcilable members), VM placement chains (incl. Tools-less
VMs, template exclusion, hosts absent from inventory), DNS reconciliation
(CNAME hops), manual tags + name-collision attach + manual-wins precedence;
expected-graph fixtures with per-edge source/provenance expectations;
precision/recall computation + thresholds (bound here, recorded in the
readiness doc); impact-analysis correctness cases over the derived graph
(both directions, indirect chains) + the citation contract (every claim has
source + refs + watermark); idempotency eval (derive twice ⇒ identical graph);
**negative controls**: a planted wrong `DEPENDS_ON` edge in the
expected-fixtures fails; a suppressed source's edges disappearing is detected
(recall drop bites).

**Out** — changes to derivation logic (evals prove; fixes go back through
W2-owned files as separate findings); flow-telemetry cases (out of scope);
real-LLM agent runs (opt-in gate).

## Requirements (grounded in ADR-0052 §4/§6, P4-PLAN §0a)

1. **All four sources produce provenance-carrying edges in the corpus** —
   the ADR-0052 §6.4 exit criterion, demonstrated not assumed.
2. **Thresholds are explicit** — precision/recall numbers named in the corpus
   config; below-threshold fails CI.
3. **The negative control RUNS and BITES** — planted wrong edge ⇒ red,
   removal ⇒ green, both evidenced with run URLs.
4. **Runs under real PG where derivation writes** (`tests/pg/` /
   `pg-integration`) — idempotency asserted there, not on SQLite.

## Contracts / artifacts

- Eval corpus + expected graphs + thresholds; eval runner wiring into CI;
  bite-proof evidence for the readiness doc.

## Test & gate plan

- Full gate suite; the derivation eval green in CI at HEAD.
- Bite proofs: planted wrong edge red; threshold trip red on a degraded
  fixture set.

## Exit criteria

- [ ] Corpus covers all four sources + interaction cases; expected graphs carry per-edge source/provenance.
- [ ] Precision/recall thresholds enforced in CI; impact + citation correctness green.
- [ ] Planted wrong-edge negative control proven to bite (evidence recorded).
- [ ] One atomic commit.

## Workflow

`wf-eval-designer` (strong) → **strong** review → fixer if findings → verifier → one atomic commit.

## Risks

- **Fixture-shaped truth** — synthetic estates that only mirror the derivation
  logic prove nothing; expected graphs are authored from the *ADR contract*,
  not from running the code.
- **Threshold theater** — thresholds set at observed values never bite; set
  from the contract, prove the trip.
