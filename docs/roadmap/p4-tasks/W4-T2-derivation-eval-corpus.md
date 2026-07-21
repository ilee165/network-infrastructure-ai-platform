# W4-T2 — App-dependency derivation eval corpus: synthetic estates → expected graph, precision/recall, planted wrong-edge control

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-eval-designer` (strong) |
| **Review tier** | **strong** |
| **Depends on** | **W2** (derivation + impact surface shipped), **W4-T2A** (route-domain/provenance corrections) |
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
precision/recall computation gated at exact-match precision `1.0` and recall
`1.0`; impact-analysis correctness cases over the derived graph
(both directions, indirect chains) + the citation contract (every claim has
source + refs + watermark); idempotency eval (derive twice ⇒ identical graph);
**negative controls**: checked-in tests assert that a planted wrong
`DEPENDS_ON` edge trips precision and suppressing a source trips recall
(assert-red-inside-green).

**Out** — changes to derivation logic. T2A is the production-correction
precondition; T2 remains eval-only, and any later runtime finding lands as a
separate correction rather than being hidden in the corpus commit;
flow-telemetry cases (out of scope); real-LLM agent runs (opt-in gate).

## Requirements (grounded in ADR-0052 §4/§6, P4-PLAN §0a)

1. **All four sources produce provenance-carrying edges in the corpus** —
   the ADR-0052 §6.4 exit criterion, demonstrated not assumed.
2. **Exact match is the gate** — precision `1.0` and recall `1.0` on the curated
   corpus. Any miss is a pipeline or fixture defect to adjudicate, never a
   reason to lower the threshold. A genuinely ambiguous case may move to a
   labeled known-hard partition excluded from the gate only with rationale in
   `P4-RELEASE-READINESS.md`; ADR-defined exclusions are expected exclusions,
   not false negatives.
3. **The negative controls RUN and BITE continuously** — checked-in tests
   assert the scorer rejects a planted wrong edge and a suppressed source
   inside the otherwise-green blocking job. T2 records only task status,
   focused commands/results, bite test node IDs, and the blocking-CI collection
   path. T4 later records the landed T2 commit SHA and final release-HEAD
   blocking run/job URL and result. A temporary red commit is not evidence.
4. **Runs under real PG where derivation writes** (`tests/pg/` /
   `pg-integration`) — idempotency asserted there, not on SQLite.

## Contracts / artifacts

- Eval corpus + expected graphs + thresholds; eval runner wiring into CI;
  bite-proof evidence for the readiness doc.

## Test & gate plan

- Full gate suite; the derivation eval green in CI at HEAD.
- Derive-twice idempotency (its own eval check): running derivation twice
  over the corpus yields a byte-identical expected graph — no dupes, no
  unstable IDs.
- Bite proofs: assert-red-inside-green wrong-edge and suppressed-source
  mutations prove the `1.0` thresholds trip on every CI run. In the ledger's T2
  section, record only task status, focused verification commands/results,
  bite test node IDs, and the blocking-CI collection path. These are
  non-self-referential pre-commit records. T2 must not add its own commit SHA,
  a final release HEAD, or a blocking run/job URL; T4 records the landed T2
  commit SHA and owns final revalidation evidence.

## Exit criteria

- [ ] Corpus covers all four sources + interaction cases; expected graphs carry per-edge source/provenance.
- [ ] Precision `1.0` and recall `1.0` enforced in CI; impact + citation correctness green.
- [ ] Wrong-edge and suppressed-source controls assert failure inside green; T2 records only task status, focused commands/results, bite test node IDs, and the blocking-CI collection path, leaving landed-task and final-release evidence to T4.
- [ ] One atomic commit.

## Workflow

`wf-eval-designer` (strong) → **strong** review → fixer if findings → verifier → one atomic commit.

## Risks

- **Fixture-shaped truth** — synthetic estates that only mirror the derivation
  logic prove nothing; expected graphs are authored from the *ADR contract*,
  not from running the code.
- **Threshold theater** — thresholds set at observed values never bite; set
  from the contract, prove the trip.
