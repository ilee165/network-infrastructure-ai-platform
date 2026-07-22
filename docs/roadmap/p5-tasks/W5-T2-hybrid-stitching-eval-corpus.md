# W5-T2 — Hybrid stitching derivation evaluation corpus

| Field | Contract |
|---|---|
| Owner | `wf-eval-designer` |
| Depends on | W3 complete |
| Review | strong eval review |
| Status | Proposed |

## Objective and scope

Create deterministic synthetic hybrid estates with expected PG/Neo4j graphs
and impact answers, then gate stitching precision/recall and provenance. Out:
using production/customer topology or accepting overlap as ground truth.

## Requirements and contracts

1. Corpus spans AWS VPN/DX, Azure VPN/ExpressRoute, IPv4/IPv6, multi-account/
   subscription, Route53 private zones, inferred evidence, conflicts, stale
   observations, and deliberately overlapping but disconnected CIDRs.
2. Gold data names expected nodes, edges, confidence, evidence refs, suppressed
   candidates, DNS links, and representative impact paths/no-paths.
3. Thresholds are versioned and computed per mechanism plus aggregate; false
   positive hybrid edges are a hard failure regardless of aggregate score.
4. Evaluation runs derivation twice and after clean rebuild to assert
   idempotency and PG→Neo4j equivalence.

## Test and gate plan

Validate corpus schema and independence from implementation output. Compute
precision/recall, provenance completeness, path correctness, duplicates, and
rebuild equality. Mutate the join to accept CIDR overlap and retain the red
wrong-edge result, then restore and rerun green.

## Exit criteria

- [ ] Per-mechanism/aggregate thresholds pass with zero forbidden false edges.
- [ ] Impact, DNS, conflict, idempotency, provenance, and rebuild assertions pass.
- [ ] Planted wrong-edge mutation makes the blocking gate fail.
- [ ] Eval review passes; one atomic commit.
