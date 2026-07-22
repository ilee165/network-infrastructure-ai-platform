# W5-T1 — Cloud conformance and cross-vendor no-regression evals

| Field | Contract |
|---|---|
| Owner | `wf-eval-designer` |
| Depends on | W2 complete, W1 complete |
| Review | strong eval review |
| Status | Proposed |

## Objective and scope

Extend the blocking vendor roster with AWS and Azure, rerun plugin conformance,
DDI/firewall/agent routing evaluations, and prove no regression across all 13
required families. Out: live-cloud certification and new product behavior.

## Requirements and contracts

1. Roster assertion enumerates all 13 families and fails if either cloud plugin
   or any prior vendor is skipped/xfail/conditionally uncollected.
2. AWS/Azure fixture cases cover paging, retry, empty/partial scope,
   normalization, secrets, SG/NSG firewall behavior, and Route53 DDI routing.
3. Cross-provider equivalents yield semantically equal normalized results;
   Security/DDI/Discovery agent routing selects correct capabilities and cites
   raw evidence.
4. Deterministic CI layer is blocking; live scripts remain named manual due to
   absent accounts. Results record release SHA and exact test selection.

## Test and gate plan

Collect tests first and assert roster/case counts. Run conformance, DDI golden
paths, firewall corpus, routing no-regression, prompt-injection/security
regressions, and coverage. Plant removal of `azure` and Route53 routing and
prove the roster/eval gates fail before restoring.

## Exit criteria

- [ ] Thirteen-family roster is collected and green at release candidate SHA.
- [ ] Cloud normalization, security, DDI, routing and secret cases pass.
- [ ] Planted roster/routing removals make the gate bite.
- [ ] Eval review passes; one atomic commit.
