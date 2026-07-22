# W4-T3 — Consultant re-check, G-SCA re-base, and certification evidence

| Field | Contract |
|---|---|
| Owner | `wf-release-auditor` |
| Depends on | W4-T2 |
| Review | strong release review |
| Status | Proposed |

## Objective and scope

Audit W4 evidence against ADR-0060 and the latest Consultant Q1 answer; either
re-base targets from an owner decision or explicitly retain Proposed values.
Publish the certification matrix and GA promotion path. Out: changing numbers
without owner authority or accepting missing bite proof.

## Requirements and contracts

1. Re-read Q1 and record date/source/verdict. Owner numbers replace target
   manifests and roadmap references consistently; absence preserves defaults.
2. Evidence table covers target, attempted, achieved, result, raw artifact
   digest, red-control proof, environment, and gap for each G-SCA dimension.
3. Independently verify SHA/digests and recompute pass/fail; distinguish
   mechanism PASS at achieved point from certified-scale PASS.
4. Every gap names owner, required environment/action, command, evidence, and
   exact promotion criterion for GA.

## Test and gate plan

Run documentation link/consistency checks, harness manifest validation, hash
verification, and a planted evidence omission that must fail the readiness
checker. If targets changed, render and validate all rebased full manifests.

## Exit criteria

- [ ] Consultant verdict and every target reference agree.
- [ ] Evidence matrix is independently verified and omission gate bites.
- [ ] No claim exceeds achieved evidence; GA triggers are executable.
- [ ] Release review and D16 docs gates pass; one atomic commit.
