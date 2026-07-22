# W5-T3 — P5 release-readiness evidence and phase exit

| Field | Contract |
|---|---|
| Owner | `wf-release-auditor` |
| Depends on | W5-T1, W5-T2, W4-T3, all P5 tasks |
| Review | strong release review |
| Status | Proposed |

## Objective and scope

Prove every P5-scoped gate simultaneously at one release HEAD, author
`P5-RELEASE-READINESS.md`, accept ADRs 0055–0060 only on evidence, and replace
the roadmap entry marker with an exit/GA-inheritance marker. Out: implementing
late features or silently waiving red/missing gates.

## Requirements and contracts

1. Requirement-by-requirement matrix covers G-SEC, G-MNT, G-OBS, G-SCA at the
   honestly achieved point, G-REL, cloud/cross-vendor evals, and hybrid evals;
   each row cites release SHA, command/check, run URL/artifact, and result.
2. Verify CI status and artifacts directly. Setup failures are failures; each
   new gate must have retained red bite evidence and green release evidence.
3. ADR status changes to Accepted cite implementing commits/evidence. Any
   unsatisfied contract leaves its ADR Proposed and blocks P5 exit.
4. PRODUCTION.md exit marker carries GA inheritance: full certified-scale
   numbers if unmet, 30-day soak, external pentest, break-glass cadence, and
   F5/VMware/AWS/Azure live golden paths. No item silently disappears.

## Test and gate plan

Rebase release candidate onto current main, run the full documented local gate
set and required integration/kind/eval jobs, then verify blocking CI at the
same SHA. Run docs links, ADR-index consistency, task-count/status checks,
OpenAPI drift, and graph update. Plant a missing evidence row to prove the
readiness validator bites.

## Exit criteria

- [ ] `P5-RELEASE-READINESS.md` proves every in-scope requirement at one HEAD.
- [ ] All six ADRs are Accepted only with cited implementing evidence.
- [ ] PRODUCTION.md contains accurate P5 EXIT and complete GA inheritance.
- [ ] Full gates and evidence validator pass; one atomic commit.
