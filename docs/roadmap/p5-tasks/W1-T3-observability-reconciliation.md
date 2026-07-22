# W1-T3 — G-OBS reconciliation rows 5, 6, and 9

| Field | Contract |
|---|---|
| Owner | `wf-observability` |
| Depends on | W0 design gate |
| Review | sonnet spec + quality |
| Status | Proposed |

## Objective and scope

Close the three flagged reconciliation gaps: scheduled configuration backups,
executed ChangeRequests versus audit entries, and persisted reasoning traces
versus sessions/steps. Deliver jobs, series, recording/alert rules, runbooks,
and biting fault fixtures. Out: changing retention or audit-chain semantics.

## Requirements and contracts

1. Backup reconciliation compares due schedules to terminal successful runs and
   alerts on a miss within 15 minutes, with disabled schedules excluded.
2. Daily CR reconciliation counts executed terminal changes lacking the
   required audit lifecycle records and fails closed on query errors.
3. Trace reconciliation detects sessions requiring traces, traces without
   sessions, and steps without trace parents, scoped by a settled grace window.
4. Series use bounded labels; recording rules and multi-window burn/staleness
   alerts contain resolving runbook URLs. Jobs are idempotent and observable.

## Test and gate plan

Unit-test boundary times, exclusions, query failure, and repeat execution. Use
PG integration where joins/locking matter. Promtool should-fire and should-not-
fire cases plant one missed backup, one executed CR without audit, and one
orphan trace. Run observability gates and full backend gates.

## Exit criteria

- [ ] Three backed series, alerts, and runbooks ship.
- [ ] Each planted inconsistency fires; healthy/grace cases remain quiet.
- [ ] PRODUCTION.md §6 rows 5/6/9 change from deferred to backed in this task.
- [ ] D16 and promtool pass; one atomic commit.
