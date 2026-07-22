# W1-T1 — Transactional report outbox and relay recovery

| Field | Contract |
|---|---|
| Owner | `wf-implementer` (strong) |
| Depends on | W0-T5 / ADR-0059 |
| Review | strong spec + quality; secret/report spine |
| Status | Proposed |

## Objective and scope

Implement ADR-0059 for both scheduled and on-demand report requests: persist a
unique outbox envelope in the same transaction as the report-run transition,
relay it with leases and bounded retry, and make consumption idempotent. In:
migration/model/service, relay/reaper tasks, wrapper integration, metrics,
alerts/runbook, real-PG crash tests. Out: a general event bus or non-report
schema redesign.

## Requirements and contracts

1. `dispatch_outbox` fields, uniqueness, states, safe payload, and stable task
   ID match ADR-0059; migration is expand-only.
2. Scheduled and API paths call one transaction-scoped enqueue service and do
   not publish before commit.
3. Claim uses bounded `SKIP LOCKED`; stale claims recover. Post-send/pre-mark
   crashes may redeliver but cannot render or transition twice.
4. Metrics expose pending age/count, retry, dead, recovered, and duplicate
   claims. Dead-row requeue is RBAC-protected and audited.

Artifacts: model/migration; report enqueue service; relay/reaper tasks; alert
rules and `docs/runbooks/report-outbox-relay.md`; PG tests.

## Test and gate plan

Write failing PG tests for rollback-without-row, committed-row recovery,
pre-send crash, post-send crash, concurrent relays, lease expiry, poison row,
and duplicate consumer. New `backend/tests/pg/` files declare
`pytestmark = pytest.mark.integration`; prove collection with
`pytest -m integration --collect-only backend/tests/pg`. Run focused tests, report conformance,
full backend gates, migration check, promtool tests, and coverage ≥80%. Retain a
red bite proving the old post-commit direct-dispatch window drops work.

## Exit criteria

- [ ] Every crash window has a real-PG assertion; no dropped or duplicate effect.
- [ ] Both request paths are atomic and direct publication is absent.
- [ ] Relay alerts/runbook and dead-row audited recovery work.
- [ ] Strong review, D16 and `pg-integration` pass; one atomic commit.
