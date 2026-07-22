# ADR-0059: Durable Dispatch via Report Outbox and a Platform Dispatch Ratchet

**Status:** Proposed | **Date:** 2026-07-21 | **Milestone:** P5 W0

## Context

P4 report requests persist state and then call Celery. A process crash between
those actions can drop work; retries around dispatch can duplicate it. Other
bare `send_task` calls can reproduce the same class. Redis/Celery cannot join a
PostgreSQL transaction, so exactly-once delivery is unavailable.

## Decision

Add `dispatch_outbox` in an expand-only migration:

| Column | Contract |
|---|---|
| `id` UUID | immutable dispatch identity and Celery task ID |
| `aggregate_type`, `aggregate_id` | report run initially; extensible |
| `task_name`, `queue`, `payload_json` | allowlisted task envelope; payload contains IDs, never secrets |
| `state` | `pending`, `claimed`, `dispatched`, `dead` |
| `attempts`, `available_at`, `claimed_at`, `claim_owner` | recovery/backoff |
| `created_at`, `dispatched_at`, `last_error_code` | audit/metrics; no raw exception text |

`(aggregate_type, aggregate_id, task_name)` is unique. Both scheduled and
on-demand report request paths create/update the report run and insert the
outbox row in the same PostgreSQL transaction. Callers never dispatch directly.

A relay claims eligible rows in bounded batches using PostgreSQL row locking
with `FOR UPDATE SKIP LOCKED`, commits the claim, then sends through
`durable_dispatch(task_name, payload, queue, dispatch_id)`. The wrapper
allowlists task/queue pairs, assigns `task_id=dispatch_id`, applies retry policy,
and emits structured redacted metrics. The consumer uses `dispatch_id` as its
idempotency key and atomically claims the report run; duplicate deliveries
return the existing result without rendering twice.

After broker acknowledgement the relay marks the row `dispatched`. Crash before
send leaves a stale claim that a lease reaper returns to pending. Crash after
send but before mark causes a duplicate delivery, resolved by the stable task
ID and consumer idempotency. Broker rejection schedules bounded exponential
retry; non-retryable envelope errors become `dead` and alert. Operators may
requeue a dead row through an audited admin action. At-least-once transport plus
idempotent consumption provides no dropped and no duplicate effect—not a false
exactly-once claim.

All platform Celery publication must go through the hardened wrapper. A static
AST check fails on `.send_task(` outside the wrapper module and on direct
`apply_async`/`delay` outside an explicit, reviewed allowlist. The allowlist is
path+symbol scoped and initially empty after the W1 sweep. CI includes a fixture
with a planted bare call that must make the check fail.

Metrics cover pending count, oldest-row age, claims, retries, dead rows, stale
claim recovery, and duplicate consumer claims. Alerts link to a relay recovery
runbook. PostgreSQL integration tests enumerate each crash window and use the
integration marker.

## Consequences

Dispatch effects are recoverable and observable, at the cost of relay latency
and an additional table. The generic envelope allows later migrations, but P5
only moves existing platform tasks and does not create a general workflow bus.
