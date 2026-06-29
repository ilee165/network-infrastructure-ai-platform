# W2-T4 — Worker `acks_late` + idempotency hardening

| | |
|---|---|
| **Wave** | P3 W2 — Compute scale-out |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet (strong if a task touches credentials/audit) |
| **Depends on** | W0-T2 (ADR-0043) |
| **ADRs** | ADR-0043 (the contract), ADR-0008 (Celery `acks_late` + idempotent tasks), ADR-0020 (ChangeRequest), ADR-0017 (config snapshot) |
| **PRODUCTION.md** | §3.2, §11 G-REL/G-SCA |
| **Status** | Proposed |

## Objective

Make worker tasks safe to scale-in and node-loss: **`acks_late` + idempotent task
design** so a re-delivered task (after a worker kill mid-run) **produces no
duplicate side effect** — the property the W4-T5 idempotency drill asserts under a
real worker kill. This is the code half of "scale-in/node loss only re-runs work"
(ADR-0008/0043).

## Scope

**In** — enable `acks_late` (+ `reject_on_worker_lost`) on the relevant queues;
audit each side-effecting task (discovery writes, config snapshot/deploy via CR,
docs generation) for idempotency keys / natural dedup so a re-run is a no-op or a
safe overwrite; tests on **real PG** asserting a double-delivery yields one effect.

**Out** — the KEDA manifests (W2-T3); the drill harness (W4-T5); changing the
ChangeRequest four-eyes semantics (only idempotency of execution, not the gate).

## Requirements (grounded in ADR-0008/0043, PRODUCTION.md §3.2/§11)

1. **`acks_late`** on queues where re-run-on-loss is safe; documented per queue
   (some tasks may be naturally idempotent already).
2. **No duplicate side effect** — each side-effecting task has an idempotency key or
   natural dedup; a re-delivered task does not double-write, double-deploy, or
   double-emit an audit/CR. Asserted on **real PG** (`tests/pg/`), never SQLite
   (write-locking/isolation hidden by SQLite — P2 lesson).
3. **CR-gated writes stay gated** — idempotency must not bypass the ChangeRequest
   gate (ADR-0020); a retried CR execution is idempotent, not a second write.
4. **Celery success-rate target** — the hardening supports the ≥99%-after-retries
   target W4-T5 asserts.

## Contracts / artifacts

- `acks_late`/`reject_on_worker_lost` config; per-task idempotency keys; `tests/pg/`
  double-delivery assertions.

## Test & gate plan

- `tests/pg/` (real PG, `pg-integration`): a task delivered twice produces exactly
  one side effect; a CR retry doesn't double-execute.
- Backend D16 gates green; `include_router` introspection green; mypy/ruff clean.
- Live worker-kill proof is **W4-T5**.

## Exit criteria

- [ ] `acks_late` enabled where safe; per-queue rationale documented.
- [ ] Each side-effecting task idempotent; **double-delivery → one effect** proven on real PG.
- [ ] CR gate not bypassed; `pg-integration` green; backend D16 + `include_router` green; one atomic commit.

## Workflow

`wf-implementer` → combined sonnet review (strong if a task touches credentials/audit) → fixer if findings → verifier → one atomic commit.

## Risks

- **`acks_late` without idempotency** → duplicate side effects on retry (worse than
  losing the task). The two must ship together.
- **Asserting idempotency on SQLite** → green locally, races on PG under
  concurrency. Use `tests/pg/`.
- **Idempotency that bypasses the CR gate** → a security regression; the gate stays.
