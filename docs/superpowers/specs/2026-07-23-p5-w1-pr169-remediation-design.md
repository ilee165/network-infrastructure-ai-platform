# P5 W1 PR #169 Remediation Design

**Status:** Approved for implementation

## Objective

Bring PR #169 back to a truthful green state and close the verified durability,
authorization, operability, reconciliation, deployment-drift, and test-quality
gaps without redesigning ADR-0059.

## Scope

The remediation covers:

1. floor-pin `pyasn1>=0.6.4`, regenerate the hash-pinned backend lockfile, and
   regenerate the TypeScript OpenAPI client;
2. preserve replay retry budget by resetting outbox attempts;
3. expose an admin-only dead-dispatch listing and synchronize dispatch death
   with the public `ReportRun` lifecycle;
4. convert invalid replay envelopes into a stable typed API conflict and
   document reachable replay responses;
5. enforce the engineer floor before report-generation ChangeRequest creation;
6. complete slim-install metric fallbacks;
7. include permanently failed executed ChangeRequests in audit reconciliation;
8. pin Prometheus recording-rule source and deployed Helm content together;
9. make the Celery negative control distinguish an expected violation from a
   checker crash, reject task-module star imports, and document intentionally
   unsupported dynamic Python forms;
10. replace tautological tests, share the backup grace constant, correct
    comments/data-shape drift, and cover error/status helpers.

CodeRabbit's “backup reconciliation should disappear when backups are
disabled” finding is rejected. The retained schedule emits an explicit
excluded/healthy state and keeps freshness observable; existing tests pin that
contract.

## Durable dispatch and report lifecycle

`mark_claim_failed` remains the owner of the relay retry/death transition. When
it changes a report dispatch to `DEAD`, the same database transaction performs
a guarded `ReportRun` update:

- match the dispatch aggregate id;
- update only `status='queued'`;
- set `status='failed'`;
- set `error_class='dispatch_dead:<last_error_code>'`;
- set `finished_at` to the death timestamp;
- record a background audit event with bounded identifiers and error code;
- inspect the update row count and include whether the run changed in the audit
  detail.

The guard prevents a stale relay from clobbering a run already consumed into
`running`, `succeeded`, or a genuine post-consumption `failed` state.

`requeue_dead` validates the envelope before changing state, resets
`attempts=0`, and returns the row to `pending`. In the same transaction it
revives the run only when both conditions hold:

- `status='failed'`; and
- `error_class` begins with `dispatch_dead:`.

Revival sets `status='queued'`, clears `error_class` and `finished_at`, and
leaves genuine post-consumption failures untouched. The API's existing replay
audit detail records whether the run was revived.

`enqueue_report` uses a deliberately **broader** predicate than admin replay,
because a fresh user/scheduler re-request has a different meaning: "generate
this report again." It must reclaim a transient dispatch or persistence failure
— PR #166 F2 requires a phase-3 `persistence_error` run to be reclaimable by the
next same-period request — and it legitimately retries content failures
(`builder_error`, `render_error`). The single exception is a security-terminal
`redaction_violation`, which `enqueue_report` never silently revives or clears
(`NON_REVIVABLE_ERROR_CLASSES`); erasing a redaction failure's cause on
re-request would violate `secure by default` / `audit everything`, so it
requires an explicit distinct action. Admin `requeue_dead` stays narrowly gated
to `dispatch_dead:*` because a blind replay must not resurrect a
post-consumption failure it never dispatched. Both paths lock and reset the
existing unique outbox row rather than creating a second publishable envelope,
so admin replay and user re-request still converge on the unique
`(aggregate_type, aggregate_id, task_name)` row.

The admin dead-dispatch listing returns bounded operational metadata only:
dispatch id, aggregate/run id, typed error code, attempts, and creation time.
It never returns payload data. Pagination is bounded and ordered
deterministically.

## API and authorization

Invalid replay envelope validation becomes a typed `409 Conflict` with a stable
`invalid-dispatch-envelope` problem slug. The requeue endpoint documents
`403`, `404`, and `409`; the dead-list endpoint is admin-only and documents its
authorization response.

`request_report_generation` declares `min_role="engineer"` on the tool
descriptor. The framework rejects viewers before `ChangeRequestGate` persists
a draft. Functional tests stop using a module-wide approve-all fixture and
exercise the real gate for the viewer denial path.

## Reconciliation and observability

ChangeRequest audit reconciliation treats `FAILED` as a terminal executed
state. Its required lifecycle is the created, approval, execution-start, and
`executing_to_failed` action set; it does not require the later
`failed_to_rolled_back` edge. Completed, failed, and rolled-back states retain
separate action counts so one terminal path cannot mask another.

`BACKUP_MISS_GRACE` is the single fifteen-minute duration used by both the
reconciliation predicate and Celery beat offset. A synchronization test pins
the schedule. The stale “15m” burn-rate comment is corrected to the actual
10-minute window.

Every exported metric object has a `None` assignment in the optional
Prometheus import fallback. The slim-install test derives the metric symbols
from the module's exported gauge/counter objects, preventing future omissions.

The chart's reconciliation recording rules are compared canonically with the
promtool-gated source, mirroring the existing alert-rule equality guard.

## Celery ratchet and CI bite

The checker rejects `from app.workers.tasks.<module> import *` because it makes
direct task calls statically unresolvable. A planted fixture proves the new
violation. The negative-control CLI remains:

- exit `0`: no violations;
- exit `1`: expected forbidden-publication findings;
- any other exit: checker failure.

The workflow captures the negative-control status and accepts only `1`, while
also asserting expected violation output. Dynamic constructions such as
`getattr`, `functools.partial`, walrus-created aliases, and call-returned bound
methods are documented limitations rather than an implied complete Python
data-flow proof. Direct task decorators and canvas `.s`/`.si` matching receive
focused fixtures for the supported syntax contract.

## Test strategy

PostgreSQL tests prove:

- five transient relay failures produce `DEAD`; replay resets the budget and a
  sixth transient failure returns to `PENDING`;
- publish-success/mark-crash followed by later dispatch death cannot overwrite
  a succeeded run;
- a dispatch-death failure revives to queued, clears failure metadata, and can
  complete successfully after replay;
- a genuine post-consumption failed run is never revived;
- re-request and admin replay converge on one stable dispatch row and one
  publishable effect;
- permanently failed ChangeRequests participate in the set-wise audit query.

API and unit tests prove dead-row discovery, bounded metadata, admin RBAC,
typed replay conflict, documented responses, viewer rejection before draft
creation, timezone-safe outbox age, reconciliation terminal paths, metric
fallback completeness, recording-rule equality, and ratchet negative controls.

Each behavior change follows red-green TDD. After focused tests, the branch
runs backend unit and PostgreSQL integration suites, frontend generation/type
checks, lockfile drift/hash verification, Prometheus semantic and mutation
gates, Helm lint/render, Graphify update, and GitHub PR checks.

## Delivery

Fixes are grouped into reviewable atomic commits: CI dependency/client drift;
outbox lifecycle/API; authorization; reconciliation/observability; ratchet/CI;
test hygiene and evidence refresh. The branch is pushed only after local gates
pass. Review replies cite the exact fix or the retained disabled-backup design.
