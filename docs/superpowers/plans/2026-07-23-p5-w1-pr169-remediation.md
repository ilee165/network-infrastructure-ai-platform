# P5 W1 PR #169 Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make PR #169 green and close every verified durability, RBAC, operability, reconciliation, deployment-drift, ratchet, and test-quality finding.

**Architecture:** Preserve ADR-0059's unique outbox aggregate and add guarded, transactional synchronization to `ReportRun`; expose only bounded admin diagnostics. Keep reconciliation paths state-specific, make generated/deployed artifacts single-source verified, and strengthen static/CI gates with planted negative controls.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async, PostgreSQL, Celery, pytest, Prometheus/promtool, Helm, React TypeScript/OpenAPI, uv, GitHub Actions.

## Global Constraints

- Every behavior change starts with a failing test and records the expected failure.
- Dispatch death updates only a queued run; revival updates only failed runs with `error_class LIKE 'dispatch_dead:%'`.
- Admin replay and deterministic re-request reuse one stable dispatch row.
- Audit writes share the state-transition transaction and contain bounded typed values only.
- No schema migration or new report status enum value.
- `pyasn1>=0.6.4` is resolved through the hash-pinned lockfile, never hand-edited.
- Keep the disabled-backup reconciliation schedule and reject CodeRabbit finding #2 with citations.

---

### Task 1: Restore dependency and generated-contract CI

**Files:**
- Modify: `backend/pyproject.toml`
- Regenerate: `backend/requirements.lock.txt`
- Regenerate: `frontend/src/api/generated/openapi-types.ts`
- Modify: `docs/roadmap/P5-W1-HANDOFF.md`

**Interfaces:**
- Consumes: `uv pip compile` and `openapi-typescript` commands already enforced by drift CI.
- Produces: a lock resolving `pyasn1==0.6.4` or newer and a TypeScript client identical to regeneration from `docs/api/openapi.json`.

- [ ] **Step 1: Add a failing dependency-floor assertion**

Add a focused assertion to the existing lock/drift test surface that parses
`pyproject.toml` and requires a direct `pyasn1>=0.6.4` floor.

- [ ] **Step 2: Verify RED**

Run:

```bash
cd backend
.venv/bin/pytest tests/scripts -k 'lock and pyasn1' -q
```

Expected: failure because no direct pyasn1 floor exists.

- [ ] **Step 3: Add the floor and regenerate the lock**

Add beside the other security floor pins:

```toml
"pyasn1>=0.6.4",
```

Then run:

```bash
cd backend
uv pip compile pyproject.toml --extra dev --universal --generate-hashes \
  --python-version 3.12 --output-file requirements.lock.txt
```

- [ ] **Step 4: Regenerate the TypeScript client**

```bash
cd frontend
./node_modules/.bin/openapi-typescript ../docs/api/openapi.json \
  -o src/api/generated/openapi-types.ts
```

Update the handoff to say both the backend specification and generated
TypeScript leg were reverified at the new HEAD.

- [ ] **Step 5: Verify GREEN and commit**

Run exact lockfile, OpenAPI export, TypeScript regeneration-diff, and focused
tests. Commit:

```bash
git commit -m "fix(ci): refresh vulnerable dependency and API client"
```

---

### Task 2: Synchronize outbox death and report lifecycle

**Files:**
- Modify: `backend/app/services/report_outbox.py`
- Modify: `backend/app/models/reports.py`
- Modify: `backend/app/workers/tasks/report_outbox.py`
- Modify: `backend/tests/pg/test_report_outbox_pg.py`
- Modify: `backend/tests/services/test_report_outbox.py`

**Interfaces:**
- Consumes: `mark_claim_failed(...)`, `requeue_dead(...)`, `enqueue_report(...)`, unique outbox aggregate constraint.
- Produces: guarded report failure/revival, retry-budget reset, typed transition result for audit detail.

- [ ] **Step 1: Write failing PostgreSQL lifecycle tests**

Add tests that prove:

```python
assert dead_row.attempts == 5
await requeue_dead(session, dead_row.id)
assert dead_row.attempts == 0
assert run.status == "queued"
```

and separately:

```python
run.status = "succeeded"
await mark_claim_failed(..., retryable=True, attempts=5, max_attempts=5)
assert run.status == "succeeded"
```

Also cover dispatch-death revival, genuine execution-failure non-revival, and
re-request/requeue convergence on one outbox id.

- [ ] **Step 2: Verify RED**

Run the named new tests with
`NETOPS_TEST_DATABASE_URL=postgresql+asyncpg://... -m integration -q`.
Expected failures: attempts remain five, report stays queued at death, and
generic failed reports revive.

- [ ] **Step 3: Add provenance helpers and guarded transitions**

Use a bounded helper:

```python
DISPATCH_DEAD_PREFIX = "dispatch_dead:"

def dispatch_dead_error(error_code: str) -> str:
    return f"{DISPATCH_DEAD_PREFIX}{error_code}"

def is_dispatch_dead_error(error_class: str | None) -> bool:
    return bool(error_class and error_class.startswith(DISPATCH_DEAD_PREFIX))
```

In the DEAD branch, issue a same-session guarded update:

```python
update(ReportRun).where(
    ReportRun.id == run_id,
    ReportRun.status == ReportRunStatus.QUEUED.value,
).values(
    status=ReportRunStatus.FAILED.value,
    error_class=dispatch_dead_error(error_code),
    finished_at=now,
)
```

Return whether the row changed. In `requeue_dead`, set `attempts=0` and revive
only the failed/prefixed run, clearing `error_class` and `finished_at`.
Restrict `enqueue_report`'s reset block to the same prefix and reset the locked
existing outbox row.

Document `dispatch_dead:<typed-code>` in `ReportRun.error_class`.

- [ ] **Step 4: Audit relay death transactionally**

In the relay's database transaction, record `report.outbox_dead` with dispatch
id, aggregate id, error code, attempts, and `run_transitioned` boolean after
`mark_claim_failed` reports DEAD.

- [ ] **Step 5: Verify GREEN and commit**

Run all outbox unit and PG suites. Commit:

```bash
git commit -m "fix(reports): synchronize dead dispatch lifecycle"
```

---

### Task 3: Make dead dispatches operable and replay errors typed

**Files:**
- Modify: `backend/app/core/errors.py`
- Modify: `backend/app/services/report_outbox.py`
- Modify: `backend/app/api/v1/reports.py`
- Modify: `backend/app/schemas/reports_api.py`
- Modify: `backend/tests/api/test_reports.py`
- Modify: `backend/tests/services/test_report_outbox.py`
- Regenerate: `docs/api/openapi.json`
- Regenerate: `frontend/src/api/generated/openapi-types.ts`

**Interfaces:**
- Produces: `GET /api/v1/reports/outbox?state=dead`, typed 409 replay validation, documented 403/404/409 responses.

- [ ] **Step 1: Write failing API tests**

Prove the dead listing is admin-only, ordered, paginated, and returns only:

```json
{"id": "...", "run_id": "...", "error_code": "broker_unavailable",
 "attempts": 5, "created_at": "..."}
```

Add requeue tests for missing row (404) and invalid envelope (409 with
`urn:netops:error:invalid-dispatch-envelope`).

- [ ] **Step 2: Verify RED**

Run the named tests; expect 404 for the missing GET route and 500 for invalid
replay validation.

- [ ] **Step 3: Implement typed error and bounded listing**

Add:

```python
class InvalidDispatchEnvelopeError(ConflictError):
    title = "Invalid Dispatch Envelope"
    slug = "invalid-dispatch-envelope"
```

Catch service `InvalidDispatchEnvelope` at the API boundary and raise the typed
error without echoing payload content. Add response models and a bounded
`limit`/`offset` query selecting DEAD rows in deterministic created/id order.
Extend replay audit detail with `run_transitioned`.

- [ ] **Step 4: Normalize dispatch validation errors**

Make `durable_dispatch` raise `InvalidDispatchEnvelope` for allowlist,
argument-shape, payload, and stable-id validation failures. Keep broker failures
as redacted `DispatchPublicationError`.

- [ ] **Step 5: Regenerate contracts, verify, and commit**

Run API tests, OpenAPI export/check, generated TS sync, Ruff, and mypy. Commit:

```bash
git commit -m "fix(reports): expose and validate dead dispatch replay"
```

---

### Task 4: Enforce report-request authorization before persistence

**Files:**
- Modify: `backend/app/agents/documentation/tools.py`
- Modify: `backend/app/agents/automation/agent.py`
- Modify: `backend/tests/agents/documentation/test_report_tools.py`
- Modify: `backend/tests/agents/automation/test_automation_agent.py`

**Interfaces:**
- Produces: tool-level engineer minimum and explicit `ReportAccessDeniedError` execution handling.

- [ ] **Step 1: Remove the module-wide approve-all fixture and write RED tests**

Scope approval stubs only to tests that execute approved requests. Add a real
gate test invoking as `Role.VIEWER` and assert `RbacForbiddenError` plus zero
draft ChangeRequests. Add an executor test where access validation raises
`ReportAccessDeniedError` and assert the CR reaches the intended audited denial
state rather than the generic unexpected-exception path.

- [ ] **Step 2: Verify RED**

Expected: viewer creates a draft and the permission error bypasses the current
`except ValueError`.

- [ ] **Step 3: Implement minimal guards**

Declare:

```python
@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    change_request_kind=ChangeRequestKind.REPORT_GENERATION,
    min_role="engineer",
)
```

Catch `(ValueError, ReportAccessDeniedError)` at the report executor boundary,
preserving redacted/audited handling.

- [ ] **Step 4: Verify and commit**

Run documentation-tool, automation-agent, and role-matrix tests. Commit:

```bash
git commit -m "fix(reports): enforce request authorization floor"
```

---

### Task 5: Complete reconciliation and observability contracts

**Files:**
- Modify: `backend/app/services/reconciliation.py`
- Modify: `backend/app/workers/celery_app.py`
- Modify: `backend/app/core/metrics.py`
- Modify: `backend/tests/services/test_reconciliation.py`
- Modify: `backend/tests/pg/test_reconciliation_pg.py`
- Modify: `backend/tests/core/test_metrics.py` or the existing optional-import test module
- Modify: `backend/tests/services/test_reconciliation_prometheusrule_render.py`
- Modify: `deploy/observability/slo-burn-rate.alerts.yaml`

**Interfaces:**
- Produces: state-specific FAILED reconciliation, shared grace interval, complete slim-import symbols, source/chart recording-rule equality.

- [ ] **Step 1: Write RED tests**

Add a PG case requiring FAILED CR actions through
`executing_to_failed` but not `failed_to_rolled_back`. Add a mutation case
proving rolled-back actions cannot satisfy FAILED. Replace `.hex` target ids
with `str(cr.id)`. Add slim import iteration that asserts every exported metric
object exists and is `None`. Add canonical equality between
`slo-recording.rules.yaml` and rendered Helm recording groups.

- [ ] **Step 2: Verify RED**

Expected: FAILED CR omitted, `RECONCILIATION_SCHEDULE_ENABLED` absent during
slim import, and no recording-rule equality guard.

- [ ] **Step 3: Implement state-specific action sets**

Add:

```python
expected_failed = expected_completed[:-1] + (
    "change_request.executing_to_failed",
)
```

Compute distinct counts and select the count column by exact terminal state for
COMPLETED, FAILED, and ROLLED_BACK.

- [ ] **Step 4: Share grace and complete metrics fallback**

Use `BACKUP_MISS_GRACE` to derive beat hour/minute rather than a second literal.
Assign `RECONCILIATION_SCHEDULE_ENABLED = None` in the ImportError branch.
Correct the burn-window comment from 15m to 10m.

- [ ] **Step 5: Verify semantic/mutation/chart gates and commit**

Run reconciliation unit/PG tests, slim-import tests, promtool tests/bite,
Helm lint/render and equality tests. Commit:

```bash
git commit -m "fix(observability): close reconciliation review gaps"
```

---

### Task 6: Strengthen the Celery ratchet and its CI proof

**Files:**
- Modify: `backend/scripts/check_celery_dispatch.py`
- Modify: `backend/tests/scripts/test_check_celery_dispatch.py`
- Add: `backend/tests/fixtures/celery_dispatch_ratchet/task_star_import.py`
- Add: focused bare-decorator and canvas fixtures
- Modify: `.github/workflows/backend-gates.yml`
- Modify: `docs/security/celery-publication-ratchet.md`

**Interfaces:**
- Produces: `task_star_import` violation and exact negative-control exit contract.

- [ ] **Step 1: Add failing fixtures/tests**

Plant:

```python
from app.workers.tasks.discovery import *
run_discovery("id")
```

and assert `{"task_star_import"}`. Add supported bare-task-decorator and
chain/group canvas fixtures. Change the CLI test to assert return code exactly
`1` and expected violation tokens.

- [ ] **Step 2: Verify RED**

Expected: star import scans clean and the workflow text permits all non-zero
statuses.

- [ ] **Step 3: Implement star-import violation**

In `visit_ImportFrom`, when a task module imports `*`, record a violation at the
import line. Expand task-symbol decorator discovery to recognize both called
and bare `.task` decorators. Keep the checker intentionally bounded.

- [ ] **Step 4: Harden workflow exit handling**

Use a non-errexit block to capture status, then require exactly one:

```bash
set +e
output="$(python scripts/check_celery_dispatch.py --negative-control 2>&1)"
status=$?
set -e
test "$status" -eq 1
grep -q "send_task" <<<"$output"
```

Emit explicit errors for status `0` and status `>1`.

- [ ] **Step 5: Document dynamic limitations, verify, and commit**

Document `getattr`, `partial`, walrus aliases, and call-returned methods as
outside the static proof. Run positive inventory, negative CLI, checker tests,
and workflow contract tests. Commit:

```bash
git commit -m "fix(dispatch): make Celery ratchet run and bite"
```

---

### Task 7: Repair test hygiene and refresh evidence

**Files:**
- Modify: `backend/tests/api/test_reports.py`
- Modify: `backend/tests/services/test_reconciliation.py`
- Modify: `backend/tests/services/test_report_outbox.py`
- Modify: `docs/roadmap/P5-W1-HANDOFF.md`
- Modify: `docs/roadmap/p5-tasks/W1-T1-report-outbox-relay.md`
- Modify: `docs/roadmap/p5-tasks/W1-T2-send-task-ratchet.md`
- Modify: `docs/roadmap/p5-tasks/W1-T3-observability-reconciliation.md`

**Interfaces:**
- Produces: assertion-bearing publication, terminal-success, boundary-idempotency, and timezone tests.

- [ ] **Step 1: Replace tautologies**

Delete `sent_tasks`. Use a fail-fast monkeypatch of `celery_app.send_task` in
tests that assert no publication. Make the terminal-success test create/query a
successful backup row. Make the idempotency test invoke reconciliation twice
against persisted state and assert stable metrics/result, not equality of the
same pure call.

- [ ] **Step 2: Add missing helper/error tests**

Cover timezone-aware `outbox_status`, requeue 404, report executor denial and
failure paths, and every new audit detail.

- [ ] **Step 3: Run full verification**

Run:

```bash
cd backend
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/lint-imports
.venv/bin/pytest -n 4 -m 'not integration' --timeout=120 -q
```

Run the full W1 live-PostgreSQL suite, frontend lint/tsc/vitest/build, lockfile
and generated-contract checks, promtool semantic/mutation gates, Helm
lint/render, and `git diff --check`.

- [ ] **Step 4: Update Graphify and handoff**

Run `graphify update .`, query the repaired lifecycle and ratchet paths, and
record exact fresh counts/commits in the handoff. Commit:

```bash
git commit -m "test(reports): harden PR 169 regression proofs"
```

- [ ] **Step 5: Review, push, and recheck PR**

Run a final requirement-by-requirement audit, push `feat/p5-w1`, monitor PR
#169 checks, and reply to CodeRabbit findings with fix commits or the cited
disabled-backup rejection.
