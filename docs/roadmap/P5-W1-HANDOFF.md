# P5 W1 handoff — dispatch durability and observability debt

**Verdict:** **IMPLEMENTED / VERIFIED** on `feat/p5-w1` at `263b51e5`
(2026-07-23). This closes W1 only. W2–W5 remain pending, P5 is not released,
and ADR-0059 remains Proposed until W5-T3. The final strong whole-branch review
after `263b51e5` is **APPROVED**.

## Requirement-to-evidence map

| Contract | Exact implementation and proof | Commit / review verdict |
|---|---|---|
| T1 outbox schema, safe envelope, stable dispatch ID, expand-only migration | `backend/app/models/dispatch_outbox.py`, `backend/alembic/versions/0023_p5_report_dispatch_outbox.py`, `backend/tests/migrations/test_0023_report_dispatch_outbox.py`, `backend/tests/services/test_report_outbox_envelope.py` | `7973b979`, `998ac7a8`, `a3f475e3`; dual strong spec/quality reviews completed and final strong verifier **VERIFIED** |
| T1 scheduled and on-demand atomic enqueue, scheduled catch-up, and approved report-request execution; no pre-commit/direct publish | `backend/app/services/report_outbox.py`, `backend/app/api/v1/reports.py`, `backend/app/agents/framework/report_requests.py`, `backend/app/agents/documentation/tools.py`, `backend/app/agents/automation/agent.py`, `backend/tests/pg/test_report_outbox_pg.py` | `7973b979`, `998ac7a8`, `2fd8320a`, `4ae5cac0`, `f1abf495`; final strong verifier **VERIFIED** and whole-branch review **APPROVED** |
| T1 lease, bounded `SKIP LOCKED`, stale recovery, post-send redelivery with one effect, poison/dead replay | `backend/app/workers/tasks/report_outbox.py`, `backend/tests/pg/test_report_outbox_pg.py`, `backend/tests/services/test_report_outbox.py` | `7973b979`, `998ac7a8`, `a3f475e3`; final strong verifier **VERIFIED** |
| T1 metrics, alerts, audited RBAC replay, runbook, report conformance | `backend/app/core/metrics.py`, `deploy/observability/report-engine.alerts.yaml`, `deploy/observability/report-engine.alerts.test.yaml`, `deploy/observability/run-report-promtool-bite.sh`, `docs/runbooks/report-outbox-relay.md`, `backend/tests/engines/reports/test_boundary.py` | T1 commit series above plus `4ae5cac0`; dual strong reviews and final strong verifier **VERIFIED** |
| T2 zero unjustified publications and wrapper routing/ID/error/canvas contract | `backend/app/workers/dispatch.py`, migrated callers under `backend/app/`, `backend/tests/workers/test_dispatch_canvas.py`, `docs/security/celery-publication-ratchet.md`, `backend/tests/services/test_report_outbox.py` | `1815cc68`, `79e837e1`, `e5708d55`; combined verifier **VERIFIED** and whole-branch review **APPROVED** |
| T2 AST ratchet, blocking CI, aliases/multiline/nested/task-call/canvas forms, visitor mutation and planted calls | `backend/scripts/check_celery_dispatch.py`, `backend/tests/scripts/test_check_celery_dispatch.py`, `backend/tests/fixtures/celery_dispatch_ratchet/`, `.github/workflows/backend-gates.yml` | `1815cc68`, `79e837e1`, `e5708d55`; combined verifier **VERIFIED** and whole-branch review **APPROVED** |
| T3 backup enabled-state metric, CR/audit set-wise indexed query, terminal-state-specific lifecycle actions, trace semantics, and PG joins | `backend/app/services/reconciliation.py`, `backend/app/workers/tasks/reconciliation.py`, `backend/app/models/audit.py`, `backend/alembic/versions/0024_audit_reconciliation_lookup.py`, `backend/tests/migrations/test_0024_audit_reconciliation_lookup.py`, `backend/tests/services/test_reconciliation.py`, `backend/tests/pg/test_reconciliation_pg.py` | `59e8b7b3`, `2a1a7c4e`, `ba2e60a6`, `80e1d99a`, `f2607bca`, `263b51e5`; review/fix verifier **VERIFIED**, live-PG verified, whole-branch review **APPROVED** |
| T3 bounded series, recording/burn/staleness alerts, SLO roster, runbooks, deployed chart seam | `backend/app/core/metrics.py`, `backend/tests/agents/eval/test_slo_alert_corpus.py`, `deploy/observability/slo-recording.rules.yaml`, `deploy/observability/slo-burn-rate.alerts.yaml`, `deploy/kubernetes/netops/templates/slo-recording-prometheusrule.yaml`, `deploy/kubernetes/netops/templates/slo-burn-rate-prometheusrule.yaml`, `docs/runbooks/slo-config-backup-completeness.md`, `docs/runbooks/slo-change-request-audit-completeness.md`, `docs/runbooks/slo-reasoning-trace-persistence.md` | `59e8b7b3`, `2a1a7c4e`, `1db099b8`, `f2607bca`, `263b51e5`; review/fix verifier **VERIFIED** and whole-branch review **APPROVED** |
| T3 should-fire/quiet cases and mutation bites; PRODUCTION §6 rows 5/6/9 backed | `deploy/observability/reconciliation.alerts.test.yaml`, `deploy/observability/run-reconciliation-promtool-bite.sh`, `docs/roadmap/PRODUCTION.md` | `59e8b7b3`, `2a1a7c4e`, `ba2e60a6`, `1db099b8`, `f2607bca`, `263b51e5`; verifier **VERIFIED** and whole-branch review **APPROVED** |

## Fresh closeout results

The final cross-task evidence run reported:

- backend non-integration: **4,412 passed, 30 skipped**;
- live PostgreSQL W1 suite: **38 passed**;
- dispatch checker: clean tree green; negative controls reject `send_task`,
  `apply_async`, `delay`, `task_call`, and three `canvas_call` forms;
- focused checker, OpenAPI, and migration tests: **35 passed**;
- D16 lanes: Ruff check/format, mypy, import-linter, static/config/chart drift,
  OpenAPI drift, and the dispatch checker all clean;
- Prometheus: **11 recording-rule**, **19 SLO-alert**, and **7 report-rule**
  tests passed, including semantic and both reconciliation/report mutation
  bites;
- Helm lint and render passed; Alembic head is **0024**.

The branch range is the goal/rider `44eec806` plus W1 implementation and
focused fix commits `59e8b7b3`, `2a1a7c4e`, `7973b979`, `ba2e60a6`,
`1db099b8`, `80e1d99a`, `998ac7a8`, `a3f475e3`, `2fd8320a`, `4ae5cac0`,
`1815cc68`, `79e837e1`, `f2607bca`, `f1abf495`, `e5708d55`, and `263b51e5`.

## Rider P9 closeout

- `p5_w1_all_three_deep_spec_exit_criteria_are_mapped_to_evidence`: **PASS** —
  the table above and the three implemented deep specs map every requirement.
- `p5_w1_branch_is_clean_and_contains_only_goal_and_w1_commits`: **PASS before
  this documentation commit** — `origin/main..263b51e5` contains the goal,
  W1 implementation/review-fix commits listed above, and the prior
  documentation-only closeout commits; the final range adds only this refresh.
- `p5_w1_graphify_index_is_current`: **PASS** — exact committed W1 HEAD was
  exported to native Linux ext4, where `graphify update .` completed with exit
  0 in 21.25 seconds and rebuilt 1,274 source files into 21,478 nodes, 50,095
  edges, and 954 communities. The ignored `graphify-out` was copied back to
  this linked worktree; graph and manifest mtimes are 2026-07-23 15:54:12 and
  15:54:13. A closeout query surfaced `ScheduledReportSpec`,
  `ChangeRequestGate`, `durable_dispatch`, reconciliation controls, and the W1
  specs. Direct update on DrvFS had stalled during symbol resolution, so the
  native ext4 rebuild remains the successful, authoritative workaround.
