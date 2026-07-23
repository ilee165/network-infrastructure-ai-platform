# P5 W1 handoff — dispatch durability and observability debt

**Verdict:** **IMPLEMENTED / VERIFIED** on `feat/p5-w1` at `79e837e1`
(2026-07-23). This closes W1 only. W2–W5 remain pending, P5 is not released,
and ADR-0059 remains Proposed until W5-T3.

## Requirement-to-evidence map

| Contract | Exact implementation and proof | Commit / review verdict |
|---|---|---|
| T1 outbox schema, safe envelope, stable dispatch ID, expand-only migration | `backend/app/models/dispatch_outbox.py`, `backend/alembic/versions/0023_p5_report_dispatch_outbox.py`, `backend/tests/migrations/test_0023_report_dispatch_outbox.py`, `backend/tests/services/test_report_outbox_envelope.py` | `7973b979`, `998ac7a8`, `a3f475e3`; dual strong spec/quality reviews completed and final strong verifier **VERIFIED** |
| T1 scheduled and on-demand atomic enqueue; no pre-commit/direct publish | `backend/app/services/report_outbox.py`, `backend/app/api/v1/reports.py`, `backend/app/agents/framework/report_requests.py`, `backend/app/agents/documentation/tools.py`, `backend/tests/pg/test_report_outbox_pg.py` | `7973b979`, `998ac7a8`, `2fd8320a`, `4ae5cac0`; final strong verifier **VERIFIED** |
| T1 lease, bounded `SKIP LOCKED`, stale recovery, post-send redelivery with one effect, poison/dead replay | `backend/app/workers/tasks/report_outbox.py`, `backend/tests/pg/test_report_outbox_pg.py`, `backend/tests/services/test_report_outbox.py` | `7973b979`, `998ac7a8`, `a3f475e3`; final strong verifier **VERIFIED** |
| T1 metrics, alerts, audited RBAC replay, runbook, report conformance | `backend/app/core/metrics.py`, `deploy/observability/report-engine.alerts.yaml`, `deploy/observability/report-engine.alerts.test.yaml`, `deploy/observability/run-report-promtool-bite.sh`, `docs/runbooks/report-outbox-relay.md`, `backend/tests/engines/reports/test_boundary.py` | T1 commit series above plus `4ae5cac0`; dual strong reviews and final strong verifier **VERIFIED** |
| T2 zero unjustified publications and wrapper routing/ID/error contract | `backend/app/workers/dispatch.py`, migrated callers under `backend/app/`, `docs/security/celery-publication-ratchet.md`, `backend/tests/services/test_report_outbox.py` | `1815cc68`, `79e837e1`; combined review completed and verifier **VERIFIED** |
| T2 AST ratchet, blocking CI, aliases/multiline/nested forms, visitor mutation and planted calls | `backend/scripts/check_celery_dispatch.py`, `backend/tests/scripts/test_check_celery_dispatch.py`, `backend/tests/fixtures/celery_dispatch_ratchet/`, `.github/workflows/backend-gates.yml` | `1815cc68`, `79e837e1`; combined review completed and verifier **VERIFIED** |
| T3 backup, CR/audit, and trace reconciliation semantics and PG joins | `backend/app/services/reconciliation.py`, `backend/app/workers/tasks/reconciliation.py`, `backend/tests/services/test_reconciliation.py`, `backend/tests/pg/test_reconciliation_pg.py` | `59e8b7b3`, `2a1a7c4e`, `ba2e60a6`, `80e1d99a`; review/fix verifier **VERIFIED**, followed by live-PG verification |
| T3 bounded series, recording/burn/staleness alerts, runbooks, deployed chart seam | `backend/app/core/metrics.py`, `deploy/observability/slo-recording.rules.yaml`, `deploy/observability/slo-burn-rate.alerts.yaml`, `deploy/kubernetes/netops/templates/slo-recording-prometheusrule.yaml`, `deploy/kubernetes/netops/templates/slo-burn-rate-prometheusrule.yaml`, `docs/runbooks/slo-config-backup-completeness.md`, `docs/runbooks/slo-change-request-audit-completeness.md`, `docs/runbooks/slo-reasoning-trace-persistence.md` | `59e8b7b3`, `2a1a7c4e`, `1db099b8`; review/fix verifier **VERIFIED** |
| T3 should-fire/quiet cases and mutation bites; PRODUCTION §6 rows 5/6/9 backed | `deploy/observability/reconciliation.alerts.test.yaml`, `deploy/observability/run-reconciliation-promtool-bite.sh`, `docs/roadmap/PRODUCTION.md` | `59e8b7b3`, `2a1a7c4e`, `ba2e60a6`, `1db099b8`; verifier **VERIFIED** |

## Fresh closeout results

The final cross-task evidence run reported:

- backend non-integration: **4,393 passed, 30 skipped**;
- live PostgreSQL W1 suite: **35 passed**;
- dispatch checker: clean tree green, all six forbidden-form negative controls
  red, then **27 focused tests passed**;
- D16 lanes: Ruff check/format, mypy (**299 source files**), import-linter
  (**10 contracts**), config/chart drift, and OpenAPI drift all clean;
- Prometheus: **10 recording-rule**, **19 SLO-alert**, and **7 report-alert**
  tests passed, including semantic and reconciliation/report mutation bites;
- Helm lint and render passed.

The branch range is the goal/rider `44eec806` plus W1 implementation and
focused fix commits `59e8b7b3`, `2a1a7c4e`, `7973b979`, `ba2e60a6`,
`1db099b8`, `80e1d99a`, `998ac7a8`, `a3f475e3`, `2fd8320a`, `4ae5cac0`,
`1815cc68`, and `79e837e1`.

## Rider P9 closeout

- `p5_w1_all_three_deep_spec_exit_criteria_are_mapped_to_evidence`: **PASS** —
  the table above and the three implemented deep specs map every requirement.
- `p5_w1_branch_is_clean_and_contains_only_goal_and_w1_commits`: **PASS before
  this documentation commit** — `origin/main..79e837e1` is exactly the 13
  commits listed above; the final range adds only this closeout commit.
- `p5_w1_graphify_index_is_current`: **UNPROVEN / TOOL GAP** — this linked
  worktree has no root `graphify-out/graph.json`. Repeated `graphify update .`
  attempts completed the AST scan and then stalled in symbol resolution. T2
  reported completion, but no updated root graph is present here. A nested
  artifact queried during closeout identifies itself as using the pre-#1504
  node-ID scheme; the authoritative main-worktree graph therefore remains
  pre-#1504. This non-code closeout gap does not change the verified W1 runtime
  verdict and is deliberately not marked PASS.
