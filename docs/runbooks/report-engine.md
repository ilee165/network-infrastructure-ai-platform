# Runbook — Compliance/Audit Report Engine (staleness, failures, redaction trips)

**Alerts covered:** `NetopsReportWeeklyStale`, `NetopsReportMonthlyStale`,
`NetopsReportRedactionViolation`, `NetopsReportFailureBurn`
(`deploy/observability/report-engine.alerts.yaml`; P4 W3-T1, ADR-0053 §9).

The report engine (ADR-0053) renders the four PRODUCTION.md §7 evidence
reports (change, compliance posture, access review, audit integrity) on the
`docs` Celery queue: beat-scheduled per kind (weekly/monthly defaults) plus
on-demand via `POST /api/v1/reports`. Artifacts (CSV + PDF) live in Postgres
(`report_artifacts`) with sha256 + a 7-year default expiry.

## NetopsReportWeeklyStale / NetopsReportMonthlyStale (page)

`netops_report_last_success_timestamp{report_kind}` is older than cadence +
grace (weekly: 8d; monthly: 33d). A scheduled evidence report has silently
stopped being produced.

1. **Has this kind ever succeeded?** A freshly deployed platform has no gauge
   sample until the first success (a never-set gauge cannot alert — if the
   alert fired, a success EXISTED and stopped).
   `SELECT kind, status, error_class, finished_at FROM report_runs ORDER BY created_at DESC LIMIT 20;`
2. **Runs failing?** If recent runs are `failed`, pivot on `error_class`
   (`redaction_violation` → the redaction section below; `builder_error` /
   `render_error` → worker logs `reports.builder_failed` /
   `reports.render_failed`, keyed by `run_id`).
3. **No runs at all?** Beat or the docs-queue worker is down:
   - beat process up? (`celery -A app.workers.celery_app beat` container);
   - docs worker consuming? `netops_celery_queue_depth{queue="docs"}` rising
     means enqueued-but-not-consumed; flat-zero with no runs means beat never
     fired (check `report_generation_hour/minute` + per-kind
     `report_*_cadence` settings).
4. **Recovery:** trigger the missed period on demand (RBAC floor applies):
   `POST /api/v1/reports {"kind": ..., "period_start": ..., "period_end": ...}`.
   Generation is idempotent per (kind, period) — a duplicate request cannot
   double-generate; a previously failed period is re-attempted.

## NetopsReportRedactionViolation (page — the distinguished class)

`enforce_redaction` (ADR-0053 §6 layer 2) rejected a payload in the single
render path and generation failed CLOSED — no artifact was written. This pages
because the filter caught secret-shaped material headed for an artifact that
LEAVES the platform (once exported, unrecoverable).

1. Find the run: `SELECT id, kind, error_class FROM report_runs WHERE status='failed' AND error_class='redaction_violation' ORDER BY updated_at DESC;`
   The audit entry (`report.generation_failed`) and worker log
   (`reports.redaction_violation`) carry the **field path and rule only —
   never the value** (by design; do not go looking for the value in logs, it
   is not there).
2. **Real secret in a source?** If the field path points at data (not a field
   name), a secret-formatted value (PEM/JWT/AKIA/vendor token) reached a
   report source table — treat as an incident: identify how it got there,
   purge it at the source, rotate the credential.
3. **False positive?** A legitimate field name matching the deny class (e.g. a
   column literally named `*_token_count`): rename the field in the builder or
   extend the payload so the name no longer matches — the deny list itself
   lives ONLY in `backend/app/engines/reports/redaction.py` and any narrowing
   is a strong-reviewed change (fail-closed is the accepted cost, ADR-0053
   "Negative").
4. Re-run the period on demand once fixed (the failed claim row is reclaimed).

## NetopsReportFailureBurn (ticket)

≥2 generation failures for one kind within 6h — persistent breakage; the
kind's staleness page follows at cadence + grace if unfixed. Triage exactly as
step 2 of the staleness flow (pivot on `error_class`, then worker logs by
`run_id`).

## Verification after any fix

- `GET /api/v1/reports?kind=<kind>` shows a `succeeded` run for the period;
- `netops_report_last_success_timestamp{report_kind="<kind>"}` advanced;
- the staleness alert resolves within its `for:` hold.

## Report contents — change report (`kind=change`; ADR-0053 §7.1, W3-T2)

API note for consumers of `POST/GET /api/v1/reports` with `kind=change`
(engineer+ floor, weekly beat cadence, regime tag `soc2:CC8.1`): the artifact
is the CR lifecycle roll-up for the CLOSED-OPEN UTC period `[start, end)` —
a CR appears when any `change_request.*` audit event falls in the period
(start instant included, end instant excluded), and appears with its
**complete** transition history, which may extend beyond the period.

Four sections per artifact (CSV and PDF carry the same structure; the golden
fixture `backend/tests/engines/reports/golden/change_report_golden.json` pins
it for the W4-T3 conformance checks):

1. **Change requests** — CR id, kind, state, requester, executor (human or
   agent, from the `approved_to_executing` audit actor), created (UTC), and
   the reasoning-trace LINK (`trace:<id> via /api/v1/agents/<session>` — an
   id/URL resolved under the *viewer's* RBAC at view time, never trace
   content).
2. **Approvals (four-eyes evidence)** — approver identity with IdP subject for
   federated accounts (`name [idp:<subject>]`, D11), decision, timestamp.
3. **Lifecycle transitions** — every `change_request.*` audit event (creation,
   four-eyes waivers, each state edge) with actor and UTC timestamp.
4. **Diff statistics and snapshot references** — outcome token, verified flag,
   `applied_diff` LINE COUNT, and the baseline snapshot reference
   (`sha256:<hash>`). Statistics and references only (ADR-0021 posture):
   **config text never enters this report** — every JSONB-derived cell is a
   validated token, bool, count, or SHA-256 hex reference.
