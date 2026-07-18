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

## Report contents — compliance posture report (`kind=compliance_posture`; ADR-0053 §7.2, W3-T3)

API note for consumers of `POST/GET /api/v1/reports` with
`kind=compliance_posture` (engineer+ floor, weekly beat cadence, regime tags
`soc2:CC7.1` + `soc2:CC4.1`): the artifact rolls the M4 compliance engine up
from the **persisted run history** (`compliance_runs` /
`compliance_run_findings`), populated by the daily `reports.compliance_sweep`
beat task (`compliance_sweep_hour/minute` settings). The history persists
**status/severity only — no evidence-excerpt column exists** (ADR-0053 §6
layer 3); live excerpt drill-down stays on the on-demand engineer+ endpoint
`GET /config-snapshots/{device_id}/compliance`.

Six sections per artifact (CSV and PDF carry the same structure; the golden
fixture `backend/tests/engines/reports/golden/compliance_posture_golden.json`
pins it for the W4-T3 conformance checks):

1. **Compliance evaluation runs** — every run in the CLOSED-OPEN UTC period
   with trigger (`sweep`/`on_demand`), **policy-pack id + version, and engine
   version stamped per run** (evidence provenance).
2. **Latest posture by policy** — pass/violation/skipped counts from the most
   recent run in the period.
3. **Latest posture by device** — hostname + vendor per device (a deleted
   device renders `device:<uuid>`).
4. **Latest posture by severity** — the full ADR-0018 vocabulary
   (`info`/`warn`/`violation`), zeros are measured.
5. **Daily posture trend** — one row per UTC day; a day's posture comes from
   its most recent run. **A day with no recorded sweep renders the explicit
   `gap` marker — never an interpolated or carried-forward value** (a run of
   gap days means the daily sweep is not firing: check the
   `compliance-daily-sweep` beat entry and the docs-queue worker, then the
   staleness flow above).
6. **Out-of-scope vendors** — F5 BIG-IP and VMware vSphere have **no
   text-config compliance surface in P4** (ADR-0050 §7.6 / ADR-0051 §3 named
   deferrals): their devices are reported as uncovered — out-of-scope is
   **not** passing.

## Report contents — access review report (`kind=access_review`; ADR-0053 §7.3, W3-T4)

API note for consumers of `POST/GET /api/v1/reports` with `kind=access_review`
(**admin floor at BOTH generation and artifact download** — the
highest-sensitivity report; monthly beat cadence; regime tags `soc2:CC6.1` +
`soc2:CC6.2` + `soc2:CC6.3`): the artifact is the periodic access-review
evidence for the CLOSED-OPEN UTC period `[start, end)`. Every download of this
report writes its own audit entry (`report.artifact_downloaded` with the
artifact sha256) — evidence about evidence — and the admin floor is
re-evaluated from the database at download time, so a demotion after
generation denies the download.

Five sections per artifact (CSV and PDF carry the same structure; the golden
fixture `backend/tests/engines/reports/golden/access_review_golden.json` pins
it for the W4-T3 conformance checks):

1. **User accounts and role assignments** — every local + OIDC account with
   role, provider (`local`, `oidc`, `local (break-glass)` for local admins
   while OIDC is enabled, `local (fenced while OIDC enabled)` otherwise),
   enabled/disabled status, creation time, **last login** (derived from the
   audit login events `auth.login` / `auth.local.breakglass_login` /
   `auth.oidc.login_succeeded`, anchored strictly before the period end), and
   an honest activity classification: `active`, `dormant`,
   `never-logged-in (dormant)` (the service/bootstrap-account surface —
   **surfaced, never silently excluded**), or `never-logged-in (new account)`
   (created inside the dormancy window — new, not dormant). The window is
   `NETOPS_REPORT_ACCESS_REVIEW_DORMANT_DAYS` (default 90) ending at the
   period end.
2. **Role assignment summary** — accounts/enabled/disabled per RBAC role in
   rank order (`viewer` → `admin`); zero-account roles render measured zeros.
3. **OIDC federation posture** — enabled/disabled, groups claim, the
   admin-via-OIDC opt-in state, the break-glass local-login fence state
   (ADR-0028 §5), and the dormancy window in force.
4. **IdP group-to-role assignments** — the configured `group → role` map with
   the **effective** role at login (the ADR-0028 §4 admin cap and deny-default
   are surfaced, and an invalid role name renders as a visible
   misconfiguration).
5. **Break-glass local logins in period** — **every**
   `auth.local.breakglass_login` audit entry in the period (time, actor, user
   id, request id); an empty period carries an explicit note. A row here means
   the alerted local-admin recovery path was used — review each one.

Zero credential-adjacent data (ADR-0053 §6 layer 1): the builder projects
explicit secret-free columns only — `users.password_hash` and the
`refresh_sessions` table are deny-set surfaces the no-SELECT boundary proof
(`backend/tests/engines/reports/test_boundary.py`) asserts are never queried.
Roster/role/mapping state is generation-time state (the platform keeps no
role-assignment history); login-derived columns are anchored at the period end.
