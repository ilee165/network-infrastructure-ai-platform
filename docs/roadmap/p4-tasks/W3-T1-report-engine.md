# W3-T1 — Report engine: PG report model + beat scheduling + air-gap CSV/PDF renderers + retention + RBAC + fail-closed redaction

| | |
|---|---|
| **Wave** | P4 W3 — Compliance & audit reporting suite |
| **Owner** | `wf-implementer` (strong) |
| **Review tier** | **strong** spec + quality (escalated: audit spine + artifacts leave the platform) |
| **Depends on** | **W0-T4** (ADR-0053, the contract) |
| **ADRs** | ADR-0053 §1–§6/§9 (binding), ADR-0008 (beat/queues), ADR-0011/0038 (audit), ADR-0015/0046 (metrics/alerts), P3-W0-T8 (lockfile) |
| **PRODUCTION.md** | §7, §11 G-SEC/G-OBS |
| **Status** | Proposed |

## Objective

Implement the ADR-0053 engine: **`engines/reports/` over `report_runs` +
`report_artifacts` (plus the §7.2 trend tables in the same expand-only
revision), Celery beat on the existing `docs` queue + on-demand API with a
claim-row guard, stdlib CSV with formula-injection neutralization, WeasyPrint
PDF behind a deny-all `url_fetcher` with bundled fonts, the three-layer
fail-closed redaction contract, RBAC at generation AND download (both audited),
retention purge, and the §9 metrics/alerts.** The four report payloads land in
T2–T5 on top of this engine.

## Scope

**In** — `engines/reports/` module (payloads: frozen Pydantic,
`extra="forbid"`; Jinja2 templates; single render path); one expand-only
migration: `report_runs`, `report_artifacts` (bytea + sha256 + expires_at),
`compliance_runs`, `compliance_run_findings` (ADR-0053 §7.2 — same revision
per the ADR); `app.workers.tasks.reports` on the `docs` queue; beat entries +
settings (cadence per kind, `.env.example` ↔ `config.py` 1:1);
`POST /api/v1/reports` + artifact metadata/download endpoints; claim-row guard
(`_claim_backup_run` precedent); per-kind RBAC floors enforced at generation
AND download; audit entry per generation and per download;
`reports.purge_expired` daily task (7-year PROPOSED default, per-kind
override); CSV writer neutralizing `=`,`+`,`-`,`@`,TAB,CR cells; WeasyPrint +
custom deny-all `url_fetcher` (file:-in-template-dir + data: only), fonts
bundled (`fonts-dejavu-core` in `backend.Dockerfile`); WeasyPrint + transitive
pins via the uv lockfile; `redaction.py::enforce_redaction` choke point
(deny-class field names + format-anchored value patterns — NO bare entropy
detection); source allowlist as an import-linter boundary + a
no-SELECT-deny-set test; fail-closed semantics (typed `error_class`, field
path only, no partial artifact); §9 metrics + staleness/failure alerts with
should-fire `promtool` cases; Documentation-Agent read/trigger tools (list
runs, fetch metadata, request generation under invoking-user RBAC).

**Out** — the four report payload/template implementations (W3-T2..T5); the
regime-mapping doc (W3-T6); the planted-secret eval corpus (W4-T3); e-mail/
webhook distribution, legal holds, MinIO (named deferrals); the RAG-embedded
`documents` table (structurally excluded).

## Requirements (grounded in ADR-0053 §1–§6/§9)

1. **Never the `documents` table** — reports are never embedded; the exclusion
   is structural (separate model + boundary test).
2. **Deterministic, LLM-free renders** — timestamp injected as payload data;
   PDF metadata pinned; no LLM path into artifacts.
3. **Redaction fail-closed at one choke point** — every payload passes
   `enforce_redaction` in the single render path; a hit aborts with
   `redaction_violation`, names the field path only, increments the failure
   counter, writes an audit entry.
4. **Zero render-time egress** — a CDN reference is a render-time CI error;
   the fetcher doubles as the SSRF guard.
5. **RBAC honored at download time** (role change between generation and
   download bites); floors: change/posture `engineer`+, access-review/
   audit-integrity `admin` (PROPOSED, refinable).
6. **Idempotent per `(kind, period)`** — beat + on-demand cannot
   double-generate (claim row).
7. **Alerts conform to ADR-0046** — staleness per scheduled kind + failure
   burn, runbook links, promtool should-fire cases proven to bite.

## Contracts / artifacts

- Engine module + migration + tasks + API + templates skeleton + redaction
  module + Dockerfile apt layer + lockfile update + alert rules + runbooks +
  agent tools; API docs.

## Test & gate plan

- Full gate suite; `tests/pg/` under `pg-integration` for report queries,
  claim-row semantics, purge, artifact round-trip.
- Redaction unit set: deny-class names, PEM/JWT/AKIA patterns, clean payloads
  pass, SHA-256 digests NOT flagged (the ADR-0038 lesson).
- Render tests: templates render offline (fetcher denies all remote); CSV
  neutralization cases; PDF structure extraction smoke.
- Import-linter boundary + no-SELECT-deny-set test green.
- `promtool test rules` incl. should-fire cases; metrics exposed.

## Exit criteria

- [ ] Engine + tables live (expand-only, single revision incl. §7.2 tables); artifacts in PG with sha256 + expiry.
- [ ] Beat + on-demand generation with claim-row idempotency; cadence settings wired 1:1.
- [ ] RBAC at generation AND download; every generation/download audited.
- [ ] CSV formula-injection neutralization + WeasyPrint deny-all fetcher + bundled fonts — zero render-time egress, asserted in CI.
- [ ] Redaction choke point + source allowlist + fail-closed semantics green (planted-secret bite proof lands in W4-T3).
- [ ] Retention purge task live; §9 metrics + alerts with biting promtool cases.
- [ ] Lockfile + Trivy gates green with WeasyPrint + apt layer; one atomic commit.

## Workflow

`wf-implementer` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **A second render path** would bypass the choke point — keep exactly one
  payload→artifact path; boundary-tested.
- **Fetcher allowlist too wide** (e.g. any `file:`) reopens SSRF/local-read —
  template-dir-scoped only.
- **Image bloat/CVE surface** from the Pango/HarfBuzz layer — measured at
  land time; the split-image escalation is named in the ADR if Trivy demands
  it.
