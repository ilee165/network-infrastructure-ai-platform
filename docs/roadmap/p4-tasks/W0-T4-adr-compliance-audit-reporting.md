# W0-T4 — ADR-0053 compliance & audit reporting suite (report engine, air-gap CSV/PDF, redaction contract)

| | |
|---|---|
| **Wave** | P4 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** (secret surface: the engine reads the audit spine and renders artifacts that leave the platform) |
| **Depends on** | — |
| **Builds on** | ADR-0011/0038 (audit spine), ADR-0018 (compliance engine), ADR-0020/0021 (CR lifecycle), ADR-0028 (OIDC/break-glass), ADR-0008 (Celery beat), ADR-0015/0046 (metrics/alerts), ADR-0019 (documents/RAG — the surface reports must NOT ride), P3-W0-T8 (lockfile) |
| **PRODUCTION.md** | §7 (the four reports), §12 (regimes/retention), §11 G-SEC/G-OBS |
| **Status** | **Done** (W0, `feat/p4-w0-adrs`) |

## Objective

Ratify the reporting design the W3 build implements field-for-field: **a
deterministic, LLM-free report engine (`engines/reports/`) over a dedicated PG
model (`report_runs`/`report_artifacts` — never the RAG-embedded `documents`
table), Celery beat on the existing `docs` queue + on-demand API, stdlib CSV
with formula-injection neutralization, WeasyPrint PDF behind a deny-all
`url_fetcher` with bundled fonts (zero render-time egress), a three-layer
fail-closed redaction contract (source allowlist + one choke-point filter +
secret-free history tables), RBAC on generation AND download (both audited),
7-year PROPOSED retention with scheduled purge, SOC 2 CC-series PROPOSED regime
tags, and the two named history tables** (`compliance_runs`/
`compliance_run_findings` for trend; `audit_chain_verification_runs` for the
integrity trail).

## Scope

**In** — engine + PG model (§1), scheduling incl. the daily compliance sweep
(§2), RBAC + audit posture, no-CR rationale (§3), retention default (§4),
renderer evaluation + air-gap enforcement (§5), the redaction contract + its
W4-T3 eval obligation (§6), the four report contracts incl. history tables
(§7), regime-tag default (§8), metrics/alerts (§9).

**Out** — implementation (W3-T1..T6); the eval corpus (W4-T3); regime-mapping
*content* (W3-T6 doc); SIEM delivery of report artifacts; e-mail/webhook
distribution and legal-hold exceptions (named future enrichments); Consultant
§12 answers (regimes/retention/role floors stay PROPOSED, rebased when
answered).

## Requirements (grounded in PRODUCTION.md §7, ADR-0011/0038, P4-PLAN §0a)

1. **Redaction is structural and fail-closed** — no plaintext credential/secret
   in any artifact; a redaction hit aborts generation naming the field path
   only; the planted-secret negative control must RUN and BITE (W4-T3).
2. **Reports never enter the RAG index** — a dedicated model makes the
   exclusion structural (embedding an access-review report would be an RBAC
   bypass by construction).
3. **Air-gap by code, not convention** — deny-all fetcher + bundled fonts;
   a CDN reference is a CI render error.
4. **Evidence-grade determinism** — payload → template → renderer; LLM prose
   has no path into an artifact; the Documentation Agent triggers and cites,
   never authors.
5. **Trend and integrity history named** — the two history tables convert
   metric-only signals into 7-year evidence trails; missing verification days
   surface as findings.
6. **New deps governed** — WeasyPrint via the uv lockfile; the apt layer under
   the Trivy gate.

## Contracts / artifacts

- `docs/adr/0053-compliance-audit-reporting.md` (Proposed); index entry via W0-T5.

## Test & gate plan

- D16 docs gates only (ADR — no code). The ADR names the exact assertions W3
  (allowlist boundary test, no-SELECT-deny-set, promtool should-fire cases,
  `tests/pg/` coverage) and W4-T3 (planted-secret bite proof, golden structure
  fixtures) must satisfy.

## Exit criteria

- [x] ADR-0053 written (Proposed): engine/model, scheduling, RBAC+audit, retention, renderer choice + air-gap enforcement, three-layer redaction, four report contracts + history tables, regime tags, metrics/alerts.
- [x] Reviewed whole at the strong bar (secret surface).
- [x] Rejected alternatives recorded (documents-table reuse, LLM-authored prose, entropy-based detection, CR-gated generation, per-report redaction).
- [x] One atomic commit (`888229c`).

## Workflow

`wf-implementer` drafts → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Redaction false positives** block scheduled reports (fail-closed) —
  accepted; a missing report pages, a leaked credential is unrecoverable.
- **Deny-list curation drift** as new sources join reports — mitigated by the
  source allowlist doing the heavy lifting + the one-module pinned list + the
  planted-secret eval.
