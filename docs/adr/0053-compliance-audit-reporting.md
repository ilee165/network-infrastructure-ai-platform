# ADR-0053: Compliance & Audit Reporting Suite — Report Engine, Air-Gap CSV/PDF Rendering, Redaction Contract, SOC 2 CC-Series Default

**Status:** Proposed | **Date:** 2026-07-05 | **Milestone:** P4 W0

## Context

`PRODUCTION.md` §7 mandates four compliance/audit reports — **change report**,
**compliance posture report**, **access review report**, **audit-integrity
report** — scheduled (weekly/monthly) and on-demand, exportable CSV/PDF, usable
as control evidence regardless of regime, with SOC 2 CC-series structuring as
the **PROPOSED** default until the Consultant's "compliance regimes" open item
(§12) is answered. `P4-PLAN.md` §3 schedules the build as **W3** (T1 engine,
T2–T5 the four reports, T6 regime mapping) with the eval proof in **W4-T3**
(report conformance + planted-secret redaction negative control). This ADR is
the **design gate**: the code lands in W3 field-for-field against the sections
below. No code in this ADR.

This is a **secret-surface decision** (strong review bar, P4-PLAN §0a/§2): the
report engine reads the audit spine and renders artifacts that **leave the
platform** (downloaded, mailed to auditors, attached to tickets). An artifact
is the one output that escapes every runtime RBAC/redaction control we have —
once a credential is in a PDF on an auditor's laptop, no platform control can
recall it. The redaction contract (§6) is therefore the load-bearing section.

The decision is bounded by:

- **ADR-0011 / ADR-0038 (audit spine).** `audit_log` is append-only and
  hash-chained; the daily verification CronJob (ADR-0038 §4) recomputes the
  chain from a checkpoint watermark, emits a Prometheus metric, and exits
  non-zero on a break. Today its outcomes live only in metrics/logs — the
  audit-integrity report needs a queryable history (§7.4 names it).
- **ADR-0018 + the M4 compliance engine reality.** `evaluate_policy()`
  (`backend/app/engines/config_mgmt/compliance/engine.py`) is evaluated
  **on demand** per device via `GET /config-snapshots/{device_id}/compliance`
  (engineer+) and persists **nothing**. Findings may carry **config excerpts**,
  and config text is secret-bearing (ADR-0017). The §7 trend requirement
  ("pass/fail … trend over time") is unimplementable without run-history
  persistence — §7.2 names it, and names it **secret-free by construction**.
- **ADR-0020/0021 (CR lifecycle).** The change report rolls up
  `change_requests`/`approvals`/audit/reasoning-trace links. ADR-0021 already
  rules config text out of `ChangeResult` (redaction-safe `applied_diff`, line
  counts only); the change report inherits that posture (§7.1).
- **ADR-0028 (OIDC/SSO).** Users, roles, IdP group→role mappings, break-glass
  local login (alerted + audited) — the access-review report's sources (§7.3).
- **ADR-0008 / D8 (async jobs).** Celery + Redis with fixed queues; beat
  schedules already drive nightly backup and the retention purges
  (`create_celery_app()`, `backend/app/workers/celery_app.py`). Report
  scheduling reuses this spine — no new scheduler (§2).
- **ADR-0015 / ADR-0046 (observability).** New metrics join the `netops_*`
  namespace; every alert is a multi-window burn-rate (or staleness) rule with a
  resolving `runbook_url` and a *should-fire* `promtool` case that is proven to
  bite (§9).
- **ADR-0019 / M4 documents.** Generated documents (`documents` table,
  `DocumentKind`/`DocumentFormat` in `backend/app/models/config_mgmt.py`) are
  **chunked and embedded into the pgvector RAG index** (`embed_document()`,
  `backend/app/knowledge/embedding.py`) and retrievable by agents. Reports must
  **not** ride this table (§1): embedding an access-review report would leak
  admin-only user/role/login data into any user's RAG retrieval — an RBAC
  bypass by construction.
- **D16 + the P3-W0 lockfile.** The PDF renderer is a new dependency; it lands
  via the uv lockfile under the drift gate (P4-PLAN §0a), and its system
  libraries land in the `python:3.12-slim` backend image
  (`deploy/docker/backend.Dockerfile`) under the Trivy gate.
- **Air-gap posture (§12 open item).** The platform must render evidence with
  **zero network egress at render time** — no CDN stylesheet, no font fetch, no
  telemetry. This is a hard requirement on the renderer choice (§5), not a
  deployment nicety.

## Decision

**Ship a deterministic report engine (`engines/reports/`) over a dedicated PG
report model (`report_runs` + `report_artifacts`, never the RAG-embedded
`documents` table), scheduled by Celery beat on the existing `docs` queue
(weekly/monthly defaults + on-demand API), rendering CSV via the stdlib with
formula-injection neutralization and PDF via WeasyPrint (BSD-3-Clause) behind a
deny-all URL fetcher with bundled fonts — zero network at render time. Every
artifact passes a fail-closed render-time redaction filter (deny-class field
names + format-anchored value patterns) layered over a source allowlist that
structurally excludes secret-bearing tables/columns; a planted secret fails the
build (W4-T3). Generation AND artifact download are RBAC'd per report kind and
individually audited; artifacts are retained 7 years (PROPOSED) and purged by a
scheduled job. Report metadata carries regime tags with SOC 2 CC-series as the
PROPOSED default. LLM output never enters an artifact.**

### 1. Report engine — dedicated PG model, deterministic renders

A new `engines/reports/` module (mirroring the `engines/config_mgmt/` layout)
assembles each report as a typed, secret-free **payload** (Pydantic,
`frozen=True`, `extra="forbid"`), then renders it. Two new tables (one
expand-only Alembic revision):

| Table | Columns (summary) |
|---|---|
| `report_runs` | `id`, `kind` (StrEnum: `change`, `compliance_posture`, `access_review`, `audit_integrity`), `trigger` (`scheduled` \| `on_demand`), `requested_by` (user id; `NULL` for beat), `period_start`/`period_end` (UTC), `status` (`queued`/`running`/`succeeded`/`failed`), `error_class` (typed, never free-form secret-bearing text), `regime_tags` (JSONB, §8), timestamps |
| `report_artifacts` | `id`, `run_id` FK, `format` (`csv` \| `pdf`), `content` (`bytea`), `sha256`, `size_bytes`, `expires_at` |

- **Artifacts live in Postgres (`bytea`), not on disk or object storage.**
  Evidence artifacts are small (a weekly CSV/PDF is KB–low-MB; 7 years of the
  four defaults is ~1.5k artifacts) and must survive DR — riding the PG backup
  path (ADR-0030) covers them with zero new infrastructure. The pcap
  disk-volume pattern (D14) is for large binary streams; the MinIO object-store
  option stays a named P5/GA escalation if artifact volume ever demands it.
- **Deliberately NOT the `documents` table.** `documents` rows are embedded
  into the pgvector RAG index and surfaced by agent retrieval to any user;
  reports are RBAC-scoped evidence (access-review is admin-only). Reports are
  **never embedded** — a separate model makes the exclusion structural rather
  than a filter someone can forget.
- **Deterministic, LLM-free renders.** Payload → Jinja2 template → renderer.
  Given the same payload, template, and renderer version, the artifact content
  is reproducible (the generation timestamp is injected as payload data, not
  read from the clock at render time; PDF metadata dates are pinned from the
  same field). Auditor evidence must be reproducible and immune to prompt
  injection — LLM prose has no path into an artifact. W4-T3's golden fixtures
  assert on extracted structure (rows, headings, table content), not raw PDF
  bytes.
- **Documentation Agent alignment (§7 "generated by the Documentation
  Agent").** The Documentation Agent gains typed read/trigger tools: list runs,
  fetch artifact metadata, and request an on-demand generation (which enqueues
  the same engine task under the invoking user's RBAC, §3). The agent
  *triggers and cites* reports; it never authors artifact content — the
  explainability contract (reasoning trace links the report it cited) is
  preserved without letting agent output become evidence.

### 2. Scheduling — Celery beat on the `docs` queue, plus on-demand

- A new task module `app.workers.tasks.reports` (task prefix `reports.*`)
  routed to the existing **`docs` queue** (D8: report generation is the
  document-generation workload class; no new queue, no new worker Deployment).
- **Beat entries** (in `create_celery_app()`, mirroring
  `config-nightly-backup`): default cadences **PROPOSED** — change report
  **weekly**, compliance posture **weekly**, access review **monthly**
  (§7: "monthly, for periodic access reviews"), audit-integrity **monthly**;
  cadence per kind configurable via settings (`.env.example` ↔ `config.py`
  1:1 rule). Beat loss is tolerable per the standing posture (PRODUCTION.md
  §3.2): schedules re-fire on the next beat; generation is idempotent per
  `(kind, period)`.
- **On-demand** via `POST /api/v1/reports` (kind + period), which enqueues the
  same task with `trigger=on_demand` and the requesting user recorded. A
  **claim-row guard** (the `_claim_backup_run` precedent,
  `backend/app/workers/tasks/config.py`) prevents a beat run and an on-demand
  run for the same `(kind, period)` from double-generating.
- **A daily compliance evaluation sweep** (`reports.compliance_sweep`, also
  beat-scheduled) feeds §7.2's trend history — named here because without it
  there is no time series to trend (the engine only ever ran on demand).

### 3. RBAC — on generation AND artifact access; audited; no ChangeRequest

- **Per-kind role floors (PROPOSED, refinable by the Consultant role-floor
  item):** change report and compliance posture — **engineer+** (matches the
  existing compliance endpoint floor); access review and audit-integrity —
  **admin** (user/PII surface; integrity-root attestation). The floor is
  enforced at **both** the generation trigger and the artifact download
  endpoint — an artifact is never world-readable once generated, and a role
  change between generation and download is honored at download time.
- **Every generation and every artifact download is an audit entry** (actor,
  report kind, run id, artifact sha256) — evidence about evidence; the access
  pattern of the access-review report is itself reviewable.
- **No ChangeRequest.** Report generation mutates only the platform's own
  report tables and never touches a device or network state; it is an audited
  read/derive action under RBAC — the same classification ADR-0052 gives
  manual tagging ("tags never touch a device"). CR-gating every weekly beat
  run would need a standing approver for a read-only roll-up; rejected (alt 6).

### 4. Retention — 7-year default (PROPOSED), scheduled purge

- `expires_at` defaults to **7 years** from generation — the audit-retention
  default `PRODUCTION.md` §12 carries as PROPOSED (data-retention Consultant
  item); per-kind override via settings. Storage stays trivial at default
  cadences (§1).
- A daily `reports.purge_expired` beat task hard-deletes expired artifacts and
  audits each sweep — the exact pattern of the pcap and raw-artifact purges
  (ADR-0023 §4). Runs referenced by an open legal/audit hold are out of scope
  for P4 (named future enrichment, not silently missing).

### 5. Renderer choice — CSV stdlib (hardened), PDF = WeasyPrint, air-gap enforced

**CSV:** stdlib `csv` — zero dependencies. The writer **neutralizes
spreadsheet formula injection**: any cell beginning with `=`, `+`, `-`, `@`,
tab, or CR is prefixed with `'` (OWASP CSV-injection guidance). Evidence files
are opened in Excel by auditors; an attacker-controlled device hostname or CR
title must not become an executing formula.

**PDF: WeasyPrint** (HTML/CSS → PDF). Candidates evaluated:

| Candidate | License | Python deps | System deps on `python:3.12-slim` | Air-gap | Verdict |
|---|---|---|---|---|---|
| **WeasyPrint** | BSD-3-Clause | pydyf, tinycss2, cssselect2, fontTools, Pillow (all permissive) | libpango + libharfbuzz + fontconfig + bundled fonts (`fonts-dejavu-core`) — ≈35 MB apt layer (measured at W3-T1) | Offline by construction **if** remote URLs are blocked (below) | **CHOSEN** |
| reportlab | BSD-3-Clause | pure Python (+ optional C accel) | none beyond fonts | offline | Rejected: programmatic canvas/flowable layout — four report layouts as Python code, no shared HTML/Jinja2 templating with the M4 docs path; maintainability cost dominates its smaller footprint |
| fpdf2 | LGPL-3.0 | pure Python | none | offline | Rejected: HTML subset too limited for evidence-grade tables/trends; LGPL acceptable but weaker than BSD for embedding posture |
| borb | AGPL-3.0 / commercial | — | — | — | Rejected on license (AGPL is incompatible with the self-hosted enterprise distribution posture) |
| wkhtmltopdf | LGPL-3.0 | subprocess | Qt WebKit (~150 MB) | offline | Rejected: upstream archived/unmaintained (2023) — a frozen WebKit is a CVE liability under the Trivy zero-fixable gate |
| Headless Chromium print-to-PDF (e.g. Playwright) | BSD (Chromium) | Playwright | ~300+ MB browser | offline only with care | Rejected: image bloat and attack surface grossly disproportionate to rendering tables |

- **Air-gap enforcement is code, not convention:** the WeasyPrint invocation
  passes a **custom `url_fetcher` that hard-fails every URL** except in-repo
  template-directory `file:` paths and `data:` URIs. A template that
  references a CDN font/stylesheet/image is a **render-time error in CI**
  (the templates are rendered in tests), not a silent hang in an air-gapped
  deployment. The same fetcher is the SSRF guard: payload-derived strings
  cannot make the renderer fetch an internal URL.
- **Fonts are bundled** in the image (`fonts-dejavu-core`; license: Bitstream
  Vera/public-domain derivative) — no fontconfig network fallback exists, so
  rendering is byte-stable across hosts.
- WeasyPrint + transitive pins land via the **uv lockfile** (P3-W0-T8) under
  the existing drift gate; the apt layer lands in `backend.Dockerfile` under
  the Trivy gate. Pango/HarfBuzz are LGPL/MIT **system** libraries dynamically
  linked by a BSD Python package — no license contamination of the platform.

### 6. Redaction contract — layered, fail-closed, one choke point (the strong bar)

**Invariant: no plaintext credential or secret appears in any generated
artifact.** Enforcement is structural — three layers, none of which is
per-report goodwill:

1. **Source allowlist (structural, layer 1).** The report data-access layer
   may read **only** an allowlisted set of secret-free sources (CR metadata,
   approvals, audit columns — already secret-free per ADR-0032 §5 — users/
   roles/mappings, the §7.2/§7.4 history tables, snapshot *metadata*). The
   deny-set — `device_credentials` (vault ciphertext AND plaintext paths),
   `config_snapshots.content`, `raw_artifacts` content, any KMS/KEK surface —
   is not reachable from `engines/reports/` (import-linter boundary + a test
   asserting the module's session issues no SELECT against deny-set
   tables/columns). What is never queried can never leak.
2. **Render-time deny-class filter (layer 2, the choke point).** Every payload
   passes `engines/reports/redaction.py::enforce_redaction(payload)` in the
   **single** render path before any renderer sees it — there is exactly one
   code path from payload to artifact, and the filter is in it. It rejects on:
   - **field-name deny-class** (case-insensitive): `password`, `passphrase`,
     `secret`, `token`, `api_key`, `private_key`, `credential`,
     `authorization`, `cookie`, `community` (SNMP) — the pinned list lives in
     that one module;
   - **format-anchored value patterns**: PEM blocks
     (`-----BEGIN … PRIVATE KEY`), JWTs (`eyJ` three-segment), AWS key ids
     (`AKIA`/`ASIA`), known vendor token prefixes. **Deliberately NOT bare
     high-entropy detection**: evidence artifacts legitimately carry SHA-256
     hex digests (artifact hashes, ADR-0038 `entry_hash` presentation) — an
     entropy detector would false-positive on the audit-integrity report
     itself and be tuned into uselessness (the ADR-0038 §"Negative" lesson).
3. **Secret-free persistence by construction (layer 3).** The history tables
   the reports read were designed to never hold secret material: §7.2 persists
   status/severity only (no finding evidence excerpt — excerpts can quote
   config text); §7.1 carries diff *statistics* and snapshot references, never
   config text (ADR-0021 posture).

- **Fail CLOSED.** A redaction hit **aborts generation**: `report_runs.status
  = failed` with a typed `error_class` (e.g. `redaction_violation`), a
  `netops_report_failures_total` increment, and an audit entry. No partial
  artifact is written. The failure record names the **field path only — never
  the value** (a redaction failure must not itself leak the secret into logs,
  metrics, or the API).
- **W4-T3 planted-secret negative control (must RUN and BITE).** The eval
  plants a deny-class field and a PEM-formatted value in a report fixture
  payload and asserts generation fails closed; the bite proof disables the
  filter and asserts the eval goes red. Green-at-setup is not accepted
  (P1-W4 lesson, P4-PLAN §0a). Golden-artifact fixtures additionally assert
  no deny-pattern match in any emitted CSV/PDF text (extraction-based).
- All report queries and the redaction filter get `tests/pg/` coverage under
  the blocking `pg-integration` job (P4-PLAN §0a: report queries are
  aggregation/trend-heavy — SQLite must not hide PG semantics).

### 7. The four reports

#### 7.1 Change report (W3-T2) — engineer+

CR lifecycle roll-up for the period: per CR — requester, approver(s), executor
(human or agent), state transitions with timestamps, **before/after as config
snapshot references + redaction-safe diff statistics** (line counts, the
ADR-0021 `applied_diff` posture — never config text), and **reasoning-trace
links** (URLs into the platform, resolvable under the viewer's own RBAC).
Sources: `change_requests`, `approvals`, `audit_log`, `reasoning_traces`
(link ids only). Evidence claim: every state change traversed the CR lifecycle
with four-eyes approval (G-SEC).

#### 7.2 Compliance posture report (W3-T3) — engineer+; names the trend persistence

Roll-up of the M4 compliance engine across all vendors: pass/fail by
**policy**, **device**, and **severity**, plus **trend over time**. The trend
requires history that does not exist today — this ADR names it:

| Table | Columns (summary) |
|---|---|
| `compliance_runs` | `id`, `executed_at`, `trigger` (`sweep` \| `on_demand`), policy pack id + version, device scope, engine version |
| `compliance_run_findings` | `run_id` FK, `device_id`, `policy_id`, `rule_id`, `status` (`pass`/`violation`/`skipped`, ADR-0018 §5), `severity` |

**Deliberately no evidence-excerpt column** (§6 layer 3): excerpts can quote
config text; the persisted history is secret-free by construction. Drill-down
to a live excerpt stays where it is today — the on-demand engineer+ endpoint.
The daily `reports.compliance_sweep` (§2) populates the history; the report
trends over `compliance_runs`. Expand-only migration, same revision as §1.

#### 7.3 Access review report (W3-T4) — admin

Users (local + OIDC), role assignments, IdP group→role mappings (ADR-0028),
last login per user, dormant accounts, and **break-glass usage** (every local
break-glass login in the period, from its audit entries — ADR-0028 makes
break-glass alerted + audited). Evidence claim: periodic access review
(SOC 2 CC6-series). Highest-sensitivity report — admin floor on generation
and download; its own downloads are audited (§3).

#### 7.4 Audit-integrity report (W3-T5) — admin; names the verification history

Surfaces the ADR-0038 spine: per-day hash-chain verification outcomes for the
period + the **append-only grant attestation**. Two sources:

- **`audit_chain_verification_runs`** (named here; written by the ADR-0038
  daily CronJob as a small additive change): `started_at`/`finished_at`,
  verified range (from/to entry id), `outcome` (`clean` \| `break`),
  checkpoint before/after. Today the CronJob emits only a metric + exit code —
  metrics retention cannot back a 7-year evidence trail; this table can.
  A **missing day is surfaced as a gap** in the report (a verification that
  never ran is a finding, not a blank).
- **Grant attestation at generation time:** the generator queries the PG
  catalog and attests no `UPDATE`/`DELETE` grant exists on `audit_log`
  (the G-SEC "append-only attested (grant check)" criterion), recording the
  attestation result + timestamp in the report.

Evidence claim: the integrity root is tamper-evident and verified daily
(G-SEC).

### 8. Regime mapping — SOC 2 CC-series PROPOSED default; tags are metadata

- Report metadata (`report_runs.regime_tags`) carries regime control tags,
  e.g. `soc2:CC8.1` (change management), `soc2:CC7.1`/`CC4.1` (posture
  monitoring), `soc2:CC6.1–CC6.3` (access review), `soc2:CC7.2` (audit
  integrity). The authoritative report↔control mapping is the **W3-T6 mapping
  doc**; the tags snapshot the mapping version in force at generation.
- **SOC 2 CC-series is the PROPOSED default regime** (`PRODUCTION.md` §7/§12)
  until the Consultant's compliance-regimes item is answered. Tags are
  **metadata only** — report *content* is regime-neutral evidence, so an
  ISO 27001/NIST answer re-tags and re-maps (W3-T6 doc revision); it does not
  redesign reports or invalidate existing artifacts.

### 9. Metrics — wired to the existing alert spine (ADR-0046 conformant)

New `netops_*` series (ADR-0015 namespace; label `report_kind`, bounded
cardinality — four kinds):

- `netops_report_generation_seconds` (histogram) — duration per kind;
- `netops_report_failures_total` (counter; labels `report_kind`,
  `error_class`) — `redaction_violation` is a distinguished class so a
  redaction trip pages, not just fails;
- `netops_report_last_success_timestamp` (gauge per kind) — staleness source.

Alerts join the existing rules files under the ADR-0046 contract: a
**staleness alert** per scheduled kind (last success older than cadence +
grace — the scheduled-backup-completeness pattern) and a **failure burn**
alert; each carries a resolving `runbook_url` and ships a *should-fire*
`promtool test rules` case proven to bite before joining `all-gates`
(ADR-0046 §6). Single-threshold trips are not acceptable where a burn-rate
form applies.

### 10. Scope boundary

**In:** the report model + engine module shape (§1), scheduling (§2), RBAC +
audit posture (§3), retention default (§4), renderer choice + air-gap
enforcement (§5), the redaction contract + its eval obligation (§6), the four
report contracts incl. the two named history tables (§7), regime-tag default
(§8), metrics/alerts (§9). **Out:** implementation (W3-T1…T6) and the eval
corpus (W4-T3); the regime mapping *content* (W3-T6 doc); SIEM delivery of
reports (ADR-0045 exports audit events, not report artifacts); report e-mail/
webhook distribution (named future enrichment — artifacts are pulled via the
RBAC'd API in P4); legal-hold retention exceptions (§4); the Consultant §12
answers (regimes, retention, role floors) — defaults here are PROPOSED and
rebased, not re-decided, when answered. This ADR does not modify ADR-0038's
chain construction, ADR-0018's policy format, or any CR-lifecycle semantics.

## Consequences

**Positive**
- The four §7 reports become scheduled, RBAC'd, retained evidence with a
  deterministic render path — auditor-consumable without regime lock-in
  (tags re-map, content stands).
- The redaction contract is structural (source allowlist + one choke-point
  filter + secret-free history), fail-closed, and bite-proven — not per-report
  goodwill; the artifact export surface, the one output that escapes runtime
  controls, is covered by G-SEC-grade tests.
- Trend and integrity history (`compliance_runs`/`compliance_run_findings`,
  `audit_chain_verification_runs`) convert two metric-only signals into
  7-year-capable evidence trails, closing the §7 trend gap and the
  "verification ran but left no record" gap — with missing days surfaced.
- WeasyPrint keeps the four layouts as HTML/Jinja2 templates (shared skills
  with the M4 docs path), BSD-licensed, offline-by-construction with the
  deny-all fetcher doubling as an SSRF guard; CSV hardening closes the
  formula-injection hole in the most-opened export format.
- Zero new infrastructure: existing beat, existing `docs` queue, artifacts in
  PG under the existing backup/DR path, alerts on the existing ADR-0046 spine.

**Negative**
- ~35 MB of Pango/HarfBuzz/fontconfig/fonts joins the shared backend image and
  its Trivy surface (accepted; measured and re-checked at W3-T1 — the
  packet-analysis stage precedent shows a split image is available if the CVE
  load ever demands it).
- PDF output is structure-stable, not byte-golden — W4-T3 asserts on extracted
  structure, a weaker (but honest) fixture form than byte equality.
- The deny-class field list and value patterns need curation as new sources
  join reports; a miss in layer 2 is only caught if layer 1/3 also missed —
  mitigated by the planted-secret eval, the one-module pinned list, and the
  source allowlist doing the heavy lifting.
- Fail-closed redaction means a false positive (a legitimate field matching a
  deny pattern) blocks a scheduled report until renamed/allowlisted —
  accepted: a missing weekly report pages someone; a leaked credential in an
  auditor's inbox is unrecoverable.
- 7-year `bytea` retention in PG grows the primary database rather than cheap
  object storage — trivial at default cadences, and the MinIO escalation is
  named (§1) if cadence/size assumptions break.
- The daily compliance sweep adds scheduled engine load proportional to
  devices × rules — bounded by the existing nightly-backup fan-out pattern and
  the `docs`-queue isolation (D8 per-queue KEDA scaling).

## Alternatives considered

1. **reportlab instead of WeasyPrint.** Rejected (§5): smallest footprint, but
   layout is imperative Python per report — four evidence layouts with no
   shared templating, diverging from the M4 docs path. The ~35 MB apt layer is
   a fair price for HTML/CSS templates reviewers can read.
2. **fpdf2 / borb / wkhtmltopdf / headless Chromium.** Rejected (§5 table):
   HTML subset too weak (fpdf2), AGPL (borb), unmaintained WebKit under a
   CVE gate (wkhtmltopdf), 300 MB browser to print tables (Chromium).
3. **Store artifacts in the `documents` table (reuse the M4 docs path
   end-to-end).** Rejected (§1): `documents` content is RAG-embedded and
   agent-retrievable — admin-only access-review content would leak through
   retrieval to any user. Separation is the structural fix; a "skip embedding"
   flag on `documents` was considered and rejected as exactly the forgettable
   per-row goodwill this ADR bans elsewhere.
4. **Let the Documentation Agent (LLM) write the report prose.** Rejected
   (§1): evidence must be deterministic/reproducible, and an LLM path would
   let prompt injection reach artifacts that leave the platform. The agent
   triggers and cites; the engine renders.
5. **Bare high-entropy secret detection in the redaction filter.** Rejected
   (§6): the audit-integrity report legitimately carries SHA-256 hex digests;
   entropy scanning would false-positive on the platform's own integrity
   evidence and get tuned into silence — the exact failure mode ADR-0038
   warns about. Format-anchored patterns + name deny-class + source allowlist
   instead.
6. **CR-gate report generation (treat it as a state-changing action).**
   Rejected (§3): generation touches no device/network state; CR-gating every
   beat run needs a standing approver for a read-only roll-up and would push
   operators toward rubber-stamping — degrading the four-eyes signal the CR
   gate exists to protect. RBAC + full audit, the ADR-0052 tagging precedent.
7. **Persist compliance finding evidence excerpts for richer drill-down.**
   Rejected (§7.2): excerpts can quote config text (secret-bearing,
   ADR-0017); a secret-free history table is redaction layer 3. Live
   drill-down stays on the existing on-demand engineer+ endpoint.
8. **Per-report redaction (each report task sanitizes its own output).**
   Rejected (§6): that is the "per-report goodwill" anti-pattern the task
   brief names — report #5 forgets. One choke point in the single render
   path, plus a structural source allowlist beneath it.
9. **Object storage (MinIO) for artifacts now.** Rejected (§1): new
   stateful infrastructure + a second backup/DR surface for KB-scale
   artifacts already covered by PG backups. Named escalation, not a P4 need.
10. **A DB-backed schedules table with a UI scheduler.** Rejected (§2):
    four kinds × fixed cadences is settings-grade configuration; a schedules
    CRUD surface adds authz/audit surface with no P4 requirement behind it.
    Beat entries + settings, like every existing scheduled job.
