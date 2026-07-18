# SOC 2 CC-Series Evidence Mapping — Compliance/Audit Reporting Suite

**Status:** PROPOSED — the Consultant's "compliance regimes" open item
(`docs/consultant/QUESTIONS.md` Q7) is not yet answered by the platform owner;
this doc is the working default, not a decision.
**Mapping version:** 1
**Binding ADR:** ADR-0053 §8 (`docs/adr/0053-compliance-audit-reporting.md`)
**PRODUCTION.md:** §7 (regime mapping), §12 (compliance-regimes open item)
**Owner task:** P4 W3-T6

## Purpose

The four report kinds shipped in W3-T2..T5 (change, compliance posture, access
review, audit integrity) are secret-free, RBAC-scoped evidence artifacts. Their
*content* is deliberately regime-neutral — it was designed from PRODUCTION.md
§7's plain-language description of what each report must contain, not from any
specific control catalog. This document is the **authoritative layer that
points from that content to SOC 2 CC-series controls**: which controls each
report kind evidences, exactly which artifact fields satisfy each one, and —
just as importantly — which parts of each control are **not** evidenced (named
limits, stated honestly rather than implied covered).

`report_runs.regime_tags` (P4 W3-T1 schema) carries machine-readable pointers
into this doc (e.g. `soc2:CC8.1`) plus a `mapping-version:<N>` tag snapshotting
which revision of this doc was authoritative when the run was generated
(`backend/app/engines/reports/regime_mapping.py`). Tags are **metadata only**:
changing this doc, or the regime it targets, never changes report content and
never invalidates a previously generated artifact — see "Rebasing to a
different regime" below.

**Language discipline:** this doc states what a field *evidences toward* a
control's intent, in the author's own paraphrase of the AICPA Trust Services
Criteria (Common Criteria series). It is not legal or audit advice, it does
not constitute a SOC 2 attestation, and nothing here is a claim that the
platform **is compliant** or **certified**. The only accurate phrase is
**"SOC 2 Type II-aligned"** (Consultant Q7 recommended default) — never
"compliant" or "certified."

## 1. Change report (`kind=change`) → `soc2:CC8.1`

**Control CC8.1 — Change management.** The entity authorizes, designs,
develops/acquires, configures, documents, tests, approves, and implements
changes to infrastructure, data, and software to meet its objectives.

**Evidencing fields** (full field list: `docs/runbooks/report-engine.md`
"Report contents — change report"):

| Control aspect | Artifact field(s) |
|---|---|
| Change is authorized before execution | Section 2 *Approvals* — approver identity (incl. IdP subject for federated accounts), decision, timestamp (the four-eyes gate) |
| Change is documented end to end | Section 3 *Lifecycle transitions* — every `change_request.*` audit event (creation, waivers, each state edge) with actor + UTC timestamp |
| Change is attributable | Section 1 *Change requests* — requester, executor (human or agent, from the approval-to-executing actor), created timestamp, reasoning-trace link |
| Change is verified and its prior state is retrievable | Section 4 *Diff statistics and snapshot references* — outcome token, verified flag, applied-diff line count, baseline snapshot `sha256:<hash>` reference (never raw config text, ADR-0021 posture) |

**Named limits:**

- Evidences **CR-gated** changes only. A change applied outside the
  ChangeRequest workflow (e.g. a manual out-of-band device edit) creates no CR
  row and is invisible to this report; drift *detection* is a separate control
  surface (the compliance-posture report and the config-drift engine), not
  this one.
- **F5 BIG-IP and VMware config drift is out of scope in P4** (ADR-0050 §7.6 /
  ADR-0051 §3): a CR against those vendors is still evidenced here (the CR
  lifecycle itself is vendor-agnostic), but there is no independent
  post-change drift check confirming the device matches the approved diff for
  either vendor.

## 2. Compliance posture report (`kind=compliance_posture`) → `soc2:CC7.1` + `soc2:CC4.1`

**Control CC7.1 — Detection.** The entity uses detection and monitoring
procedures to identify changes to configurations that could introduce new
vulnerabilities, and to identify susceptibility to newly discovered
vulnerabilities.
**Control CC4.1 — Monitoring activities.** The entity selects, develops, and
performs ongoing and/or separate evaluations to ascertain whether the
components of internal control are present and functioning.

**Evidencing fields** (full field list: `docs/runbooks/report-engine.md`
"Report contents — compliance posture report"):

| Control aspect | Artifact field(s) |
|---|---|
| An evaluation actually ran, with provenance (CC4.1) | Section 1 *Compliance evaluation runs* — trigger (`sweep`/`on_demand`), policy-pack id + version, engine version stamped per run |
| Configuration-vulnerability posture at every grain (CC7.1) | Sections 2–4 *Latest posture by policy / by device / by severity* |
| Monitoring is ongoing, not a one-off (CC4.1) | Section 5 *Daily posture trend* — one row per UTC day; a day with no recorded sweep renders the explicit `gap` marker, never an interpolated value |
| Coverage gaps are surfaced, not implied covered | Section 6 *Out-of-scope vendors* |

**Named limits:**

- **F5 BIG-IP and VMware vSphere have no text-config compliance surface in
  P4** (ADR-0050 §7.6 / ADR-0051 §3): CC7.1 is evidenced for the covered
  vendor set only. Devices on the two named vendors are reported
  out-of-scope — out-of-scope is explicitly **not** the same as passing.
- The engine evaluates the **default policy pack** only
  (`app.engines.config_mgmt.compliance.loader.load_default_pack`); a control
  that depends on a customer-authored policy is not evidenced until that
  pack exists and is wired into the daily sweep.
- A `gap` day is itself a CC4.1 finding (the daily sweep did not run), not
  silence — see the report's own "Out-of-scope vendors" / gap-day guidance
  and the `NetopsReportWeeklyStale` / `NetopsReportMonthlyStale` runbook
  entries for the operational response.

## 3. Access review report (`kind=access_review`) → `soc2:CC6.1`–`CC6.3`

**Control CC6.1 — Logical access.** The entity implements logical access
security software, infrastructure, and architectures over protected
information assets.
**Control CC6.2 — Registration and authorization.** Prior to issuing system
credentials, the entity registers and authorizes new internal and external
users.
**Control CC6.3 — Role-based access and removal.** The entity uses
role-based access control and removes access when it is no longer required.

**Evidencing fields** (full field list: `docs/runbooks/report-engine.md`
"Report contents — access review report"):

| Control aspect | Artifact field(s) |
|---|---|
| Who has access, and of what strength (CC6.1) | Section 1 *User accounts and role assignments* — provider, enabled/disabled, last login, honest dormancy classification (`active`/`dormant`/`never-logged-in (dormant)`/`never-logged-in (new account)`) |
| Access is role-structured, and removal candidates surface (CC6.3) | Section 2 *Role assignment summary* — accounts per role in rank order; Section 1's dormancy classification is the removal-candidate signal, surfaced never silently excluded |
| Federated registration path is governed (CC6.2) | Section 3 *OIDC federation posture* — groups claim, admin-via-OIDC opt-in, break-glass local-login fence state, dormancy window in force |
| The authorization rule set itself, not just its outcome (CC6.2/CC6.3) | Section 4 *IdP group-to-role assignments* — configured mapping plus the **effective** role at login (admin cap and deny-default surfaced; a misconfigured role name renders visibly, never silently dropped) |
| The access-control exception path is itself monitored (CC6.1) | Section 5 *Break-glass local logins in period* — every `auth.local.breakglass_login` audit entry in the period |

**Named limits:**

- The report is a **point-in-time roster** plus a login-derived activity
  signal; the platform keeps no historical role-assignment table, so "who
  held role X on day N" for any day inside the period other than the period
  end is not reconstructable from this artifact alone (the per-mutation
  audit log is the underlying source of truth and is cross-referenceable,
  but not pre-joined into this report).
- CC6.2's "prior to issuing credentials" aspect is evidenced by the
  **current** registration state and the mapping **rules**, not by a
  per-user historical record of the original registration decision (account
  creation is itself audited under `user.created`, a separate audit-log
  query, not a report-engine field).

## 4. Audit-integrity report (`kind=audit_integrity`) → `soc2:CC7.2`

**Control CC7.2 — Monitoring for security events.** The entity monitors
system components and the operation of those components for anomalies that
are indicative of malicious acts, natural disasters, or errors, to identify
security events.

**Evidencing fields** (full field list: `docs/runbooks/report-engine.md`
"Report contents — audit-integrity report"):

| Control aspect | Artifact field(s) |
|---|---|
| The tamper-evidence mechanism ran, digest-anchored | Section 1 *Chain verification runs* — outcome (`clean`/`break`), entries verified, walked range, checkpoint SHA-256 digests before/after, that run's append-only grant check |
| Monitoring is continuous, not a one-off | Section 2 *Daily verification outcomes* — a day with no persisted run renders the explicit `gap` marker **and** raises a `verification-gap` finding |
| An actual anomaly is a named row, never buried | Section 3 *Integrity findings* — explicit rows per `verification-gap` day, `chain-break` day, and `append-only-grant` day |
| The append-only control is enforced *right now*, not just historically | Section 4 *Append-only grant attestation* — a **live**, generation-time `pg_catalog` query (parent + every partition), never cached |

**Named limits:**

- CC7.2 also covers **incident-response process** evidence (who responded,
  how, and how fast); this report evidences **detection only** — the
  response workflow that follows a `chain-break` or `append-only-grant`
  finding (e.g. an incident ticket) is not itself tracked by the report
  engine.
- A `REVOKE` cannot bind the table owner or a superuser (migration 0001):
  the grant attestation is a backstop against non-privileged
  misconfiguration, and the hash chain is the tamper-evidence backstop
  against privileged actors. CC7.2 is evidenced for the **structural
  detection layer** — it is not a claim that a privileged insider is
  incapable of acting.

## Cross-cutting limits (all four reports)

- **Metadata only.** `regime_tags` are labels attached to a run; they never
  change report *content*. A `soc2:CC*` tag is a pointer into this doc, not a
  certification claim.
- **PROPOSED, not decided.** SOC 2 CC-series is the Consultant Q7 recommended
  default (`docs/consultant/QUESTIONS.md` Q7; re-confirmed
  `docs/roadmap/PRODUCTION.md` §12, 2026-07-05). It is the working structure
  the reports are organized around until the platform owner answers Q7 — it
  has not been formally adopted as *the* regime.
- **No certification claim, ever.** Nothing in this doc, and no artifact this
  suite generates, constitutes a SOC 2 attestation. The only accurate
  language is "SOC 2 Type II-*aligned*."

## Rebasing to a different regime (ISO 27001 / NIST answer path)

If the Consultant's Q7 item is later answered with ISO 27001, NIST 800-53,
PCI-DSS, or another framework, the rebase is a **doc + default-tag revision**,
never a report redesign or a migration:

1. This doc gets a new revision that re-tags each report kind against the new
   framework's control identifiers (e.g. an ISO 27001 Annex A control in place
   of `CC8.1` for change management), reusing the **same four
   artifact-to-field mappings** above — the fields evidencing a control do not
   change, only the label pointing at them does.
2. **Mapping version** above is bumped, and
   `backend/app/engines/reports/regime_mapping.py` (`MAPPING_VERSION`,
   `MAPPING_DOC_SHA256`) is updated to match in the same change (see "Drift
   guard" below).
3. `REGIME_TAG_DEFAULTS` in `backend/app/engines/reports/builders.py` is
   updated to the new tag set for future runs.
4. **Existing `report_runs.regime_tags` rows are never rewritten.** A run's
   tags snapshot the mapping in force *at generation time* (ADR-0053 §8);
   historical evidence stays labeled under the mapping that was authoritative
   when it was produced. The rebase is prospective only, and no artifact is
   invalidated.

## Mapping-version drift guard

The mapping version and a pinned content hash of this document live together
in `backend/app/engines/reports/regime_mapping.py`
(`MAPPING_VERSION`, `MAPPING_DOC_SHA256`).
`backend/tests/engines/reports/test_regime_mapping.py` fails if this
document's content no longer hashes to the pinned value for the current
`MAPPING_VERSION` — i.e. any substantive edit to this document must be paired,
in the same change, with bumping **Mapping version** above, recomputing the
hash, and updating both constants. A doc-only revision without that pairing
cannot silently re-label already-generated evidence under a stale claim.
