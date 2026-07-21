# P4 Build Plan — Vendor Wave 3 (F5 BIG-IP + VMware) + Application-Dependency Topology + Compliance & Audit Reporting

**Project:** AI Network Operations Platform
**Status:** **COMPLETE — P4 EXIT 2026-07-21.** W0–W4 are merged (PRs #117–#119, #123, #166, and #167); W4's three biting eval suites and all P4-scoped gates passed at final PR HEAD `4707f09a260f34ee2126dc59ea8fa7ed7d18667e` in CI run `29840145528`, then PR #167 was squash-merged as `77d8dd63`. See `P4-RELEASE-READINESS.md`. Entry condition was satisfied by **P3-Platform COMPLETE** (`docs/roadmap/P3-RELEASE-READINESS.md` — all five §11 gates PASS; ADRs 0042–0047 Accepted, 0048 Rejected).
**Authority:** Bound by `CLAUDE.md`, `docs/architecture/DECISIONS-BRIEF.md` (D1–D16), and `docs/roadmap/PRODUCTION.md` §1 (phase table), §2.4 (Wave 3), §2.6 (per-wave exit criteria), §7 (compliance & audit reporting), §11 (gates).
**Scope source:** `PRODUCTION.md` Phase **P4** = Wave 3 vendors **F5 BIG-IP + VMware**; **application-dependency topology** (per MVP traceability); the **compliance & audit reporting suite** (§7). This is the recorded P4 inheritance from the P3 exit marker (PRODUCTION.md §1 "P4 inheritance" + `P3-RELEASE-READINESS.md` §4) — nothing else rides in.

---

## Current delivery status

| Wave | State | Evidence / next action |
|---|---|---|
| **W0 — design gate** | **Merged** | PR #117: ADRs 0050–0053, P4 marker, Consultant re-check, per-task specs |
| **W1 — F5 + VMware** | **Merged** | PR #118: both plugins and inventory surfacing; live-lab validation remains deferred as planned |
| **W2 — application dependencies** | **Merged** | PR #119 plus optimistic-concurrency follow-up PR #123: schema/projection, derivation, tagging, impact reads |
| **W3 — compliance/audit reporting** | **Merged** | PR #166, squash `7298f4b8` (2026-07-19): T1–T6, with 27 validated review findings remediated in four fix waves and 18/18 required checks green before merge. The [review report](../reviews/P4-W3-PR166-REVIEW.md) is historical evidence, not open status. |
| **W4 — evals + phase exit** | **Merged** | PR #167, squash `77d8dd63` (2026-07-21). Final PR HEAD `4707f09a`, run `29840145528`: all required jobs and `all-gates` green; T1/T2/T3 and the docs-only T4 closeout revalidated at one HEAD. |

W3 is complete at its merged head. W4 adds proof and performs the phase-exit
audit; it does not reopen the historical W3 review state.

---

## 0. Scope discipline — what "validate" means on this host

Same no-hardware posture as M4/M5/P1/P2/P3 (user-ratified each phase):

- **No live F5 BIG-IP or vCenter lab exists on the authoring host.** Plugin
  validation = the plugin **conformance suite over recorded fixtures** (raw
  vendor payloads stored verbatim; normalized models round-trip), exactly the
  discipline every prior wave used. The §2.6 "demonstrated live against a
  lab/sandbox instance" criterion is **named deferred-accepted → live lab**, the
  same deferral P3-RELEASE-READINESS §4 item 6 records for all prior waves, with
  the golden-path scripts shipped ready-to-run.
- **No LLM provider on the authoring host.** Agent-facing evals (routing, app-impact
  answers) run as the deterministic CI layer; real-LLM runs stay the documented
  opt-in manual gate (M3 pattern, unchanged).
- **Everything else in P4 is fully CI-enforceable** — graph derivation, projection,
  rebuild compatibility, report generation/formats/redaction, RBAC — and is
  therefore gated as a true PASS, biting, with negative controls (P1-W4 lesson).
- **Flow-telemetry enrichment (NetFlow/gNMI) stays OUT of scope** until the
  Consultant telemetry open item (brief §9) is answered — `PRODUCTION.md` §2.4
  records this; P4 does not smuggle it in.

---

## 0a. Lessons carried from P1/P2/P3 — applied here

| Lesson (source) | How P4 applies it |
|---|---|
| **A gate green-at-setup masks findings — confirm it RUNs and BITEs** (P1-W4) | Every new eval/check ships a negative control: a planted wrong `DEPENDS_ON` edge fails the derivation eval; a planted secret in a report fixture fails the redaction check; a monkeypatched missing `_INTERFACE_SPECS` entry fails the plugin-conformance completeness check. Verify evidence docs + run URLs before trusting promotion commits (2026-07 audit lesson). |
| **Escalate every secret-surface role to the strong model** (P1-W0) | P4 secret surfaces: **report engine on the audit spine** (W3-T1), **access-review report** (W3-T4, users/roles/OIDC/break-glass), **audit-integrity report** (W3-T5, hash-chain), **plugin credential flows** (W1-T1/T2, iControl/vCenter auth via the D11 vault). All escalate reviewers + fixer to the live strong model. Never inline `model:'fable'`. |
| **Parallel-built siblings share bug classes** (P2/P3 recurring) | F5 + VMware plugins and the four reports are template-siblings: when a review finds a class bug in one (fixture handling, pagination, redaction, empty-result), **sweep every sibling in the same fix commit**, don't wait for the bot to re-find each. |
| **SQLite hides PG semantics** (P2 recurring major) | Report queries are aggregation/window/trend-heavy and retention-scoped — **every report query + tagging model gets `tests/pg/` coverage** under the blocking `pg-integration` job, not SQLite-only. |
| **After a kill, trust git not the result object; salvage; focused-rerun; never `reset --hard`** (P1-W6, P3-W5) | Standing recovery protocol; atomic commit per task is the save unit. |
| **Arm a baseline-relative usage guard on long runs** | W2+W3 (the two big build waves) each arm `BASELINE = budget.spent()` at script top; stop near ceiling, commit, summarize. |
| **Lockfile exists — new deps go through it** (P3-W0-T8) | New deps (`pyvmomi`, the PDF renderer chosen in ADR-0053, any F5 client lib) land via the lockfile + CI drift assertion; no unpinned drift (bit twice in P1/P2). |
| **Neo4j is rebuilt from Postgres** (D5, P3 W4-T4 drill) | The application-dependency layer is **PG-backed and projected** — never Neo4j-only state. The existing Neo4j rebuild drill + `neo4j-rebuild-bite.sh` must stay green *with* the new node/edge kinds (explicit W2 exit criterion, so the P3 G-REL mechanism doesn't silently rot). |
| **Rebase before a new wave; PR-not-mid-run-edit; single combined sonnet reviewer for non-critical** (workflow README) | Standing mechanics; dual strong review only on the escalation set above. |

---

## 1. Scope

| Track | Deliverables | PRODUCTION.md ref |
|---|---|---|
| Vendor Wave 3 — F5 BIG-IP (`f5_bigip`) | iControl REST per D7: `DISCOVERY_API`, interfaces, routes (self-IPs), **virtual-server/pool/member inventory** (new normalized ADC models — the primary service-to-server mapping source), `HA_STATUS`, config backup (UCS) | §2.4 |
| Vendor Wave 3 — VMware (`vmware`) | pyVmomi per D7: `DISCOVERY_API`, virtual interfaces/port groups, **VM inventory, VM-to-host/cluster placement** (new normalized virtualization models — bridges physical L2 to workloads) | §2.4 |
| Application-dependency topology | `Application` nodes + `DEPENDS_ON` edges in Neo4j, **derived from four sources**: F5 VIP→pool→member chains, VMware VM placement, DNS dependencies (M5), manual application tagging in the UI; PG-backed + projected (D5); impact-analysis query surface + Troubleshooting-Agent tool; app-dependency UI view | §2.4, CLAUDE.md "Topology → Application dependencies" |
| Compliance & audit reporting suite | Report engine (scheduled weekly/monthly + on-demand, CSV/PDF export, RBAC'd): **change report** (CRs: requester/approver/executor/before-after/trace links), **compliance posture report** (M4 engine roll-up: pass/fail by policy/device/severity + trend), **access review report** (users/roles/OIDC mappings/last login/break-glass usage), **audit-integrity report** (daily hash-chain verification + append-only attestation); SOC 2 CC-series evidence mapping as the PROPOSED default regime | §7 |
| Evals + exit | Plugin conformance + cross-vendor/routing re-run (vendor matrix extended; nine-agent routing roster unchanged); app-dependency derivation eval corpus (precision/recall `1.0`/`1.0`); report conformance/redaction evals; continuously biting negative controls; `P4-RELEASE-READINESS.md`; ADRs 0050–0053 flipped on green | §2.6, §11 |

**Out of P4 (→ P5 / GA):** Wave 4 vendors (AWS incl. Route53, Azure) + hybrid-cloud
topology stitching + scale certification (P5); certified-scale G-SCA/G-REL numbers,
30-day calendar soak, external pentest, 6-month break-glass cadence (GA /
operational — carried unchanged from the P3 exit marker); flow-telemetry
enrichment (Consultant open item); Neo4j Enterprise HA (Consultant open item, D5
rebuild path stands).

---

## 2. Agent capability review

Roles + model tiers from `.claude/agents/README.md`. **P4 needs no new agents** —
this is a code-and-docs phase (plugins, graph pipeline, report engine, UI), the
exact shapes `wf-implementer`/`wf-implementer-light`/`wf-eval-designer` already
own. The P3 SRE roles (`wf-observability`, `wf-reliability`) are not needed;
`wf-infra` appears only if the report scheduler needs a Helm CronJob (expected:
Celery beat, no new infra).

| agentType | Model | P4 use |
|---|---|---|
| `wf-implementer` | strong (inherit) | Novel/security-critical: F5 + VMware plugins (new capability interfaces + normalized models + credential flows), derivation pipelines, report engine + the four reports, impact-analysis tool |
| `wf-implementer-light` | light | Template-following: inventory API/UI surfacing mirroring existing pages, tagging CRUD UI, golden-path scripts, docs pages |
| `wf-eval-designer` | strong | Conformance/eval corpora: cross-vendor re-run, derivation precision/recall, report format/redaction evals |
| `wf-release-auditor` | strong | Phase-exit G-* evidence + readiness doc; flips ADRs 0050–0053 + roadmap on green |
| `wf-spec-reviewer` / `wf-quality-reviewer` | sonnet* | Spec + quality review per task |
| `wf-fixer` / `wf-verifier` | sonnet* | Apply enumerated findings / confirm resolved |

\* **Escalation rule** (`.claude/agents/README.md`): every secret-surface task
escalates reviewers + fixer to the live strong model. P4 secret-surface set:
**W1-T1/T2** (device-credential flows for iControl/vCenter via the D11 vault),
**W3-T1** (report engine reads the audit spine + renders exports that leave the
platform), **W3-T4** (access-review report: users/roles/OIDC/break-glass),
**W3-T5** (audit-integrity report: hash-chain verification surface). All escalate.

---

## 3. Build waves (dependency-ordered)

Per-task pattern, unchanged from P1/P2/P3: **1 implementer → 2 reviewers (spec +
quality) → conditional fixer → verifier → 1 atomic commit.** Sequential tasks
share files; parallelize only within a task. Single combined sonnet reviewer
allowed for non-secret-surface tasks; dual strong review on the escalation set.
ADRs numbered from **0050** (current max 0049). Full per-task specs (one file per
task, with explicit exit criteria): `docs/roadmap/p4-tasks/README.md` — **authored
at W0 after this plan is reviewed**, mirroring the P3 pattern.

| Wave | Tasks | Owner(s) | Review tier | Notes |
|---|---|---|---|---|
| **W0 — ADRs / entry** | **T1** ADR-0050 F5 BIG-IP plugin (iControl REST client choice per D7, new ADC capability + `NormalizedVirtualServer`/`Pool`/`Member` models — PROPOSED names, UCS backup handling incl. secret content); **T2** ADR-0051 VMware plugin (pyVmomi, new virtualization capability + `NormalizedVM`/host/port-group models, read-only vCenter role); **T3** ADR-0052 application-dependency topology (PG schema + Neo4j projection of `Application`/`DEPENDS_ON`, the 4 derivation sources + precedence/conflict rules, tagging write-path authz — **RBAC + full audit, direct write (user decision 2026-07-05); matches the device-inventory precedent, tags never touch a device** — CR-gating considered and declined, rebuild-drill compatibility); **T4** ADR-0053 compliance & audit reporting suite (report engine + Celery-beat scheduling, CSV/PDF renderer choice — air-gap-friendly, RBAC + retention, redaction contract, SOC 2 CC-series default mapping); **T5** `PRODUCTION.md` "P4 in progress" marker + Consultant §12 re-check (compliance regimes, data retention, telemetry, app-tagging ownership) + per-task specs `docs/roadmap/p4-tasks/` | `wf-implementer` | sonnet (strong for 0053 + the credential sections of 0050/0051) | Design gate; unblocks all waves |
| **W1 — Vendor Wave 3 plugins** | **T1** F5 BIG-IP plugin: new ADC capability interface + normalized models + `f5_bigip` plugin (discovery, interfaces, self-IP routes, virtual-server/pool/member inventory, `HA_STATUS`, UCS backup via CR) + conformance fixtures (`wf-implementer`, **escalated** credential flow); **T2** VMware plugin: virtualization capability + normalized models + `vmware` plugin (pyVmomi; VM/host/cluster/port-group inventory, virtual interfaces) + conformance fixtures (`wf-implementer`, **escalated** credential flow); **T3** inventory surfacing: API endpoints + UI pages for virtual-server/pool and VM/host inventory, mirroring existing device-inventory pages (`wf-implementer-light`) | `wf-implementer` (+ light T3) | strong (T1/T2) / sonnet (T3) | T1 ∥ T2 (disjoint dirs), then T3. **Blocks W2 derivation.** New deps via lockfile |
| **W2 — Application-dependency topology** | **T1** PG schema + projector: `Application` + `DEPENDS_ON` in Postgres, Alembic migration (expand-only), Neo4j projection via `engines/topology/` (nodes/edges/projector), **auto-rebuild path includes the new kinds — `neo4j-rebuild-bite.sh` stays green** (`wf-implementer`); **T2** derivation pipelines: F5 VIP→pool→member→device/VM chains, VMware VM→host placement, M5 DNS-dependency linkage; deterministic, idempotent, per-source provenance on every edge (`wf-implementer`); **T3** manual application tagging: PG model + API + UI — direct write under RBAC (engineer+) with full audit per the ADR-0052 decision (`wf-implementer-light` UI + `wf-implementer` authz); **T4** impact analysis: "what depends on X" query surface (`knowledge/topology_read.py` extension) + Troubleshooting-Agent tool + app-dependency UI view with source-provenance display (`wf-implementer`) | `wf-implementer` (+ light) | sonnet (strong where authz) | Needs W1 (T2 consumes both plugins' models; T1/T3 can start on W0 ADR). T1→T2→T4; T3 ∥ T2. **Concurrent with W3** (disjoint files). Projection-lag SLO must hold |
| **W3 — Compliance & audit reporting suite** | **T1** report engine: PG report model + Celery-beat scheduler (weekly/monthly + on-demand), CSV + PDF renderers, retention, RBAC, **redaction contract — no plaintext credential/secret in any artifact** (`wf-implementer`, **escalated**); **T2** change report: CR lifecycle roll-up with requester/approver/executor/before-after/reasoning-trace links, generated via Documentation Agent path (`wf-implementer`); **T3** compliance posture report: M4 `config_mgmt/compliance` engine roll-up — pass/fail by policy/device/severity + **trend over time** (needs result-history persistence — part of this task) (`wf-implementer`); **T4** access review report: users, roles, OIDC group mappings, last login, break-glass usage (`wf-implementer`, **escalated**); **T5** audit-integrity report: daily hash-chain verification results + append-only grant attestation (surfaces the ADR-0038 spine) (`wf-implementer`, **escalated**); **T6** SOC 2 CC-series evidence mapping (PROPOSED default per §7): mapping doc + report-metadata regime tags (`wf-implementer-light`) | `wf-implementer` (+ light T6) | strong (T1/T4/T5) / sonnet | **Concurrent with W2** (disjoint files). T1 first; T2–T5 ∥ after T1; T6 last. All report queries under `tests/pg/` |
| **W4 — Evals + phase-exit gate** | **T0A** planning/handoff contract; **T0B** LF CSV-prefix fix; then **T1** plugin conformance + cross-vendor eval re-run: vendor matrix extended with `f5_bigip`/`vmware`, unchanged nine-agent routing roster + new vendor-surface cases (`wf-eval-designer`); **T2A** bounded derivation contract correction: route-domain-safe IP reconciliation + full virtual-server→pool→member VMware provenance (`wf-implementer`); **T2** eval-only app-dependency derivation corpus: contract-authored synthetic estate → expected graph, precision/recall `1.0`/`1.0`, impact correctness, assert-red-inside-green wrong-edge and recall-drop controls (`wf-eval-designer`); **T3** report conformance evals: golden CSV/PDF structures, evidence completeness, assert-red-inside-green redaction control (`wf-eval-designer`); **T4** G-* evidence doc `P4-RELEASE-READINESS.md`; flip ADRs 0050–0053 Accepted on green; `PRODUCTION.md` P4 exit marker + P5 inheritance recorded (`wf-release-auditor`) | `wf-eval-designer` + `wf-implementer` + `wf-release-auditor` | strong | T0A/T0B first as separate atomic commits; then T1 → T2A → T2 → T3; T2A never edits the ledger and T2 never edits production derivation; T1/T2/T3 record only task status, focused commands/results, bite test node IDs, and blocking-CI collection paths; the bounded dependency-audit remediation is a seventh pre-T4 commit; T4 owns the final lifecycle/status and records landed eval task commit SHAs, one final release HEAD, run/job URLs, and results. Eight planned commits plus one validated review-follow-up commit |

A W3-T7 stretch (promoting the three G-OBS flagged-deferred §6 reconciliation
rows to backed series + alerts) was considered at plan review and **declined
(user decision 2026-07-05)** — the rows carry to P5 unchanged, drift-guarded
(§6 open items).

---

## 4. Sequencing

- **W0 first** — the four ADRs are the design contract; naming/authz/renderer
  decisions (models, tagging write-path, PDF lib) are made once there, not
  mid-wave; per-task specs are cut from the reviewed ADRs.
- **W1 before W2-T2** — the derivation pipelines consume the normalized ADC +
  virtualization models; building derivation against unstable models is rework.
  W1-T1 ∥ W1-T2 (disjoint plugin dirs — sibling-class-bug sweep applies).
- **W2 and W3 run concurrently** — the topology track (`engines/topology/`,
  plugins, graph UI) and the reporting track (report engine, audit/CR/compliance
  readers, reports UI) touch disjoint files. W2-T1 and W2-T3 depend only on
  ADR-0052 and can start alongside W1.
- **W4 last** — evals need both plugins, the graph, and the reports in place.
  Execute T0A, T0B, T1, T2A, T2, T3, then T4; T2A is a correctness
  prerequisite and T2 remains eval-only. The release auditor flips
  ADRs/roadmap only on green.
- **Both W2 and W3 arm the baseline-relative usage guard** (each is 4–6 tasks).

---

## 5. Per-wave exit criteria

**W0 (design):** ADRs 0050–0053 written (Proposed), secret-surface sections
reviewed at the strong bar; `PRODUCTION.md` carries the "P4 in progress" marker;
Consultant §12 re-check recorded (compliance-regime + retention defaults
re-confirmed or converted); `docs/roadmap/p4-tasks/` specs exist with explicit
exit criteria per task. D16 green.

**W1 (plugins):** both plugins pass the conformance suite over recorded fixtures
(raw payloads stored verbatim; normalized models round-trip); write paths (UCS
backup restore, any config write) execute **only via ChangeRequest**; credential
flows use the D11 vault with zero plaintext leakage (escalated review);
new-plugin onboarding validated (§2.6 / §11 G-MNT item — first vendor wave since
the harness shipped); coverage ≥80% (D16); plugin + API docs published; live
golden-paths shipped ready-to-run and **named deferred-accepted → live lab**.
Cross-vendor eval not yet re-run (that is W4-T1) but existing suite shows no
regression. Lockfile updated for `pyvmomi` + friends, drift gate green.

**W2 (topology):** `Application`/`DEPENDS_ON` live in Postgres (expand-only
migration) and project to Neo4j; **all four derivation sources** produce edges
with per-source provenance; derivation is idempotent (re-run ⇒ no dupes, asserted
under real PG); **the Neo4j auto-rebuild path reproduces the application layer
from Postgres alone and `neo4j-rebuild-bite.sh` stays green**; projection-lag SLO
recording rule still holds with the new kinds; tagging is a direct write under RBAC (engineer+) with every change audited
(ADR-0052 decision — not CR-gated); impact-analysis answers cite provenance; the
Troubleshooting Agent exposes the impact tool (explainability: answers reference
graph evidence). UI view renders the app-dependency graph.

**W3 (reporting):** all four §7 reports generate on schedule (Celery beat) and
on demand, export CSV + PDF, and are RBAC'd; **redaction contract enforced — the
planted-secret negative control fails the build if a credential reaches any
artifact**; posture report shows trend over time from persisted engine-run
history; audit-integrity report surfaces daily hash-chain verification +
append-only attestation; access-review report covers users/roles/OIDC
mappings/last-login/break-glass; every report query has `tests/pg/` coverage
under the blocking `pg-integration` job; report generation emits metrics
(duration/failure) wired to the existing alert spine; SOC 2 CC-series mapping doc
published as the PROPOSED default. Audit retention default (7y PROPOSED) recorded.

**Phase exit (W4) — COMPLETE 2026-07-21:** the P4-scoped slice of the §11 gates
passed simultaneously at CI-evidenced final PR HEAD `4707f09a` in run
`29840145528` (the PR workflow evaluated the complete changed-file set) —
- **G-SEC — PASS (continuous):** P1–P3 controls inherited, no regression;
  credential-leak tests extended to report artifacts and plugin fixtures; plugin
  write paths CR-only; four-eyes remains a no-regression invariant for
  ChangeRequest-governed writes. Manual application tagging and report
  generation/access are direct RBAC-controlled, fully audited operations and
  are not four-eyes gated.
- **G-MNT — PASS:** D16 green (coverage ≥80% incl. both plugins); ADRs 0050–0053
  Accepted on green implementing evidence; docs + API docs per feature;
  new-plugin onboarding validated this wave; lockfile green.
- **G-OBS — PASS (P4 slice):** report-generation metrics and their biting alert
  suite are green. The application layer preserves the existing
  `slo:netops_topology_projection_lag:seconds` recording rule and its biting
  burn-rate alerts; P4 does not claim derivation-specific metrics or alerts.
- **G-SCA / G-REL — no new scope, no regression:** the P3 drill suite +
  `drill-bite-proofs` stay green with the application layer present (rebuild
  drill explicitly re-verified); certified-scale numbers remain deferred-accepted
  → GA, unchanged.
- **Cross-vendor eval + routing:** no regression with the extended vendor/plugin
  conformance matrix and unchanged nine-agent routing roster; derivation
  precision/recall + report conformance evals green **and biting** (each has
  its negative control).
- Live-lab golden-paths for F5/VMware **named deferred-accepted → live lab**
  (ADR-0033 §1 discipline — named, never silent).

---

## 6. Open items (non-blocking, carry forward)

- **Consultant §12 answers** — re-check at W0: *compliance regimes* (SOC 2
  CC-series stays the PROPOSED default until answered — shapes W3-T6), *data
  retention* (7y audit PROPOSED default — shapes report retention), *flow
  telemetry* (NetFlow/gNMI stays out of the dependency graph until answered),
  *app-tagging ownership* (which roles may tag — the write-path is decided: RBAC + audit, direct; the Consultant item only refines the role floor).
- **Live F5/VMware golden-paths** — deferred-accepted → live lab, same posture as
  every prior wave; scripts shipped ready-to-run.
- **G-OBS reconciliation rows 5/6/9** — flagged-deferred from P3; the W3-T7
  stretch that would have closed them was declined at plan review (2026-07-05) —
  they carry to P5 unchanged (drift-guarded).
- **P5 inheritance (recorded now so nothing drops):** Wave 4 vendors AWS (incl.
  Route53, completing the DDI triad) + Azure; hybrid on-prem/cloud topology
  stitching; scale certification. GA items (certified-scale numbers, 30-day soak,
  pentest, break-glass cadence) ride unchanged.
- **Vault status note** — the orchestrator's Obsidian vault P4 status note +
  auto-memory `MEMORY.md` entry are updated outside the in-repo commits (flagged
  so the sync is not silently skipped).
