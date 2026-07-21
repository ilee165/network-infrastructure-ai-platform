# P4 — Task Specs

Per-task decomposition of **P4-PLAN.md §3** waves **W0–W4**. Each task below is
a single atomic-commit unit running the **§3 per-task pattern**:

> **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.**
> Sequential tasks share files; parallelize only within a task (the two reviews).
> Single combined sonnet reviewer allowed for non-secret-surface tasks; dual
> **strong** review on the escalation set.

Escalation rule (P4-PLAN.md §2, `.claude/agents/README.md`): every
secret-surface task escalates **reviewers + fixer to the live strong model**.
Confirm the escalation model is in the LIVE registry before launch — a
dead-model escalation returns a silently "clean" review (P1 W0 false-clean root
cause); never inline a hard-coded model name. P4 secret-surface set:
**device-credential flows** (W1-T1/T2 — iControl token + vCenter session via the
D11 vault), **report engine on the audit spine** (W3-T1 — artifacts leave the
platform), **access-review report** (W3-T4 — users/roles/OIDC/break-glass),
**audit-integrity report** (W3-T5 — hash-chain surface).

**Plan-review amendment (2026-07-05):** the ADR-0052 design review (W0-T3) was
**escalated from sonnet to strong** at plan review — the tagging-authz section
(§7) is secret-surface-adjacent and the mandatory-pass projection decision
carries the D5 rebuild contract. The §3 table tier for W0 reads with this
amendment applied.

## Carry-forward — READ BEFORE STARTING

The P4-PLAN.md §0a lessons, mapped to the tasks they bite here:

| Lesson | Rule | Bites which task(s) here |
|---|---|---|
| **Gate must RUN and BITE** (P1-W4) | Every new eval/check ships a negative control proven to go red: a planted wrong `DEPENDS_ON` edge fails the derivation eval; a planted secret fails the redaction check; a monkeypatched missing `_INTERFACE_SPECS` entry fails the plugin-conformance completeness check. Verify evidence docs + run URLs before trusting promotion commits. | **W4-T1/T2/T3** (evals), **W4-T4** (gate evidence) |
| **Escalate secret-surface roles to strong** (P1-W0) | Reviewers + fixer on the live strong model for the escalation set above. | **W1-T1/T2**, **W3-T1/T4/T5** |
| **Parallel siblings share bug classes** (P2/P3) | F5 + VMware plugins and the four reports are template-siblings: a class bug found in one (fixture handling, pagination, redaction, empty-result) is swept across every sibling in the same fix commit. | **W1-T1 ∥ W1-T2**, **W3-T2..T5** |
| **SQLite hides PG semantics** (P2 recurring major) | Idempotency/diff-replace, partial-unique-index, and every report aggregation/trend query run under **real PostgreSQL** (`tests/pg/`, blocking `pg-integration`), never SQLite-only. | **W2-T1/T2/T3**, **W3-T1..T5** |
| **After a kill: trust git, salvage, focused-rerun, never `reset --hard`** | Standing recovery protocol; the atomic commit per task is the save unit. | any multi-task run |
| **Arm the baseline-relative usage guard** | `BASELINE = budget.spent()` at script top on the long waves; stop near ceiling, commit, summarize. | **W2**, **W3** launches |
| **New deps go through the lockfile** (P3-W0-T8; bit twice pre-lockfile) | `pyvmomi` (W1-T2) and WeasyPrint + transitive pins (W3-T1) land as floor+cap constraints resolved into the uv lockfile in the same commit; drift gate green. | **W1-T2**, **W3-T1** |
| **Neo4j is rebuilt from Postgres** (D5) | The application layer is PG-backed and projected; the auto-rebuild path includes the new kinds and `ci/kind/selftest/neo4j-rebuild-bite.sh` stays green — explicit W2 exit criterion. | **W2-T1**, re-verified **W4-T4** |
| **Rebase before a new wave; PR-not-mid-run-edit** | Standing mechanics (workflow README). | every wave launch |

**Validation posture** (P4-PLAN.md §0): no live F5 BIG-IP or vCenter lab exists
on the authoring host — plugin validation is the **conformance suite over
recorded fixtures** (raw payloads verbatim; normalized models round-trip); live
golden-paths ship ready-to-run and are **named deferred-accepted → live lab**.
No LLM provider on the host — agent-facing evals run as the deterministic CI
layer; real-LLM runs stay the documented opt-in manual gate. Everything else is
CI-enforceable and gated as a true, biting PASS. **Flow-telemetry enrichment
(NetFlow/gNMI) stays OUT of scope** until the Consultant telemetry item (Q10)
is answered — the ADR-0052 source set is closed at four.

---

## W0 — ADRs / entry (design gate) — DONE on `feat/p4-w0-adrs`

Owner: **`wf-implementer`**. The four ADRs are the contract every later wave
implements; numbered from **0050**. Secret-surface sections reviewed at the
strong bar; ADR-0052 escalated whole (amendment above).

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W0-T1](W0-T1-adr-f5-bigip-plugin.md) | ADR-0050 F5 BIG-IP plugin — httpx iControl REST, `ADC_SERVICES` + normalized ADC models, UCS archive backup | `wf-implementer` | sonnet (**strong** on §2/§7 credential + UCS sections) | — |
| [W0-T2](W0-T2-adr-vmware-plugin.md) | ADR-0051 VMware plugin — pyVmomi, `VIRTUALIZATION_INVENTORY` + normalized virtualization models, read-only vCenter role | `wf-implementer` | sonnet (**strong** on §2 credential/session section) | — |
| [W0-T3](W0-T3-adr-application-dependency-topology.md) | ADR-0052 application-dependency topology — PG-backed `Application`/`DEPENDS_ON`, four derivation sources, direct-write tagging under RBAC | `wf-implementer` | **strong** (escalated at plan review 2026-07-05) | — |
| [W0-T4](W0-T4-adr-compliance-audit-reporting.md) | ADR-0053 compliance & audit reporting suite — report engine, air-gap CSV/PDF, redaction contract, SOC 2 CC-series default | `wf-implementer` | **strong** (secret surface: artifacts leave the platform) | — |
| [W0-T5](W0-T5-production-md-p4-marker.md) | `PRODUCTION.md` "P4 in progress" marker + Consultant §12 re-check + these per-task specs + ADR index 0050–0053 | `wf-implementer` | sonnet | W0-T1..T4 |

## W1 — Vendor Wave 3 plugins (ADR-0050/0051, PRODUCTION.md §2.4/§2.6). **Blocks W2-T2 derivation.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W1-T1](W1-T1-f5-bigip-plugin.md) | F5 BIG-IP plugin: `ADC_SERVICES` + archive-capability pair + normalized models + `f5_bigip` plugin + conformance fixtures | `wf-implementer` (strong) | **strong** spec + quality (escalated credential/UCS flow) | W0-T1 |
| [W1-T2](W1-T2-vmware-plugin.md) | VMware plugin: `VIRTUALIZATION_INVENTORY` + normalized models + `vmware` plugin (pyVmomi) + conformance fixtures + lockfile | `wf-implementer` (strong) | **strong** spec + quality (escalated credential/session flow) | W0-T2 |
| [W1-T3](W1-T3-inventory-surfacing.md) | Inventory surfacing: API endpoints + UI pages for VS/pool and VM/host/cluster/port-group inventory | `wf-implementer-light` | sonnet | W1-T1, W1-T2 |

## W2 — Application-dependency topology (ADR-0052, PRODUCTION.md §2.4, D5). **Concurrent with W3** (disjoint files).

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W2-T1](W2-T1-app-schema-projector.md) | PG schema + projector: `applications`/`application_dependencies` (expand-only), Neo4j projection, **mandatory pass**, rebuild-bite stays green | `wf-implementer` | sonnet | W0-T3 (can start alongside W1) |
| [W2-T2](W2-T2-derivation-pipelines.md) | Derivation pipelines: F5 VIP→pool→member chains, VMware VM→host placement, M5 DNS linkage — deterministic, idempotent, provenance per edge | `wf-implementer` | sonnet | W2-T1, W1-T1, W1-T2 |
| [W2-T3](W2-T3-manual-application-tagging.md) | Manual application tagging: API + UI — direct write under RBAC (`engineer`+) with full audit per ADR-0052 §7 | `wf-implementer` (authz) + `wf-implementer-light` (UI) | **strong** on the authz surface / sonnet UI | W0-T3, W2-T1 (∥ W2-T2; no W1 dependency) |
| [W2-T4](W2-T4-impact-analysis.md) | Impact analysis: `fetch_impact` read + Troubleshooting-Agent tool + app-dependency UI view with provenance display | `wf-implementer` | sonnet | W2-T1, W2-T2 |

## W3 — Compliance & audit reporting suite (ADR-0053, PRODUCTION.md §7). **Concurrent with W2.**

> **Current state:** **Merged** in PR #166 (squash `7298f4b8`, 2026-07-19).
> The 27 validated review findings were remediated in four fix waves and all
> 18 required CI checks were green before merge. The
> [PR #166 review report](../../reviews/P4-W3-PR166-REVIEW.md) is historical
> evidence, not an open remediation queue.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W3-T1](W3-T1-report-engine.md) | Report engine: PG report model + beat scheduling + CSV/PDF renderers (air-gap) + retention + RBAC + **fail-closed redaction contract** | `wf-implementer` | **strong** spec + quality (escalated: audit spine + exports) | W0-T4 |
| [W3-T2](W3-T2-change-report.md) | Change report: CR lifecycle roll-up with requester/approver/executor, diff statistics, reasoning-trace links | `wf-implementer` | sonnet | W3-T1 |
| [W3-T3](W3-T3-compliance-posture-report.md) | Compliance posture report: M4 engine roll-up + **trend over time** (daily sweep populates the run history) | `wf-implementer` | sonnet | W3-T1 |
| [W3-T4](W3-T4-access-review-report.md) | Access review report: users, roles, OIDC mappings, last login, break-glass usage — admin floor | `wf-implementer` | **strong** spec + quality (escalated) | W3-T1 |
| [W3-T5](W3-T5-audit-integrity-report.md) | Audit-integrity report: daily hash-chain verification history + append-only grant attestation — admin floor | `wf-implementer` | **strong** spec + quality (escalated) | W3-T1 |
| [W3-T6](W3-T6-soc2-regime-mapping.md) | SOC 2 CC-series evidence mapping (PROPOSED default): mapping doc + report-metadata regime tags | `wf-implementer-light` | sonnet | W3-T2..T5 |

## W4 — Evals + phase-exit gate (PRODUCTION.md §2.6/§11) — COMPLETE

Owner: **`wf-eval-designer`** (suites) + **`wf-implementer`** (T2A correction)
and **`wf-release-auditor`** (gate evidence). The LAST P4 wave and the
phase-exit gate. Apart from the bounded T2A correctness prerequisite, it builds
the *proof*, not new features. **Rebase the W4 branch onto `origin/main` first.**

**Current state:** all W4 tasks are complete. Candidate `71cd249d` passed run
`29838591933`; T4 records the docs-only closeout without moving the CI evidence
anchor.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W4-T0](W4-T0-housekeeping.md) | Execution contract + mandatory LF CSV-prefix closure, split into docs T0A and code/test T0B | implementer | sonnet | W3 |
| [W4-T1](W4-T1-plugin-conformance-cross-vendor-rerun.md) | Plugin conformance + cross-vendor eval re-run: vendor matrix extended with `f5_bigip`/`vmware`; nine-agent routing roster unchanged | `wf-eval-designer` (strong) | **strong** | W4-T0 |
| [W4-T2A](W4-T2A-derivation-contract-corrections.md) | Derivation contract corrections: route-domain-safe IP reconciliation and complete VMware provenance | `wf-implementer` | **strong** | W4-T1 |
| [W4-T2](W4-T2-derivation-eval-corpus.md) | **Eval-only** app-dependency derivation corpus: contract-authored estates → expected graph, precision/recall `1.0`/`1.0`, **assert-red-inside-green controls** | `wf-eval-designer` (strong) | **strong** | W4-T2A |
| [W4-T3](W4-T3-report-conformance-evals.md) | Report conformance evals: golden CSV/PDF-structure fixtures, evidence completeness, **planted-secret redaction negative control** | `wf-eval-designer` (strong) | **strong** | W4-T2 |
| [W4-T4](W4-T4-gate-evidence-readiness.md) | `P4-RELEASE-READINESS.md` G-* evidence; ADRs 0050–0053 Accepted; `PRODUCTION.md` P4 exit marker + P5 inheritance — **Complete** | `wf-release-auditor` (strong) | **strong** quality | W4-T1, W4-T2A, W4-T2, W4-T3; all waves |

---

## Sequencing (within P4-PLAN.md §4)

- **W0** first — the four ADRs are the design contract; naming/authz/renderer
  decisions were made once there. T1–T4 independent (distinct ADRs); T5 last
  (cites the ADRs).
- **W1 before W2-T2** — the derivation pipelines consume the persisted
  normalized ADC + virtualization rows; building derivation against unstable
  models is rework. W1-T1 ∥ W1-T2 (disjoint plugin dirs — sibling-class-bug
  sweep applies); T3 after both.
- **W2 ‖ W3** — the topology track (`engines/topology/`, plugins, graph UI) and
  the reporting track (report engine, audit/CR/compliance readers, reports UI)
  touch disjoint files. W2-T1 and W2-T3 depend only on ADR-0052 + the W2-T1
  tables and can start alongside W1. Within W2: T1 → T2 → T4; T3 ∥ T2. Within
  W3: T1 first; T2–T5 ∥ after T1; T6 last.
- **W4** last — T0A/T0B land first as separate atomic commits, followed by
  T1 → T2A → T2 → T3 and then T4. W4-T2 preflight after T1 identified T2A as
  the bounded runtime-correction prerequisite; it does not edit the evidence
  ledger, and T2 remains eval-only. T1/T2/T3 each own one non-self-referential
  section for status, focused commands/results, bite test node IDs, and the
  blocking-CI collection path in `P4-W4-evals-evidence.md`; T4 alone owns the
  ledger's top-level lifecycle and populates its final table with landed eval
  task commit SHAs, one final release HEAD, run/job URLs, and results. The final
  branch log contains eight commits: the six planned pre-T4 task commits, the
  bounded dependency-audit remediation, and T4. T4 flips ADRs/roadmap only on green.
  Rebase onto `origin/main` first.
- **Both W2 and W3 arm the baseline-relative usage guard** (each is 4–6 tasks).

## Spec template

Every per-task spec uses the same sections: **Metadata · Objective · Scope
(In/Out) · Requirements · Contracts/artifacts · Test & gate plan · Exit criteria
· Workflow · Risks.** Requirements are grounded line-by-line in the cited
ADR/PRODUCTION.md §; nothing here re-decides an ADR — these specs *implement*
the W0 design gate (ADR-0050…0053).
