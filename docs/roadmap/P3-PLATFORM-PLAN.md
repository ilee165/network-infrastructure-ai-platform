# P3-Platform Build Plan — HA / Scale-out + Audit→SIEM Export + Observability-SLO Enforcement

**Project:** AI Network Operations Platform
**Status:** PLANNED — design (this doc). W0 not started. Entry condition satisfied: **P2-Security COMPLETE** (`docs/roadmap/P2-RELEASE-READINESS.md` — G-SEC/G-MNT/G-OBS PASS on release HEAD `6acac91`, CI run 28349836098; ADRs 0034–0041 Accepted).
**Authority:** Bound by `CLAUDE.md`, `docs/architecture/DECISIONS-BRIEF.md` (D1–D16), and `docs/roadmap/PRODUCTION.md` §1 (phase table + 2026-06-25 amendment), §3 (HA/scale-out), §5–§6 (SIEM export + SLOs), §8 (DR), §10 (upgrade), §11 (gates).
**Scope source:** `PRODUCTION.md` Phase **P3-Platform** = the platform tracks the 2026-06-25 re-scope moved out of P2: HA + scale-out, audit→SIEM export, observability-SLO enforcement, live failover/soak/scale DR drills, N-2 upgrade rehearsal, and promotion of the kind-harness live-enforcement run to a blocking gate. **Platform-only — no vendor wave** (Wave 3 F5/VMware is P4).

---

## 0. Scope discipline — what "validate" means on this host (decided 2026-06-29)

P3 is the phase whose purpose is to *close* G-SCA and the G-REL live drills — the
exact gates P2 deferred because the authoring host has **no certified-scale
cluster, no real devices, no LLM provider**. P3 inherits that reality, so it does
not pretend to certified scale. The ratified posture (user decision 2026-06-29):

- **Build the full machinery and prove the *mechanism* BITES at reduced scale on
  an ephemeral HA kind cluster in CI.** Failover, Neo4j rebuild, worker-kill
  idempotency, queue-burst autoscale, a reduced-scale API load test, and a
  *compressed* soak all run as blocking drills against a kind topology that hosts
  CloudNativePG, KEDA, and Redis Sentinel. Each drill ships a **negative control**
  (a planted regression that makes the assertion go red), so it is a real gate,
  not green-at-setup (the P1-W4 lesson).
- **Name the certified-scale ceiling deferred-accepted, never silently.** The
  §11 target numbers — 500-device discovery, 100 concurrent users, 5,000-device
  projection, and the 30-day calendar soak — require a real cluster and calendar
  time. They are recorded **deferred-accepted → GA / customer cluster** with a
  **written promotion path** (ADR-0047 + the readiness doc), in the exact
  ADR-0033 §1 discipline carried from P1/P2. G-OBS, by contrast, is fully
  enforceable in CI (`promtool`) and is targeted as a true PASS.
- **G-SCA/G-REL exit verdict = "mechanism PASS at reduced scale; certified-scale
  numbers named-deferred."** A later-phase/certified-scale criterion left unmet is
  **not** a P3 blocker; an unmet *mechanism* criterion would be.

The alternative (procure a real/cloud certified-scale cluster) was considered and
declined for P3 — same no-hardware posture as M4/M5/P1/P2.

---

## 0a. Lessons carried from P1/P2 — applied here

Standing discipline from `CLAUDE.md` "Orchestrated builds", `.claude/agents/README.md`,
`.claude/workflows/README.md`, and the MEMORY index, made concrete for P3:

| Lesson (source) | How P3 applies it |
|---|---|
| **A gate green-at-setup masks findings — confirm it RUNs and BITEs** (P1-W4) | Every new red gate ships a negative control: each burn-rate alert has a *firing* `promtool` case; each drill has a planted regression that turns it red; the kind-harness promotion (W4-T2) is proven to bite before it joins `all-gates`. The defining risk of an enforcement phase. |
| **Escalate every secret-surface role to the strong model; `fable` UNAVAILABLE** (P1-W0 false-clean) | P3 secret surfaces — **SIEM export** (audit spine leaving the platform), **synchronous audit write path** on failover, **WebSocket fan-out** (session tokens over pub/sub), and the **failover/audit drills** — escalate reviewers + fixer to `opus`. Never inline `model:'fable'`. |
| **After a kill, trust git not the result object; salvage uncommitted tree; focused-rerun gaps; never `reset --hard`** (P1-W6) | Standing recovery protocol for every wave. Atomic commit per task is the save unit. |
| **Arm a baseline-relative usage guard on long runs** (`budget.spent()` is cumulative) | W4 (8 drill tasks) is the long wave — capture `BASELINE = budget.spent()` at script top, gate on the run's own allowance, `return` partial on trip. |
| **SQLite hides PG semantics; use the `pg-integration` layer** (P2 recurring major) | Every idempotency / audit-loss / failover assertion runs against **real PostgreSQL** via the W5-T0 `tests/pg/` + `pg-integration` job, never SQLite. |
| **Add a dependency lockfile — drift bit twice** (P1 systemic TODO) | **W0-T8 closes it** (backend + frontend lockfile + CI assertion) *before* P3's new deps land, so drift cannot bite a third time. |
| **Rebase before a new wave; PR-not-mid-run-edit; single combined reviewer for non-critical** (workflow README) | Standing mechanics; dual strong review only on the secret-surface set above. |
| **The kind-harness live run is `continue-on-error` until deliberately promoted** (P2 carry) | W4-T2 is that deliberate, named promotion — not an accident. |

---

## 1. Scope

| Track | Deliverables | PRODUCTION.md ref |
|---|---|---|
| Data-tier HA | CloudNativePG (1 primary + 2 replicas), PgBouncer, **synchronous replication on the `audit_log` write path** (quorum commit so audit survives primary loss), pgvector verified on replicas; Neo4j automated-rebuild Job (rebuild time = topology-RTO); Redis Sentinel ×3 + AOF | §3.1/§3.2, §8 |
| Compute scale-out | `api` HPA (CPU + request-rate) + PodDisruptionBudget; **stateless WebSocket agent-session fan-out via Redis pub/sub** (any replica serves any session); KEDA ScaledObjects per queue (discovery/config/packet/docs) on Redis queue length; worker `acks_late` + idempotency hardening | §3.2 |
| Audit→SIEM export | Vendor-neutral pipeline: RFC5424 syslog + CEF over TLS + generic HTTPS/JSON sink; at-least-once delivery + ordering + backpressure; **export-lag metric** (p95 < 60 s SLO) | §5, §6 |
| Observability-SLO enforcement | Recording rules for every §6 SLI; multi-window multi-burn-rate alerts with runbook links; golden-signal Grafana dashboards-as-code (api, each queue, PG, Neo4j, Redis, LLM); **fault-injection MTTD harness** (< 5 min) | §6, §11 G-OBS |
| Reliability/scale drills | Ephemeral HA **kind** topology; Postgres failover, Neo4j rebuild, worker-kill idempotency, queue-burst KEDA, reduced-scale API load, compressed soak — each biting on a negative control | §8, §11 G-REL/G-SCA |
| Upgrade rehearsal | N-2 → N rehearsal on a seeded dataset: expand/contract migration + rolling order + Neo4j rebuild | §10, §11 G-MNT |
| Gate promotion | Promote the P2 kind-harness **live-enforcement** run (mTLS handshake + collector egress-deny) from `continue-on-error` to **blocking in `all-gates`** | P2 carry, `docs/runbooks/kind-harness.md` |
| Build hygiene | Dependency lockfile (backend + frontend) + CI drift assertion — closes the P1 systemic TODO | D16, §10 |
| Gates | G-OBS full PASS; G-SCA/G-REL **mechanism PASS at reduced scale + named certified-scale ceiling**; G-SEC continuous + kind-live promotion; G-MNT continuous + N-2 rehearsal | §11 |

**Out of P3-Platform (→ P4 / GA):** Wave 3 vendors (F5 BIG-IP, VMware) and
application-dependency topology (P4); compliance & audit reporting suite (P4);
hybrid-cloud topology + scale certification (P5); certified-scale load/soak on real
hardware, external pentest, and the 6-month break-glass cadence (GA / operational).

---

## 2. Agent capability review

Roles + model tiers from `.claude/agents/README.md`. P3 reuses the P1/P2 roster
**and adds two new SRE roles** (registered in the README this milestone) because
two P3 deliverable shapes have no fit in the existing roster:

| agentType | Model | P3 use | New? |
|---|---|---|---|
| `wf-implementer` | strong (inherit) | Novel/security-critical **Python**: SIEM export pipeline, WebSocket pub/sub fan-out, worker idempotency, sync-audit DB wiring, expand/contract migration | reuse |
| `wf-infra` | strong (inherit) | Declarative HA infra: CloudNativePG, PgBouncer, Sentinel, HPA/PDB, KEDA ScaledObjects, the kind HA topology, kind-gate promotion, upgrade-rehearsal Job, dependency-lockfile CI | reuse |
| **`wf-observability`** | **strong** | **G-OBS**: PromQL recording rules, multi-window burn-rate alerts + runbook links, Grafana dashboards-as-code, fault-injection MTTD harness. Alert-as-test gates (`promtool`), not Python-TDD | **NEW** |
| **`wf-reliability`** | **strong** | **G-SCA/G-REL live drills**: load gen (k6/locust), chaos pod-kill failover, RTO/RPO/idempotency, queue-burst, compressed soak against kind. Drill-as-test gates with negative controls; honest reduced-scale + named ceiling | **NEW** |
| `wf-eval-designer` | strong | SLO/alert eval corpus + SIEM-export conformance eval; cross-vendor + agent routing re-run | reuse |
| `wf-release-auditor` | strong | Phase-exit G-* evidence + readiness doc; flips ADRs 0042–0048 + roadmap on green | reuse |
| `wf-spec-reviewer` / `wf-quality-reviewer` | sonnet* | Spec + quality review per task | reuse |
| `wf-fixer` / `wf-verifier` | sonnet* | Apply enumerated findings / confirm resolved | reuse |

**Why two new agents and not one `wf-infra` overload:** `wf-infra` is gated on
manifest-policy tools (kubeconform/conftest/kube-linter) — "does this YAML render
and pass policy." It cannot express "does this alert *fire* within MTTD" or "did
this drill *actually* kill the primary and lose zero audit rows." Those are
statistical/behavioural assertions over a running cluster, a distinct toolchain
(`promtool`, k6, chaos) and gate philosophy. `wf-observability` and
`wf-reliability` are split rather than merged into one `wf-sre` because they own
different gates (G-OBS vs G-SCA/G-REL), run in different waves (W3 vs W4), and can
be dispatched concurrently with clear scope. If a leaner roster is preferred they
collapse cleanly into one `wf-sre` role — flagged, not assumed.

\* **Escalation rule** (`.claude/agents/README.md`): every secret-surface task
escalates reviewers + fixer to the live strong model (`opus`); `fable` is
UNAVAILABLE — never inline `model:'fable'`. P3 secret-surface set: **SIEM export**
(W3-T1, audit spine leaves the platform), **sync-audit failover path** (W1-T2,
W4-T3), **WebSocket fan-out** (W2-T2, session tokens over pub/sub), and the
**failover/audit/idempotency drills** (W4-T3/T5). All escalate.

---

## 3. Build waves (dependency-ordered)

Per-task pattern, unchanged from P1/P2: **1 implementer → 2 reviewers (spec +
quality) → conditional fixer → verifier → 1 atomic commit.** Sequential tasks
share files; parallelize only within a task. Single combined sonnet reviewer
allowed for non-secret-surface tasks; dual strong review on the escalation set.
ADRs numbered from **0042** (current max 0041). Full per-task specs (one file per
task, with explicit exit criteria): `docs/roadmap/p3-tasks/README.md`.

| Wave | Tasks | Owner(s) | Review tier | Notes |
|---|---|---|---|---|
| **W0 — ADRs / hygiene / entry** | ADR-0042 (Postgres HA + sync-audit) · 0043 (api HPA + KEDA) · 0044 (Sentinel + WS pub/sub) · 0045 (audit→SIEM export) · 0046 (SLO enforcement) · 0047 (drill harness + N-2 rehearsal; records the reduced-scale + named-ceiling stance) · 0048 (kind-harness gate promotion); **W0-T8 dependency lockfile** (backend+frontend, before new deps land); **W0-T9** `PRODUCTION.md` "P3 in progress" marker + Consultant §12 re-check (scale/HA/retention/GPU defaults) | `wf-implementer` (+ `wf-infra` for T8) | sonnet (strong for 0045/0042 secret-surface ADRs) | Design gate; unblocks all waves. Per-task specs: `docs/roadmap/p3-tasks/` |
| **W1 — Data-tier HA** | T1 CloudNativePG (1 primary + 2 replicas) + PgBouncer + sync-audit quorum + pgvector-on-replica (`wf-infra`); T2 app DB wiring: replica reads + sync-commit on audit session (`wf-implementer`, **escalated**); T3 Neo4j auto-rebuild Job (`wf-infra`); T4 Redis Sentinel ×3 + AOF (`wf-infra`) | `wf-infra` + `wf-implementer` | strong (T2 audit path) | **Blocks W4 failover/rebuild drills** |
| **W2 — Compute scale-out** | T1 api HPA + PDB (`wf-infra`); T2 stateless WebSocket fan-out via Redis pub/sub (`wf-implementer`, **escalated**); T3 KEDA ScaledObjects per queue (`wf-infra`); T4 worker `acks_late` + idempotency hardening (`wf-implementer`) | `wf-infra` + `wf-implementer` | strong (T2) / sonnet | **Concurrent with W3** (disjoint files). Blocks W4 queue-burst/load drills |
| **W3 — SIEM export + SLO enforcement** | T1 SIEM export pipeline: syslog/CEF/HTTPS, at-least-once, export-lag metric (`wf-implementer`, **escalated**); T2 recording rules (`wf-observability`); T3 burn-rate alerts + runbook links + `promtool` firing tests (`wf-observability`); T4 golden-signal dashboards-as-code (`wf-observability`); T5 fault-injection MTTD harness (`wf-observability`) | `wf-implementer` + `wf-observability` | strong (T1) / sonnet | **Concurrent with W2.** G-OBS owner |
| **W4 — kind HA + live drills + gate promotion + upgrade** | T1 ephemeral HA kind topology (CNPG/KEDA/Sentinel/enforcing-CNI) (`wf-infra`); **T2 promote P2 kind-harness mTLS + collector-deny to BLOCKING** (`wf-infra`); T3 Postgres failover drill ≤60 s + zero audit loss (`wf-reliability`, **escalated**); T4 Neo4j rebuild drill ≤ RTO (`wf-reliability`); T5 worker-kill idempotency + Celery ≥99% (real PG) (`wf-reliability`, **escalated**); T6 queue-burst KEDA + reduced-scale API load p95 + PgBouncer budget (`wf-reliability`); T7 compressed-soak drill (`wf-reliability`); T8 N-2→N upgrade rehearsal on seeded data (`wf-infra` + `wf-implementer` migration) | `wf-infra` + `wf-reliability` + `wf-implementer` | strong (T2/T3/T5) | Needs W1+W2+W3. **Long wave — arm the usage guard.** kind drills bite at reduced scale; certified-scale named-deferred |
| **W5 — Evals + phase-exit gate** | T1 SLO/alert eval corpus + SIEM-export conformance eval (format + lag) (`wf-eval-designer`); T2 cross-vendor + agent routing re-run, no regression (`wf-eval-designer`); T3 G-* evidence doc + P3 readiness; flip ADRs 0042–0048 Accepted; record G-SCA/G-REL mechanism-PASS + named ceiling, G-OBS PASS, kind-promotion blocking-verified; `PRODUCTION.md` P3 exit marker (`wf-release-auditor`) | `wf-eval-designer` + `wf-release-auditor` | strong | Phase-exit gate; mirrors P1-W7 / P2-W5. Builds the *proof*, not new controls |

---

## 4. Sequencing

- **W0 first** — ADRs are the design contract; the lockfile (W0-T9) lands before
  new deps so drift cannot re-bite; the `PRODUCTION.md` marker + Consultant
  re-check open the phase.
- **W1 first among build waves** — the HA data tier is what the failover/rebuild
  drills (W4) act on; the sync-audit path must exist before W4-T3 can assert zero
  audit loss.
- **W2 and W3 run concurrently** — compute scale-out and the observability/SIEM
  stream touch disjoint files (manifests + worker code vs. rule/dashboard files +
  export pipeline). KEDA (W2-T3) and the worker idempotency hardening (W2-T4)
  must land before the W4 queue-burst/idempotency drills.
- **W4 after W1+W2+W3** — every drill needs the HA topology, the autoscalers, and
  the metrics/alerts it asserts against. Within W4: T1 (kind topology) → T2
  (promote gate) and T3–T7 (drills, internally parallel where the cluster allows)
  → T8 (upgrade rehearsal). This is the **long wave**: arm the baseline-relative
  usage guard.
- **W5 last** — needs the full machinery in place to evaluate; the release auditor
  flips ADRs/roadmap only on green.

---

## 5. Per-wave exit criteria

**W0 (design):** ADRs 0042–0048 written (Proposed); secret-surface ADRs
(0042 sync-audit, 0045 SIEM) reviewed at the strong bar; dependency lockfile in
place and CI drift assertion **proven to bite** (a planted out-of-lock dep fails
CI); `PRODUCTION.md` carries a "P3 in progress" marker; Consultant §12 defaults
(scale/HA/retention/GPU) re-confirmed or converted. D16 green.

**W1 (data-tier HA):** CloudNativePG cluster + PgBouncer + Sentinel render and
pass `infra` policy gates (kubeconform/conftest/kube-linter); pgvector verified on
a replica; the `audit_log` write path uses **synchronous (quorum) commit**
asserted under real PG; Neo4j auto-rebuild Job renders and its rebuild path is
exercised. No D16 regression.

**W2 (compute scale-out):** api HPA + PDB and KEDA ScaledObjects render and pass
policy gates; WebSocket session state is **fully externalized to Redis pub/sub**
(asserted: a session opened on replica A is served by replica B); worker tasks are
`acks_late` + idempotent — a re-delivered task produces **no duplicate side
effect** (asserted under real PG).

**W3 (SIEM + SLO):** the SIEM export pipeline emits valid RFC5424 syslog + CEF +
HTTPS/JSON, delivers **at-least-once with ordering** under a fault-injected sink
outage, and exposes the **export-lag metric**; **no audit payload secret leaks**
into any export log/artifact (escalated review). Every §6 SLI has a recording
rule; every SLO has a multi-window burn-rate alert linking a runbook; **each alert
has a `promtool` firing test that bites** (a perturbed series fires within the
window); golden-signal dashboards render and lint; the fault-injection harness
fires each alert within the **MTTD < 5 min** budget over synthetic series.

**W4 (drills + promotion + upgrade):** on the ephemeral HA kind cluster, as
**blocking** CI —
- **Failover (G-REL):** PG primary kill → automated promotion, write service
  restored **≤ 60 s**, **zero committed-audit-entry loss** (sync path verified);
  negative control (async path) shows the assertion go red.
- **Neo4j rebuild (G-REL):** destroy → full topology restored from Postgres within
  the measured topology-RTO at reduced scale.
- **Idempotency (G-REL):** worker-node kill mid-run → jobs complete via retry with
  no duplicate side effect (real PG); Celery success ≥ 99% over the window.
- **Queue-burst (G-SCA):** 10× `discovery` depth → KEDA scale-out then scale-in,
  drains within SLO, `config`/`packet`/`docs` not starved (per-queue isolation);
  reduced-scale API load shows p95 held and a 1→2-replica improvement; PgBouncer
  shows no connection exhaustion.
- **Compressed soak:** §6 SLOs hold over the compressed window.
- **Gate promotion:** the P2 kind-harness **mTLS-handshake + collector-egress-deny**
  live assertions now run **inside `all-gates`** (no `continue-on-error`), and were
  shown to **bite** on a planted regression before promotion — closing the P2 carry.
- **Upgrade (G-MNT):** N-2 → N rehearsal green on a seeded dataset (expand/contract
  migration + rolling order + Neo4j rebuild).
- Each drill states the scale it ran at; **certified-scale numbers named-deferred**.

**Phase exit (W5):** the P3-scoped slice of all five §11 gates passes
simultaneously on the release HEAD —
- **G-OBS — PASS (full):** every §6 SLO has a recording rule + multi-window
  burn-rate alert + runbook link; golden-signal dashboards exist; fault-injection
  MTTD < 5 min proven; audit→SIEM export operating within the lag SLO.
- **G-SCA — mechanism PASS at reduced scale + named ceiling:** scale-out/in,
  queue-burst isolation, load p95, PgBouncer budget all bite on kind; the
  500-device / 100-user / 5,000-device certified-scale numbers are
  **deferred-accepted → GA/customer cluster** (promotion path in ADR-0047 +
  readiness doc), named not silent.
- **G-REL — mechanism PASS at reduced scale + named ceiling:** failover (≤60 s,
  zero audit loss), Neo4j rebuild, idempotency, Celery ≥99%, compressed soak all
  bite on kind; the **30-day calendar soak** and certified-scale DR are
  **deferred-accepted → GA**, named. P2 G-REL baseline holds.
- **G-SEC — PASS (continuous + promotion):** inherits all P2 controls; the
  kind-live mTLS-handshake + collector-egress-deny sub-items are now **blocking**
  (the P2 PARTIAL items promoted); no regression. External pentest + 6-month
  break-glass remain GA/operational, named.
- **G-MNT — PASS:** D16 green; ADRs 0042–0048 Accepted; **N-2 upgrade rehearsal
  green** (closes the P2-deferred §11 G-MNT item); dependency lockfile added
  (closes the P1 systemic TODO); `PRODUCTION.md` amended with the P3 exit marker.

Every later-phase / certified-scale criterion is named deferred-accepted, none
silent (ADR-0033 §1 discipline, carried from P1/P2). Each gate that flips an ADR
is confirmed to RUN and BITE (P1-W4 lesson).

---

## 6. Open items (non-blocking, carry forward)

- **Consultant §12 answers** — re-check `docs/consultant/QUESTIONS.md` at W0: *scale
  targets* (rebases the named G-SCA ceiling numbers), *HA/DR expectations* (RPO/RTO
  targets, Neo4j Enterprise opt-in), *GPU availability* (Ollama pool + first-token
  SLO), *data retention* (SIEM export + log/audit retention windows). PROPOSED
  defaults hold otherwise.
- **Certified-scale + 30-day soak** — deferred-accepted → GA / customer cluster;
  promotion path written in ADR-0047 and the W5 readiness doc (the kind drills are
  the mechanism proof; the ceiling is the calendar/hardware bit).
- **kind-harness live enforcement** — W4-T2 promotes the P2 mTLS + collector-deny
  live assertions to blocking; `docs/runbooks/kind-harness.md` is updated to record
  the promotion (the P2 readiness doc named this as the P3 inheritance).
- **Neo4j HA** — single-instance + automated rebuild is the designed path (D5);
  Neo4j Enterprise causal cluster stays a PROPOSED opt-in pending the Consultant
  HA answer (§3.2).
- **P4 inheritance** — Wave 3 (F5 BIG-IP, VMware) + application-dependency topology +
  the compliance & audit reporting suite; its plan is authored when P3-Platform exits.
- **Vault status note** — the orchestrator's Obsidian vault P3-Platform status note +
  `MEMORY.md` are updated outside the in-repo commits (flagged so the sync is not
  silently skipped).
