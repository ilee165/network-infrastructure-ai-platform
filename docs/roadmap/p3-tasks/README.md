# P3-Platform — Task Specs

Per-task decomposition of **P3-PLATFORM-PLAN.md §3** waves **W0–W5**. Each task
below is a single atomic-commit unit running the **§3 per-task pattern**:

> **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.**
> Sequential tasks share files; parallelize only within a task (the two reviews).
> Single combined sonnet reviewer allowed for non-secret-surface tasks; dual
> **strong** review on the escalation set.

Escalation rule (P3-PLATFORM-PLAN.md §2, `.claude/agents/README.md`): every
secret-surface task escalates **reviewers + fixer to the live strong model**.
**`fable` is UNAVAILABLE — escalate to `opus`.** A dead-model escalation returns a
silently "clean" review (P1 W0 false-clean root cause); never inline
`model: 'fable'`. P3 secret-surface set: **SIEM export** (W3-T1), **sync-audit
failover path** (W1-T2, W4-T3), **WebSocket fan-out** (W2-T2), **worker-kill /
audit-loss drills** (W4-T5).

## Carry-forward — READ BEFORE STARTING

P1's `docs/roadmap/P1-W4-LESSONS.md` traps and the P2 lessons recur here. P3 is an
**enforcement phase** (alerts + drills), so the "gate green-at-setup masks
findings" trap is the dominant risk. Apply up front:

| Lesson | Rule | Bites which task(s) here |
|---|---|---|
| **Gate must RUN and BITE** (P1-W4) | Every new red gate ships a negative control: a *firing* `promtool` case per alert; a planted regression per drill; prove-it-bites before joining `all-gates`. | **W3-T3/T5** (alerts/MTTD), **W4-T2** (gate promotion), **W4-T3..T8** (drills), **W0-T8** (lockfile) |
| **L1** new gating CI tool | Run the tool LOCALLY before pushing it as gating; local gate set ≠ CI gate set. Where it can't run on this host (kind/promtool/k6 absent), say so and lean on a rendered/emulated equivalent. | **W0-T8** (lockfile CI), **W3-T3** (promtool), **W4-T1** (kind), all **W4** drills |
| **L3** exec argv `$(VAR)` | K8s does NOT substitute `$(VAR)` in exec argv — wrap in `sh -c`. | SIEM exporter (**W3-T1** if sidecar), every drill/upgrade **Job/CronJob** (**W4**) |
| **L4** helm secret idempotency | Reuse-or-generate dev secrets via `lookup` (empty in CI, reused on upgrade); a regen severs live connections. | **W1-T1** (PG superuser/TLS secret), **W4-T1** (kind bring-up) |
| **L5** CI pipe masks exit code | `set -o pipefail` + `test -s <out>` on any piped CI/job step. | **W4-T1** kind apply/assert, every **W4** drill pipeline |
| **SQLite ≠ PG semantics** (P2) | Idempotency / audit-loss / failover assertions run against **real PostgreSQL** (`tests/pg/` + `pg-integration`), never SQLite. | **W1-T2**, **W4-T3**, **W4-T5**, **W5** |
| **No-lockfile dep drift** (P1, bit twice) | Lockfile lands in **W0-T8** *before* P3's new deps, so drift can't re-bite; verify `include_router` route-introspection still green after any dep touch. | **W0-T8**, any task adding a dep |
| **kind `continue-on-error` until promoted** (P2 carry) | The P2 kind live run is signal-only; promotion to blocking is a deliberate, *proven-to-bite* step. | **W4-T2** |
| **L7** session windows | One-atomic-commit-per-task survives kills; discard half-done uncommitted work, resume via `resumeFromRunId` same-session only. Arm the baseline-relative usage guard on **W4** (8 tasks). | any multi-task workflow run |
| **L8** agent registry | Confirm every `agentType` is in the LIVE registry before launch — **`wf-observability` + `wf-reliability` were added this milestone**; confirm both loaded. | any **W3/W4** workflow launch |

**Reduced-scale + named-ceiling posture** (P3-PLATFORM-PLAN §0): drills prove the
*mechanism* bites at reduced scale on kind; the certified-scale numbers
(500-device / 100-user / 5,000-device / 30-day soak) are **named deferred-accepted
→ GA**, never silently claimed. Each drill states the scale it ran at.

---

## W0 — ADRs / hygiene / entry (design gate)

Owner: **`wf-implementer`** (ADRs) + **`wf-infra`** (lockfile). ADRs are the
contract every later wave implements; numbered from **0042**. Secret-surface ADRs
(0042 sync-audit, 0045 SIEM) reviewed at the strong bar.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W0-T1](W0-T1-adr-postgres-ha-sync-audit.md) | ADR-0042 Postgres HA (CloudNativePG 1+2) + PgBouncer + synchronous audit write path | `wf-implementer` | **strong** (data/audit tier) | — |
| [W0-T2](W0-T2-adr-api-hpa-keda-autoscaling.md) | ADR-0043 api HPA + KEDA per-queue worker autoscaling | `wf-implementer` | sonnet | — |
| [W0-T3](W0-T3-adr-redis-sentinel-websocket-fanout.md) | ADR-0044 Redis Sentinel + stateless WebSocket fan-out via Redis pub/sub | `wf-implementer` | sonnet | — |
| [W0-T4](W0-T4-adr-audit-siem-export.md) | ADR-0045 Audit→SIEM export (syslog/CEF/HTTPS, at-least-once, export-lag SLO) | `wf-implementer` | **strong** (audit spine) | — |
| [W0-T5](W0-T5-adr-observability-slo-enforcement.md) | ADR-0046 Observability-SLO enforcement (recording rules, burn-rate alerts, dashboards, fault-injection MTTD) | `wf-implementer` | sonnet | — |
| [W0-T6](W0-T6-adr-reliability-scale-drill-harness.md) | ADR-0047 Reliability/scale drill harness + N-2 upgrade rehearsal; records reduced-scale + named-ceiling stance | `wf-implementer` | sonnet | — |
| [W0-T7](W0-T7-adr-kind-harness-gate-promotion.md) | ADR-0048 kind-harness gate promotion (mTLS + collector-deny → blocking) | `wf-implementer` | sonnet | — |
| [W0-T8](W0-T8-dependency-lockfile.md) | Dependency lockfile (backend + frontend) + CI drift assertion — closes P1 systemic TODO | `wf-infra` | sonnet | — |
| [W0-T9](W0-T9-production-md-p3-marker.md) | `PRODUCTION.md` "P3 in progress" marker + Consultant §12 re-check (scale/HA/retention/GPU) | `wf-implementer` | sonnet | W0-T1..T7 |

## W1 — Data-tier HA (ADR-0042/0044, PRODUCTION.md §3.2/§8). **Blocks W4 failover/rebuild drills.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W1-T1](W1-T1-cloudnativepg-ha-pgbouncer.md) | CloudNativePG (1 primary + 2 replicas) + PgBouncer + sync-audit quorum + pgvector-on-replica | `wf-infra` (strong) | **strong** spec + quality | W0-T1 |
| [W1-T2](W1-T2-app-db-wiring-replica-sync-audit.md) | App DB wiring — replica reads + synchronous-commit on the audit session (real PG) | `wf-implementer` | **strong** (audit path) | W1-T1 |
| [W1-T3](W1-T3-neo4j-auto-rebuild-job.md) | Neo4j automated-rebuild Job (liveness-fail → recreate + rebuild; rebuild time = topology-RTO) | `wf-infra` | sonnet | W0-T1 |
| [W1-T4](W1-T4-redis-sentinel.md) | Redis Sentinel ×3 + AOF persistence | `wf-infra` | sonnet | W0-T3 |

## W2 — Compute scale-out (ADR-0043/0044, PRODUCTION.md §3.2). **Concurrent with W3.** Blocks W4 queue-burst/load drills.

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W2-T1](W2-T1-api-hpa-pdb.md) | api HPA (CPU + request-rate) + PodDisruptionBudget | `wf-infra` | sonnet | W0-T2 |
| [W2-T2](W2-T2-websocket-redis-pubsub-fanout.md) | Stateless WebSocket agent-session fan-out via Redis pub/sub | `wf-implementer` | **strong** (session tokens) | W0-T3, W1-T4 |
| [W2-T3](W2-T3-keda-scaledobjects-per-queue.md) | KEDA ScaledObjects per queue (discovery/config/packet/docs) on Redis queue length | `wf-infra` | sonnet | W0-T2, W1-T4 |
| [W2-T4](W2-T4-worker-idempotency-acks-late.md) | Worker `acks_late` + idempotency hardening (no duplicate side effect on scale-in / node loss) | `wf-implementer` | sonnet | W0-T2 |

## W3 — SIEM export + SLO enforcement (ADR-0045/0046, PRODUCTION.md §5/§6, G-OBS). **Concurrent with W2.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W3-T1](W3-T1-audit-siem-export-pipeline.md) | Audit→SIEM export pipeline — RFC5424 syslog + CEF + HTTPS/JSON; at-least-once + ordering + backpressure; export-lag metric | `wf-implementer` | **strong** (audit spine) | W0-T4 |
| [W3-T2](W3-T2-slo-recording-rules.md) | Prometheus recording rules for every §6 SLI | `wf-observability` | sonnet | W0-T5 |
| [W3-T3](W3-T3-burn-rate-alerts.md) | Multi-window burn-rate alert rules + runbook links + `promtool` firing tests | `wf-observability` | sonnet | W3-T2 |
| [W3-T4](W3-T4-golden-signal-dashboards.md) | Golden-signal Grafana dashboards-as-code (api, each queue, PG, Neo4j, Redis, LLM) | `wf-observability` | sonnet | W3-T2 |
| [W3-T5](W3-T5-fault-injection-mttd-harness.md) | Fault-injection MTTD harness (DB down / queue stall / LLM-provider failure → alert fires < 5 min) | `wf-observability` | sonnet | W3-T3 |

## W4 — kind HA + live drills + gate promotion + upgrade (ADR-0047/0048, PRODUCTION.md §8/§10, G-REL/G-SCA/G-MNT). **Long wave — arm the usage guard.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W4-T1](W4-T1-kind-ha-topology.md) | Ephemeral HA kind topology in CI (CNPG operator + KEDA + Sentinel + enforcing CNI) | `wf-infra` | **strong** quality | W1, W2 |
| [W4-T2](W4-T2-promote-kind-harness-blocking.md) | Promote P2 kind-harness mTLS-handshake + collector-egress-deny to **blocking** in `all-gates` | `wf-infra` | **strong** spec + quality | W4-T1 |
| [W4-T3](W4-T3-postgres-failover-drill.md) | Postgres failover drill — primary kill → promote ≤ 60 s, **zero committed-audit loss** | `wf-reliability` | **strong** spec + quality | W1-T1, W4-T1 |
| [W4-T4](W4-T4-neo4j-rebuild-drill.md) | Neo4j destroy-and-rebuild drill — topology restored ≤ topology-RTO (reduced scale) | `wf-reliability` | sonnet | W1-T3, W4-T1 |
| [W4-T5](W4-T5-worker-kill-idempotency-drill.md) | Worker-kill idempotency + Celery ≥99% success drill (real PG) | `wf-reliability` | **strong** spec + quality | W2-T4, W4-T1 |
| [W4-T6](W4-T6-queue-burst-load-drill.md) | Queue-burst KEDA scale-out/in + reduced-scale API load p95 + PgBouncer budget | `wf-reliability` | sonnet | W2-T1, W2-T3, W4-T1 |
| [W4-T7](W4-T7-compressed-soak-drill.md) | Compressed-soak drill — §6 SLOs hold over the compressed window | `wf-reliability` | sonnet | W3, W4-T1 |
| [W4-T8](W4-T8-n2-upgrade-rehearsal.md) | N-2 → N upgrade rehearsal on seeded data (expand/contract + rolling order + Neo4j rebuild) | `wf-infra` + `wf-implementer` | sonnet | W1, W2, W4-T1 |

## W5 — Evals + phase-exit gate (PRODUCTION.md §6/§11, G-OBS/G-SCA/G-REL/G-MNT)

Owner: **`wf-eval-designer`** (suites) + **`wf-release-auditor`** (gate evidence).
The LAST P3 wave and the phase-exit gate. Builds the *proof*, not new controls.
**Rebase the W5 branch onto `origin/main` first.**

| Task | Title | Owner | Review tier | Depends on |
|---|---|---|---|---|
| [W5-T1](W5-T1-slo-siem-eval-corpus.md) | SLO/alert eval corpus + SIEM-export conformance eval (format + lag) | `wf-eval-designer` (strong) | **strong** quality | W3 |
| [W5-T2](W5-T2-cross-vendor-routing-rerun.md) | Cross-vendor + agent routing re-run (no regression vs P2 matrix; roster unchanged) | `wf-eval-designer` | sonnet spec + quality | W4 |
| [W5-T3](W5-T3-gate-evidence-readiness.md) | G-* gate evidence doc + P3-Platform readiness; flip ADRs 0042–0048 → Accepted; record G-SCA/G-REL mechanism-PASS + named ceiling; `PRODUCTION.md` P3 exit marker | `wf-release-auditor` (strong) | **strong** quality | W5-T1, W5-T2, W4 |

---

## Sequencing (within P3-PLATFORM-PLAN.md §4)

- **W0** first (ADRs + lockfile + marker). T1–T7 independent (distinct ADRs); T8
  lockfile lands before new deps; T9 last (cites the ADRs).
- **W1** before W4 (the HA tier is what failover/rebuild drills act on; the
  sync-audit path must exist before W4-T3 asserts zero audit loss). T1 → T2
  (app wiring imports the cluster/pooler); T3, T4 independent.
- **W2 ‖ W3** (disjoint files: manifests + worker code vs. rule/dashboard files +
  export pipeline). W2-T3/T4 land before the W4 queue-burst/idempotency drills.
- **W4** after W1+W2+W3: T1 (kind topology) → T2 (promote gate) and T3–T7 (drills,
  internally parallel where the cluster allows) → T8 (upgrade rehearsal). The long
  wave — arm the baseline-relative usage guard.
- **W5** last: T1 ‖ T2 (disjoint: eval corpus / routing cases); T3 last (cites
  T1/T2 + W4, flips ADRs + roadmap on green). Rebase onto `origin/main` first.

## Spec template

Every per-task spec uses the same sections: **Metadata · Objective · Scope (In/Out)
· Requirements · Contracts/artifacts · Test & gate plan · Exit criteria · Workflow ·
Risks.** Requirements are grounded line-by-line in the cited ADR/PRODUCTION.md §;
nothing here re-decides an ADR — these specs *implement* the W0 design gate
(ADR-0042…0048).
