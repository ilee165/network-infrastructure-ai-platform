# ADR-0047: Reliability/Scale Drill Harness + N-2 Upgrade Rehearsal — Reduced-Scale Mechanism Proof + Named Certified-Scale Ceiling

**Status:** Proposed | **Date:** 2026-06-29 | **Milestone:** P3 W0

## Context

`PRODUCTION.md` §11 gates **G-REL** (§313) and **G-SCA** (§322) — and the
maintainability item **G-MNT §346** (N-2 upgrade rehearsal) — are the gates
P2-Security explicitly deferred: per the §1 2026-06-25 amendment (§300), the live
failover/soak/scale drills "need a certified-scale cluster to validate" and were
moved to **P3-Platform**. P3 is the phase whose purpose is to *close* them. The §8
"DR / backup" table likewise schedules the failover and Neo4j-rebuild drills "from
P3-Platform," and §10 fixes the upgrade strategy (expand/contract, rolling order,
post-upgrade Neo4j rebuild) that G-MNT §346 rehearses.

This ADR is the **design gate** for the drill harness — the catalogue of drills,
their §11 pass criteria + target numbers, the rule that makes each drill a *real*
gate, and the N-2 → N upgrade-rehearsal procedure. It does **not** build the kind
topology (ADR-0048 + W4-T1) or implement the drills (W4-T3..T8); it is the
testable contract those tasks satisfy.

The authoring/CI host has **no certified-scale cluster, no real devices, no LLM
provider** (the exact reason P2 deferred these gates), and P3 inherits that
reality (`P3-PLATFORM-PLAN.md` §0, user decision 2026-06-29). So this ADR also
ratifies — **critically** — the **reduced-scale + named-ceiling validation
posture**: the drills prove each *mechanism* **bites** on an ephemeral HA kind
cluster at reduced scale, and the certified-scale numbers (500-device discovery,
100 concurrent users, 5,000-device projection, 30-day calendar soak) are recorded
**deferred-accepted → GA / customer cluster** with a **written promotion path** —
named, never silently claimed (ADR-0033 §1 discipline, carried from P1/P2).

Bounded by **ADR-0030** (backup/DR baseline — pgBackRest WAL archiving, the
out-of-cluster DR tier; topology-RTO via Neo4j rebuild), **ADR-0042** (Postgres HA
+ synchronous audit write path — the failover/zero-audit-loss design these drills
exercise), **ADR-0043** (api HPA + KEDA per-queue autoscaling — the scale-out
machinery the queue-burst/load drills exercise), **ADR-0044** (Redis Sentinel +
WebSocket fan-out), **ADR-0005** (Neo4j as a rebuildable projection — the rebuild
drill's whole premise), **ADR-0008** (Celery per-queue workers — idempotency /
≥99% success), **ADR-0029** (K8s/Helm GA chart, the upgrade target), and
**ADR-0016** (testing/CI — drills join `all-gates`). The kind topology itself and
its gate promotion are **ADR-0048**. PRODUCTION.md §8, §10, and §11
G-REL §313 / G-SCA §322 / G-MNT §346 are the line-by-line source.

## Decision

**The platform ships a catalogue of reliability/scale drills that run as blocking
CI against an ephemeral HA kind cluster (ADR-0048 / W4-T1) hosting CloudNativePG,
KEDA, and Redis Sentinel. Each drill proves a single §11 mechanism — Postgres
failover (≤ 60 s, zero committed-audit loss), Neo4j destroy-and-rebuild (≤
topology-RTO), worker-kill idempotency + Celery ≥ 99% success, queue-burst KEDA
scale-out/in with per-queue isolation, reduced-scale API load p95, and a
compressed soak — and EVERY drill ships a planted negative control that turns its
assertion red, so it is a real gate and not green-at-setup (P1-W4 lesson).
Idempotency / audit-loss / failover assertions run against REAL PostgreSQL
(`tests/pg/` + the `pg-integration` job), never SQLite (P2 lesson). The drills run
at REDUCED scale and each states the scale it ran at; the §11 certified-scale
numbers (500-device / 100-user / 5,000-device / 30-day soak) are NAMED
deferred-accepted → GA / customer cluster with a written promotion path (§4).
Separately, an N-2 → N upgrade rehearsal runs in CI on a seeded production-shaped
dataset, exercising the §10 expand/contract migration, the rolling upgrade order
with Celery warm shutdown, and the post-upgrade Neo4j rebuild (G-MNT §346).**

### 1. Reduced-scale, mechanism-proving posture — the load-bearing decision

Every drill's job is to prove the **mechanism** works, on kind, at a scale the CI
host can run. A drill that exercises the real control path on a 3-node
CloudNativePG cluster with a handful of seeded devices is a true proof that
*failover promotes and loses no audit row*, *the projection rebuilds from
Postgres*, *a re-delivered task produces no duplicate side effect*, *KEDA scales a
queue out and back in*. What it does **not** prove is the *certified-scale number*
(§4). The two are kept distinct and both stated, so the phase can honestly report
"mechanism PASS at reduced scale" without ever implying "validated at certified
scale" — the §0 posture and the dominant risk this ADR guards (a drill that
quietly slides from "the mechanism bites" to "we ran at scale").

**Each drill MUST state the scale it ran at** (instance counts, seeded device/user
counts, queue depths, soak duration) in its output and runbook, so the reduced
scale is on the record next to every PASS.

Where kind cannot run on the local author host (P1-W4 **L1**: a new gating tool's
local set ≠ the CI set), the drill says so and leans on the CI kind run / a
rendered or emulated equivalent — the same honesty ADR-0042 §5 applies to the
pgvector-on-replica smoke.

### 2. Drill-as-test + negative control — the anti-false-green rule

**Every drill ships a planted regression (a "negative control") that makes its
assertion go RED**, and that regression is shown to bite before the drill joins
`all-gates`. This is the single most important rule in this ADR (P1-W4 lesson: a
gate green-at-setup masks the findings it would have produced). A drill that
asserts nothing — or that would pass whether or not the control works — is not a
gate. Concretely, per drill:

| Drill | Positive assertion | Planted negative control (turns it RED) |
|---|---|---|
| Postgres failover | primary kill → promote ≤ 60 s; every committed audit row survives, hash-chain-valid, no `seq` gap | async / non-quorum commit on the audit path → a just-committed audit row is lost on the promoted primary |
| Neo4j rebuild | destroy graph → full topology re-projected from Postgres ≤ topology-RTO | a broken/disabled rebuild Job (or a projection-source gap) → topology not restored in budget |
| Worker-kill idempotency | worker-node kill mid-run → jobs complete via retry, **no duplicate side effect** (real PG); Celery success ≥ 99% over the window | remove `acks_late` / idempotency guard → a re-delivered task double-writes |
| Queue-burst (KEDA) | 10× `discovery` depth → scale-out then scale-in, drains within SLO, `config`/`packet`/`docs` not starved | disabled/misconfigured KEDA trigger (or a shared-concurrency cap) → no scale-out, or a starved sibling queue |
| API load (reduced) | p95 held under reduced-scale concurrent load with 2 api replicas; 1→2-replica improvement shown; PgBouncer no connection exhaustion | removed api PDB / a connection-budget regression → p95 breach or connection-exhaustion error |
| Compressed soak | §6 SLOs hold over the compressed window | an injected SLO regression (e.g. an error-rate or latency perturbation) → a burn-rate breach over the window |

The mechanism is enforced in CI plumbing too (P1-W4 **L5**): every piped drill
step uses `set -o pipefail` + `test -s <out>` so a silent mid-pipe failure cannot
read as green; Job/CronJob exec argv that reference env vars wrap them in `sh -c`
(**L3**: K8s does not substitute `$(VAR)` in exec argv).

### 3. The drill catalogue + §11 criteria + target numbers

Each drill maps to a §11 criterion (the contract W4-T3..T8 implement):

| Drill | Gate / §11 line | Target (reduced-scale run) | Implemented by | ADR design |
|---|---|---|---|---|
| **Postgres failover** | G-REL §316 | promote ≤ **60 s**, **zero committed-audit-entry loss** (sync path verified) | W4-T3 (escalated) | ADR-0042 §2/§3/§7 |
| **Neo4j destroy-and-rebuild** | G-REL §317 | topology restored ≤ **measured topology-RTO** (the rebuild time becomes the RTO) | W4-T4 | ADR-0005 §3, ADR-0030 §1 |
| **Worker-kill idempotency** | G-REL §319 | jobs complete via retry, **no duplicate side effect** (real PG) | W4-T5 (escalated) | ADR-0008, ADR-0042 (real-PG) |
| **Celery success rate** | G-REL §320 | **≥ 99%** after retries over the window | W4-T5 | ADR-0008 |
| **Queue-burst isolation** | G-SCA §329 | 10× depth → KEDA scale-out + scale-in within SLO; siblings not starved | W4-T6 | ADR-0043 (KEDA) |
| **Reduced-scale API load** | G-SCA §327/§330 | p95 held; 1→2-replica improvement; **PgBouncer no connection exhaustion** | W4-T6 | ADR-0042 §4, ADR-0043 |
| **Compressed soak** | G-REL §315 (compressed) | §6 SLOs hold over the **compressed** window | W4-T7 | ADR-0046 (SLOs) |
| **N-2 → N upgrade rehearsal** | G-MNT §346 | green on seeded data: expand/contract + rolling order + Neo4j rebuild | W4-T8 | §4 below, §10 |

The **topology-RTO** is *measured*, not asserted against a fixed number: per
ADR-0005 §3 / ADR-0030, the Neo4j rebuild time at the run's scale **becomes** the
topology-RTO; the §8/§317 "< 30 min at the certified scale point" is the
deferred-accepted ceiling (§4), not the reduced-scale bar.

### 4. Named certified-scale ceiling + written promotion path

The §11 numbers below require a real certified-scale cluster and calendar time
that the CI host does not have. They are **deferred-accepted → GA / customer
cluster**, recorded here so the W5 readiness doc can cite a written promotion path
and so no later wave can over-claim "validated at scale" (ADR-0033 §1: named,
never silent). Each names *what hardware* and *what re-run* flips it from the
reduced-scale mechanism PASS to a full certified PASS:

| Deferred ceiling (§11) | Reduced-scale proof we DO ship | What flips it to full PASS (promotion path) |
|---|---|---|
| 500-device discovery ≤ 60 min with autoscale (G-SCA §326) | queue-burst proves KEDA scales `discovery` out/in and drains within SLO at reduced device count | a certified cluster + a 500-device seeded estate; re-run the discovery drill, assert ≤ 60 min with observed scale-out/in |
| 100 concurrent users, p95 < 300 ms, 2→4 replica linearity (G-SCA §327) | reduced-scale load proves p95 holds + a 1→2 replica improvement + no connection exhaustion | a certified cluster sized for 100 users; re-run the load drill at 100 users / 2 + 4 replicas |
| 5,000-device / 100k-interface projection usable, lag SLO held (G-SCA §328) | reduced-scale projection + freshness check; mechanism (scoped queries, no full-graph fetch) verified | a 5,000-device seeded dataset on a sized Neo4j/UI; re-run the projection + render check |
| Neo4j topology-RTO < 30 min @ 5,000 devices (G-REL §317) | rebuild drill proves re-projection succeeds and measures RTO at reduced scale | a 5,000-device dataset; re-run the rebuild drill, assert measured RTO < 30 min |
| 30-day calendar soak meets all §6 SLOs (G-REL §315) | **compressed** soak proves SLOs hold over a compressed window with a planted SLO regression biting | a 30-day staging window on a sized cluster; run the calendar soak, assert §6 SLOs |
| Backups-only DR onto a clean cluster: RPO ≤ 5 min, RTO ≤ 1 h (G-REL §318) | failover (in-cluster HA) bites; ADR-0030 pgBackRest WAL tier exists | a clean target cluster + a backup repository; run the restore-from-backups-alone drill, time RPO/RTO |

These are also the **PROPOSED** targets pending the Consultant scale/HA answers
(§12, re-checked in W0-T9); when answered, the ceiling numbers **re-base** on the
answered values (PRODUCTION.md §324) — a re-base, not a removal of the deferral.

### 5. Real-PG assertion rule

The idempotency, audit-loss, and failover drills assert against **real
PostgreSQL** — the `tests/pg/` layer behind the blocking `pg-integration` job
established in P2 (`P2-RELEASE-READINESS.md`), never SQLite. SQLite hides PG
semantics (sync-commit behaviour, advisory locks, the append-only grant/trigger
posture, partitioned-index and NULLS-ordering rules) that these exact drills
depend on — the recurring P2 review major. The failover drill's audit-survival
check (every committed row present, hash-chain-valid, no `seq` gap — ADR-0042 §2)
is meaningless on SQLite; it runs on the kind CloudNativePG cluster, which **is**
real Postgres.

### 6. N-2 → N upgrade rehearsal procedure (G-MNT §346)

The rehearsal proves a two-release upgrade lands cleanly on a seeded
production-shaped dataset, exercising the §10 upgrade strategy end-to-end:

1. **Seed at N-2.** Bring up the platform at release **N-2** and seed a
   production-shaped dataset (devices, sites, `change_requests`/`approvals`,
   `audit_log` rows with a valid hash chain, `config_snapshots`, a topology
   projection). The seed is the N-2/N-1 fixture the rehearsal upgrades *through*.
2. **Expand migration (Alembic, §289).** Run release **N**'s migrations as the
   Helm **pre-upgrade Job** using **expand/contract**: release N adds
   columns/tables (expand) and N-2/N-1 code must run correctly against the
   expanded schema. The rehearsal asserts the running N-2 pods keep functioning
   against the expanded schema (the rolling-upgrade precondition).
3. **Rolling order (§290).** Apply the §10 order: **migrate DB (expand) → roll
   `worker` per queue with Celery warm shutdown** (finish in-flight tasks, accept
   no new — ADR-0008) → **roll `api`** (≥ 2 replicas keep availability) →
   **frontend**. The rehearsal asserts no dropped in-flight task and continuous
   api availability across the roll.
4. **Post-upgrade Neo4j rebuild (§290).** If the projection schema version
   changed, the post-upgrade rebuild is **triggered automatically** and the
   topology re-projects from Postgres (ADR-0005 §3) — the same mechanism the
   Neo4j rebuild drill (§3) proves, here in the upgrade path.
5. **Audit-chain integrity across the upgrade.** After the upgrade the `audit_log`
   hash chain is still valid with no `seq` gap (ADR-0038) and the append-only
   grant/trigger posture survived the migration (ADR-0030 restore-contract
   discipline applied to upgrade).

**Negative control (per §2):** a deliberately non-expand/contract migration (e.g.
a destructive column drop in the N migration, or skipping the warm shutdown so
in-flight tasks are killed) turns the rehearsal **RED** — proving it bites, not
green-at-setup. The rehearsal runs at **reduced scale** on the seeded fixture and
states it; the "production-shaped" qualifier is about *shape* (the table/relation
mix and a valid chain), not certified row counts.

### 7. Scope boundary

**In:** the drill catalogue + each drill's §11 pass criterion and target number;
the drill-as-test + negative-control rule and its CI-plumbing guards; the
reduced-scale + named-ceiling posture and the explicit promotion path; the
real-PG assertion rule; and the N-2 → N upgrade-rehearsal procedure
(expand/contract, rolling order, post-upgrade rebuild, seeded N-2 dataset).

**Out:** the ephemeral kind topology and its enforcing CNI / gate promotion
(**ADR-0048** + W4-T1/T2); the drills' and the rehearsal's implementation
(W4-T3..T8); the HA controls the drills exercise (ADR-0042/0043/0044, built in
W1/W2); the SLO recording rules / burn-rate alerts the soak leans on (ADR-0046,
W3); and **procuring real certified-scale hardware** (declined for P3, §0 — same
no-hardware posture as M4/M5/P1/P2). Infra/CI policy gates stay green on any
manifests/Jobs these tasks add (named for W4).

## Consequences

**Positive**
- The G-REL live drills and G-SCA mechanisms that P2 deferred are closed **as real
  gates** — each bites on a negative control, so a regression in failover,
  rebuild, idempotency, or autoscale is caught in CI, not in production.
- The N-2 → N rehearsal closes the P2-deferred G-MNT §346 item and protects the
  §10 expand/contract + rolling-upgrade contract on every release.
- Real-PG assertions keep the audit-survival and idempotency proofs honest (the
  semantics SQLite hides are exactly the ones these drills depend on).
- The certified-scale ceiling is **named and carries a written promotion path**,
  so the phase can report an honest "mechanism PASS at reduced scale" and a later
  wave/GA can flip each ceiling with a defined hardware + re-run step — no silent
  over-claim, no silent gap (ADR-0033 §1).

**Negative**
- Reduced-scale runs **do not** certify the §11 scale numbers — that is the
  explicit, named limitation (§4), not a hidden one; GA still owes the
  certified-scale + 30-day-soak runs.
- The harness depends on the kind HA topology (ADR-0048) and an enforcing CNI for
  the related security assertions — an operational dependency made explicit there.
- Negative controls are extra surface to maintain: each planted regression must
  stay representative as the controls evolve, or a drill could silently stop
  biting (the freshness of the negative control is itself a maintenance item).
- A compressed soak can miss slow leaks a 30-day calendar soak would surface;
  this is named in the ceiling (§4) and is why the calendar soak stays
  deferred-accepted rather than claimed.

## Alternatives considered

1. **Procure a real / cloud certified-scale cluster and run the §11 numbers
   directly.** Rejected for P3 (§0): same no-hardware posture as M4/M5/P1/P2. The
   certified-scale numbers are named deferred-accepted → GA with a written
   promotion path (§4) instead of silently dropped or falsely claimed.
2. **Run the drills but skip the negative controls** (assert the happy path only).
   Rejected (§2): a drill with no planted regression can pass green-at-setup
   whether or not the control works — the exact P1-W4 false-green failure. The
   negative control is what makes each drill a gate.
3. **Assert idempotency / audit-loss on SQLite** (the fast unit-suite backend).
   Rejected (§5): SQLite does not reproduce sync-commit, advisory-lock, or
   append-only grant/trigger semantics — the audit-survival check would be
   vacuous. Real PG via `pg-integration` only.
4. **Claim certified scale from the reduced-scale runs** (treat "mechanism bites"
   as "validated at scale"). Rejected — the dominant risk this ADR guards (§0/§1);
   it would violate ADR-0033 §1 named-deferral discipline and mislead the G-SCA /
   G-REL exit verdict.
5. **A single end-to-end "platform soak" instead of per-mechanism drills.**
   Rejected: one monolithic run cannot pinpoint *which* mechanism regressed and is
   hard to give a meaningful negative control. Per-mechanism drills (each with its
   own planted regression) localize failures and map 1:1 to §11 criteria.
6. **Defer the N-2 upgrade rehearsal to GA with the scale numbers.** Rejected: the
   expand/contract + rolling-order + rebuild *mechanism* (§6) is fully provable on
   the seeded kind fixture without certified scale, and G-MNT §346 is an in-scope
   P3 maintainability gate (not a scale gate) — only the row counts, not the
   procedure, are scale-bound.
