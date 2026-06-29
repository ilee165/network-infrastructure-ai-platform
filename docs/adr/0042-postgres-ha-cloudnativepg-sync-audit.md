# ADR-0042: Postgres HA — CloudNativePG (1 primary + 2 replicas) + PgBouncer + Synchronous Audit Write Path

**Status:** Proposed | **Date:** 2026-06-29 | **Milestone:** P3 W0

## Context

`PRODUCTION.md` §3 schedules HA/scale-out for **P3-Platform**, and §3.2 names
PostgreSQL the **strongest HA tier** because it is the single system of record
(ADR-0004): inventory, encrypted `device_credentials`, `change_requests`/`approvals`,
the append-only **`audit_log`**, `reasoning_traces`, `config_snapshots`,
`documents`/`embeddings`. Everything the platform "cannot afford to lose" lives here.
Today Postgres is a single instance (ADR-0004); a primary loss is an outage and —
worse — risks losing the most recently committed **audit** rows, which §11 G-REL
forbids.

This ADR is the **design gate**. It ratifies the Postgres HA design the build
implements in **W1-T1** (CloudNativePG `Cluster` + PgBouncer + quorum config, render
/ policy gates), **W1-T2** (app-side per-transaction sync-commit on the
audit-writing transaction, real PG), and
the live **W4-T3** failover drill (primary kill → promote ≤ 60 s, zero committed-audit
loss). It does **not** implement those controls. The audit log is the integrity root
(ADR-0011 §2, ADR-0038), so the synchronous audit write path is a **secret-surface /
audit-spine decision** (strong review).

Bounded by **ADR-0004** (Postgres + pgvector system of record), **ADR-0029** (K8s/Helm
GA chart + hardening baseline), **ADR-0030** (backup/DR baseline — pgBackRest WAL
archiving, the complementary recovery tier), and **ADR-0038** (audit hash-chain — the
in-DB tamper-evidence this durability path protects). PRODUCTION.md §3.1/§3.2, §8,
§11 G-REL §316 / G-SCA §330 are the line-by-line source.

The §1 (2026-06-25) re-scope moved the live failover/soak/scale drills out of
P2-Security into P3-Platform because they need a real platform stack to validate;
this ADR is the data-tier half of that move. Per `P3-PLATFORM-PLAN.md` §0, the
*mechanism* is proven to bite at **reduced scale** on an ephemeral HA kind cluster
(W4-T1/T3); the **certified-scale** numbers (500-device discovery, 100 concurrent
users, 5,000-device projection, 30-day soak) are **named deferred-accepted → GA /
customer cluster**, never silently claimed.

## Decision

**PostgreSQL runs under the CloudNativePG operator as 1 primary + 2 streaming
replicas with automated failover; PgBouncer (transaction-mode) fronts every
connection; the `audit_log` write path commits with quorum-based synchronous
replication so a promoted replica holds every committed audit row; pgvector is
available and queryable on replicas. Patroni is the named no-operator fallback;
certified-scale sizing is named deferred-accepted. Synchronous commit is scoped to
the audit path: it is set per-transaction on the transaction that appends an
`audit_log` row, so only transactions that write audit (state-changing audited
actions) pay the synchronous round-trip; transactions with no audit write keep the
default async commit. Because an audit append rides in the caller's action
transaction (atomic with the action — ADR-0011/0038), making that transaction
synchronous makes the whole action+audit commit synchronous; that is deliberate, not
a defect, and is the price of preserving action↔audit atomicity.**

### 1. Operator: CloudNativePG (primary); Patroni (named fallback)

The HA tier uses the **CloudNativePG** operator (PRODUCTION.md §3.1/§3.2): a Postgres
16 `Cluster` of **3 instances** (1 primary + 2 streaming replicas), operator-managed
streaming replication, automated primary election/promotion, declarative
`Cluster`/`Pooler` CRDs that render into the ADR-0029 Helm chart, and a clean fit with
the ADR-0030 pgBackRest WAL-archiving recovery tier. Replication and superuser
secrets are reused-or-generated via Helm `lookup` (empty in CI, reused on upgrade,
never regenerated — P1-W4 **L4**); a regen would sever every live connection.

**If no operator is permitted** in the customer cluster, the named fallback is
**Patroni** + a streaming-replication StatefulSet (PRODUCTION.md §3.2 "Alternative if
no operator allowed: Patroni"). It delivers the same 1+2 + automated-failover +
quorum-sync shape with more operational surface (etcd/Consul DCS, more bespoke
manifests). This is recorded so the operator choice is **explicit, not a silent
default** — switching is a superseding-ADR change (G-MNT, no silent drift).

Neo4j HA is **out of this ADR** (single instance + automated rebuild, D5 / §3.2 —
ADR design owned by W1-T3); Redis HA is **out** (Sentinel, ADR-0044). This ADR is the
Postgres tier only.

### 2. Synchronous (quorum) commit on the audit write path — the load-bearing decision

The §11 G-REL §316 requirement is **"zero committed-audit-entry loss (synchronous
audit path verified)"** on a primary kill. Asynchronous streaming replication can
acknowledge a commit on the primary before the WAL reaches any replica, so a primary
crash in that window loses the just-committed row — unacceptable for the audit spine.

**Quorum synchronous replication on the audit commit only:**

- The cluster sets quorum-based synchronous standbys — `synchronous_commit =
  remote_apply` (or `on`) with **`ANY 1 (<2 replicas>)`** quorum
  (`synchronous_standby_names`), so a commit is acknowledged only once **at least one
  replica** has the WAL durably (the W1-T1 CNPG `synchronous` config; CloudNativePG
  expresses this via its synchronous-replication settings). On a primary kill the
  operator promotes a replica that, by the quorum guarantee, already holds every
  acknowledged audit row.
- **Scoped to the audit-writing transaction, not all writes — and the existing
  session model is what makes this scoping real.** There is **no dedicated
  audit-write session and no single audit-writer process**: `audit_service.record()`
  (`backend/app/services/audit/service.py`) takes the **caller's** `AsyncSession`,
  appends a single `audit_log` INSERT and **flushes but never commits — the caller
  owns the transaction**, so the audit row commits or rolls back atomically with the
  action it describes (ADR-0011 §2, ADR-0038; ~25 call sites — `auth.py:193`,
  `workers/tasks/discovery.py:702`, `engines/config_mgmt/capture.py:234`,
  `agents/automation/agent.py:316`, etc. — each pass their own action session and
  commit it). The only serialization on the append is a **transaction-scoped advisory
  lock on the hash-chain head** (`_current_chain_head`), not a single writer session.
  Because the audit append therefore rides inside the caller's action transaction,
  W1-T2 sets `synchronous_commit` **per-transaction** (`SET LOCAL`, §4) at the point
  `record()` participates, which makes **the enclosing action transaction**
  synchronous — the audit INSERT cannot be made synchronous in isolation without
  splitting it onto a separate session/transaction, which would break the
  action↔audit atomicity ADR-0011/0038 require. This is the intended coupling: the
  synchronous round-trip lands on transactions that contain an audited state change
  (already gated by the ChangeRequest lifecycle), while the high-volume
  discovery/config/telemetry writes that emit no audit row keep the default async
  commit.

  *Implementation note / W1-T2 boundary:* the scoping unit is **"transactions that
  write audit," not "the audit row alone."** A transaction that writes an audit row
  alongside a large bulk mutation will make that whole mutation synchronous too; if a
  future caller needs a bulk write to stay async while still auditing, it must emit
  the audit append on a **separate** committed transaction and explicitly accept the
  loss of action↔audit atomicity — a superseding decision, not the default. W1-T2
  owns this trade-off and documents it where it sets `SET LOCAL`.
- **It composes with the ADR-0038 hash chain.** The hash-chain append runs **inside
  the same caller transaction that carries the `SET LOCAL synchronous_commit`**, so a
  row that is acknowledged is both chain-linked and replicated. The W4-T3 survival
  check is exactly: every audit row
  committed before the kill is present and **hash-chain-valid with no `seq` gap** on
  the promoted primary.

**Latency trade-off (stated, per §11 G-REL risk):** synchronous commit adds **one
primary↔replica WAL round-trip** to each audit append (single-digit to low-tens of
ms intra-cluster, dominated by the replica link). Because it is scoped to the audit
path, the cost lands only on state-changing audited actions (already gated by the
ChangeRequest lifecycle), not on read or bulk-ingest paths. **Availability trade-off:**
`ANY 1 (...)` (not `ANY 2`/`FIRST`) means audit commits keep succeeding while **at
least one** replica is healthy — a single replica loss does not stall the audit path,
and the quorum still guarantees the survivor holds the row. Requiring all standbys
would convert a single replica outage into an audit-write outage; that is rejected
here.

### 3. Automatic failover — primary kill → promote, write service ≤ 60 s

On primary loss the **CloudNativePG operator promotes a replica automatically — no
manual step** (PRODUCTION.md §3.2 "automated failover"; §11 G-REL §316). The drill
(W4-T3) measures **from the kill to write-service restored** and asserts **≤ 60 s**
(the §316 RTO). PgBouncer (§4) re-points to the new primary via the operator-managed
read-write service endpoint, so applications reconnect through the pooler without
config change. This sits **above** the ADR-0030 pgBackRest tier: streaming
replication + promotion is the in-cluster HA recovery (seconds); pgBackRest PITR is
the out-of-cluster DR recovery (the §8 RPO ≤ 5 min / RTO ≤ 1 h targets for a
backups-only clean-cluster restore). The two are complementary, not redundant.

### 4. PgBouncer — transaction-mode pooling + connection budget

A **PgBouncer** pooler (CloudNativePG `Pooler`, transaction mode) fronts every
connection (PRODUCTION.md §3.1/§3.2). **Transaction mode** is the default because the
scaled-out tier — ≥2 `api` replicas (HPA) plus per-queue KEDA-scaled workers
(ADR-0043) — opens far more client connections than Postgres can hold as backends;
transaction-mode pooling multiplexes many short transactions onto a small server-side
pool, which is the **connection-budget rationale W4-T6 asserts (G-SCA §330: "Postgres
connection budget holds under [queue-burst + load] via PgBouncer — no
connection-exhaustion errors")**.

Transaction mode constrains the app (W1-T2): **no session-pinned features that
PgBouncer cannot carry across a pooled transaction** — no reliance on session-level
`SET` that must persist beyond a transaction, and a documented prepared-statement
caveat (use protocol-level handling compatible with transaction pooling). The
`synchronous_commit` setting for the audit write **must** be applied in a
transaction-mode-safe way — per-transaction `SET LOCAL` on the caller transaction
that appends the audit row (§2), **not** a session `SET` that pooling would drop.
`SET LOCAL` is in fact the only correct mechanism here for two reasons: it survives
transaction-mode pooling, and (because the audit row commits in the caller's action
transaction, §2) it correctly scopes the synchronous round-trip to exactly the
audit-writing transaction without leaking onto subsequent pooled transactions that
share the same backend. W1-T2 owns this and tests it on real PG.

### 5. pgvector on replicas — read scale-out must not break embedding reads

The system of record carries `documents`/`embeddings` for RAG (ADR-0004, ADR-0019).
With read traffic routed to replicas, the **pgvector extension must be present and
queryable on every replica** — a streaming replica inherits installed extensions, but
this is **verified, not assumed**: W1-T1 ships a **pgvector-on-replica smoke** (an
embedding/similarity query succeeds against a replica), exercised on the W4-T1 kind
bring-up or a rendered emulation where kind is unavailable locally (stated; P1-W4
**L1**). If pgvector were missing on a replica, RAG reads routed there would fail —
this check is the guard.

### 6. RTO / RPO targets recorded (for the W4-T3 contract)

| Target | Value | Source |
|---|---|---|
| Audit RPO on primary kill | **0 committed-audit-row loss** (sync-quorum path) | §11 G-REL §316 |
| Write-service RTO on failover | **≤ 60 s** (kill → write restored, automated) | §11 G-REL §316 |
| Platform RPO (backups-only DR) | ≤ 5 min (WAL archiving, ADR-0030) — PROPOSED | §8 (A2/Q2) |
| Platform RTO (backups-only DR) | ≤ 1 h full platform — PROPOSED | §8 (A2/Q2) |

The PROPOSED §8 platform RPO/RTO are pending the Consultant HA/DR answer (§12,
re-checked in W0-T9); the audit-RPO (zero) and failover-RTO (≤ 60 s) are firm G-REL
§316 criteria this design must meet.

### 7. Build-task contract — the assertions this ADR pins

So the build tasks have a testable contract (the ADR is the design; the gates are the
proof):

- **W1-T1** (`wf-infra`, render/policy): CloudNativePG 1+2 + PgBouncer (transaction
  mode) render and pass infra policy gates (`helm lint`, `helm template | kubeconform
  -strict`, kube-linter, conftest); **render-twice stable** (no secret regen, **L4**);
  quorum sync config present on the audit write path; pgvector-on-replica smoke
  passes.
- **W1-T2** (`wf-implementer`, escalated): the **caller transaction that appends an
  `audit_log` row** issues `SET LOCAL synchronous_commit` (= `remote_apply`/`on`) per
  this ADR — applied at the point `audit_service.record()` participates, **not** on a
  separate "audit session" (none exists; §2), and **asserted on real PG**
  (`tests/pg/`, `pg-integration` job — never SQLite, P2 lesson). The test must prove
  (a) a transaction that appends audit commits synchronously (the durability
  guarantee) and (b) a transaction with **no** audit write keeps the default async
  commit (the scoping guarantee), and must document that the synchronous mode covers
  the **whole** audit-writing transaction, preserving the action↔audit atomicity of
  ADR-0011/0038. The app routes through PgBouncer with no pooling-incompatible
  feature; read/write routing per §4/§5; redaction + hash-chain unchanged.
- **W4-T3** (`wf-reliability`, escalated): live on the W4-T1 kind cluster — primary
  kill → **automated promotion, write service ≤ 60 s**; **every committed audit row
  survives on the promoted primary, hash-chain-valid, no `seq` gap**; a **negative
  control** (async / non-quorum commit) loses a row → assertion **red**, proving the
  drill bites (P1-W4: a gate must RUN and BITE). Reduced scale, stated; **L5**
  pipefail + `test -s` on the drill pipeline.

### 8. Scope boundary

**In:** the Postgres HA design — operator choice + fallback, replica count, PgBouncer
mode + connection-budget rationale, which writes are synchronous (audit only),
quorum/`synchronous_standby_names` shape, pgvector-on-replica verification, and the
failover RTO / audit-RPO targets. **Out:** the implementation (W1-T1/T2), the live
failover drill (W4-T3), certified-scale sizing (named deferred-accepted, §0),
cloud-managed Postgres (self-hosted only, D-series / ADR-0004), and Neo4j/Redis HA
(D5 rebuild / ADR-0044). Infra policy gates stay green on the new manifests
(named for W1-T1).

## Consequences

**Positive**
- A committed audit entry survives a primary loss — the §11 G-REL §316 "zero
  committed-audit-entry loss" guarantee, the audit-spine reason this ADR exists.
- Automated promotion restores write service ≤ 60 s with no operator action; the data
  tier stops being a single point of failure.
- PgBouncer transaction-mode pooling holds the connection budget under the scaled-out
  api/worker tiers (G-SCA §330), keeping Postgres from connection exhaustion.
- Scoping sync per-transaction (set on the transaction that appends an audit row, §2)
  keeps durability where mandatory without taxing the high-volume
  discovery/config/telemetry transactions that emit no audit row, which keep the
  default async commit.
- Read scale-out (replica reads, pgvector verified) offloads the primary without
  breaking RAG reads.

**Negative**
- Synchronous commit adds a primary↔replica WAL round-trip to every audit append
  (§2) — bounded by scoping it to the audit-writing transaction and quorum `ANY 1`
  (one healthy replica suffices).
- **The synchronous round-trip lands on the whole audit-writing transaction, not the
  audit INSERT alone (stated coupling, §2).** Because the audit row commits inside the
  caller's action transaction (atomic with the action — ADR-0011/0038), `SET LOCAL
  synchronous_commit` on that transaction makes the **entire** login/config/discovery
  transaction synchronous, not just its audit INSERT. The audit row cannot be made
  synchronous in isolation without splitting it onto its own session/transaction,
  which would break the existing action↔audit atomicity. This is accepted, not
  hidden: the cost is bounded because audited state changes are already gated by the
  ChangeRequest lifecycle and are low-volume relative to bulk ingest; a future caller
  that needs a bulk audited write to stay async must explicitly trade away atomicity
  on a separate transaction (§2 implementation note) — a superseding decision.
- The CloudNativePG operator is an operational dependency (CRDs, controller upgrades);
  the Patroni fallback (§1) is heavier still — recorded so the choice is explicit.
- A misconfigured quorum (sync on all writes, or `ANY 2`/`FIRST` requiring every
  standby) either collapses throughput or turns a single replica loss into an
  audit-write outage; §2 fixes the shape (`ANY 1`, audit-only) and W1-T1/W4-T3 assert
  it — the over-scoping risk the spec calls out.
- pgvector-on-replica is assumed-inherited but **must be verified** (§5); a silent
  miss breaks RAG reads routed to a replica — W1-T1's smoke is the guard.

## Alternatives considered

1. **Single instance + pgBackRest restore only (status quo, ADR-0030).** Rejected for
   P3: restore-from-backup cannot meet the ≤ 60 s failover RTO and **loses the audit
   rows since the last archived WAL** — it violates G-REL §316 zero-audit-loss.
   pgBackRest stays as the complementary out-of-cluster DR tier (§3), not the HA tier.
2. **Asynchronous replication for all writes (including audit).** Rejected: an async
   commit is acknowledged before the WAL reaches any replica, so a primary crash loses
   the just-committed audit row — the exact failure G-REL §316 forbids. Async is kept
   for **non-audit** writes only.
3. **Synchronous commit on ALL writes.** Rejected (spec risk + §2): a WAL round-trip
   on every discovery/config/telemetry write collapses throughput for no audit-spine
   benefit. Sync is scoped per-transaction to the transactions that append an audit
   row (§2), which keeps it off transactions that emit no audit row.
4. **`ANY 2` / `FIRST 2` (all standbys must ack).** Rejected: turns a single replica
   outage into an audit-write stall. `ANY 1` keeps the durability guarantee (the
   survivor holds the row) while tolerating one replica loss.
5. **Patroni as the primary operator.** Considered and recorded as the **named
   no-operator fallback** (§1), not the default: more operational surface (external
   DCS, bespoke manifests) than CloudNativePG's declarative CRDs for the same 1+2 +
   quorum-sync shape (PRODUCTION.md §3.2).
6. **Cloud-managed Postgres (RDS/Cloud SQL/Azure DB) with built-in HA.** Rejected for
   P3: the platform is **self-hosted / local-first** (CLAUDE.md, ADR-0004 D-series);
   managed PG is a customer-cloud option, not the shipped design.
7. **Neo4j-style "rebuild from source" for Postgres HA.** Not applicable: Postgres is
   the *source* of record (ADR-0004) — there is nothing to rebuild it from, which is
   precisely why it gets the strongest HA tier (§3.2).
