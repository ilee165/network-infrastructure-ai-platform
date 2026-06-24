# ADR-0030: Backup and Disaster Recovery Baseline

**Status:** Accepted | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

CLAUDE.md's Production Readiness section requires every iteration to improve **reliability**, and the platform must be "deployable on-premises using Docker or Kubernetes." PRODUCTION.md §8 schedules the **backup/DR baseline** in P1 (drills execute from P2), and P1-PLAN.md §3 W5 assigns it to `wf-infra`. This ADR is the design gate for that baseline: it fixes *what* is backed up, *how*, *to where*, and *how recovery is proven* — without yet running the drills.

The data architecture (ADR-0004 D4, ADR-0005 D5) makes DR asymmetric across our two stateful stores, and that asymmetry is the whole shape of this decision:

- **PostgreSQL is the single system of record** (ADR-0004): inventory, encrypted `device_credentials`, `change_requests`/`approvals`, the append-only `audit_log`, `reasoning_traces`, `config_snapshots`, `normalized_*`, `raw_artifacts`, `pcap_metadata`, `documents`/`embeddings`. Everything the platform "cannot afford to lose" is here, so Postgres backup is the load-bearing DR obligation.
- **Neo4j is a rebuildable projection** (ADR-0005 §3): it "never holds data that exists nowhere else," and a full rebuild (drop graph, re-project from Postgres) "must always succeed and is the recovery story." DR for the graph is therefore **re-projection, not restore of a graph dump** — a deliberate consequence of D5 that this ADR makes operational.
- **pcaps are the most sensitive artifact class** (ADR-0023): packet payloads (cleartext credentials, PII) live on a disk volume with `pcap_metadata` in Postgres and a 30-day tombstone-driven retention. A DR copy of the pcap volume must honor — not subvert — that retention contract.

The two integrity invariants this baseline must not break: (1) **device credentials stay encrypted** end-to-end — a backup is just another place a `device_credentials` row could leak from, and ADR-0011 §1 says "a database dump alone reveals no device credentials" (the KEK is never in the same blast radius); (2) the **append-only `audit_log` (ADR-0011 §2) must survive a restore with its immutability intact** — a restored database must come back with the same `INSERT`/`SELECT`-only grant posture and the same `BEFORE UPDATE OR DELETE` trigger, or the restore has silently re-opened the audit log to tampering.

RPO/RTO targets here are **PROPOSED** defaults (PRODUCTION.md §8, A2/Q2) pending the Consultant Agent's HA/DR answer (§12); §6 below flags them for confirmation.

## Decision

**PostgreSQL is protected by pgBackRest (continuous WAL archiving + full/incremental backups) to a MinIO/S3-compatible object store; Neo4j has no backup — DR is a rebuild-drill job that re-projects from Postgres and re-runs discovery, emitting a topology-RTO metric (per ADR-0005); the pcap volume is snapshotted to the same object store under the ADR-0023 retention contract. The append-only audit log's immutability (grants + trigger) is part of the restore contract and is verified post-restore. The whole baseline is declarative infra (Helm/CronJobs), built in P1; drills execute from P2. PROPOSED targets: RPO ≤ 5 min, RTO ≤ 1 h, topology-RTO < 30 min at 5,000 devices.**

### 1. PostgreSQL — pgBackRest (the load-bearing tier)

Postgres is the only store whose loss is unrecoverable (ADR-0004 §1), so it gets the strongest backup tier. **pgBackRest** (PRODUCTION.md §8) over the native `pg_dump`/`pg_basebackup` path because it gives continuous WAL archiving (PITR), incrementals, parallel/compressed transfer, and a built-in `check`/`verify` that makes the restore drill scriptable.

| Aspect | Decision | Source / rationale |
|---|---|---|
| Backup engine | pgBackRest, sidecar/CronJob against the primary | PRODUCTION.md §8 |
| WAL archiving | Continuous — `archive_command = pgbackrest ... archive-push`; `archive_mode = on` | Gives RPO from "last full" down to "last archived WAL segment" |
| Full / incremental | Full **weekly**, incremental **daily** | PRODUCTION.md §8 table |
| Repository (target) | **MinIO** (S3-compatible) — air-gap-friendly on-prem default; any S3 endpoint accepted via config | PRODUCTION.md §8, §12 (air-gap → MinIO default) |
| Retention | 35 days of fulls+incrementals + monthly fulls kept 1 year (pgBackRest `repo-retention-full`/`-archive`) | PRODUCTION.md §8 table — does **not** override the 7-year `audit_log` *data* retention (PRODUCTION.md §7); audit rows live inside every Postgres backup, so audit data is retained as long as the longest-retained full |
| Encryption | pgBackRest repo encryption **on** (`repo-cipher-type=aes-256-cbc`); repo cipher passphrase is a `credential_ref` from the platform secret store, never inlined | Backups carry encrypted-but-present `device_credentials` rows + audit/PII; the repo must be encrypted at rest independently of MinIO's own SSE |
| Integrity | `pgbackrest verify` after every backup; sha-checksum'd manifest | Restore-drill precondition |
| RPO | **≤ 5 min (PROPOSED)** — continuous WAL archiving + (in P2) streaming replication | PRODUCTION.md §8, G-REL |
| Restore test | Quarterly timed drill, **from P2** | PRODUCTION.md §8, G-REL |

**The backup is not a credential-exposure path.** `device_credentials` are AES-256-GCM envelope-encrypted at the column level (ADR-0011 §1): the backup contains `ciphertext`, `nonce`, `wrapped_dek`, `kek_version` — never plaintext, never the DEK in the clear. Per ADR-0011's posture ("a database dump alone reveals no device credentials"), the **KEK (master key) is never co-located with the backup**: it is KMS/file-provided (ADR-0011 §1 `KeyProvider`) and its own recovery is the separate "Secrets/master key" key-escrow drill (PRODUCTION.md §8), out of pgBackRest's scope. A restored database is useless for device access until the matching `kek_version` is reachable — this is the intended separation of duties, not a gap. Restore-sample credential-leak checks are part of G-SEC ("no plaintext device credential in any … backup sample").

**Audit-log immutability is part of the restore contract (ADR-0011 §2).** `audit_log` is append-only *by database grant* (application role has `INSERT`/`SELECT` only; `UPDATE`/`DELETE` withheld) plus a PROPOSED `BEFORE UPDATE OR DELETE` trigger. A physical pgBackRest restore reproduces table data, grants, and triggers as part of the cluster, so immutability is restored with the data — but this is **asserted, not assumed**: the restore drill (§5) runs a post-restore assertion that (a) the application role still lacks `UPDATE`/`DELETE` on `audit_log`, (b) the guard trigger exists and fires, and (c) the audit row count/`max(id)` is ≥ the pre-incident checkpoint (no truncation). If §5 of PRODUCTION.md ships audit hash-chaining, the chain is re-verified end-to-end post-restore as the strongest immutability check. A restore that comes back with a writable audit log is a **failed** drill, not a successful one.

### 2. Neo4j — no backup; recovery is a rebuild-drill job (per ADR-0005)

ADR-0005 §3 makes rebuildability "a contract, not an aspiration": Neo4j holds no unique data, every node carries its source Postgres key (`pg_id` + `last_projected_at`), and "full-rebuild … must always succeed." DR therefore **does not restore a Neo4j dump** — it **re-projects from Postgres `normalized_*` and re-runs discovery where projection alone is insufficient**. Restoring a stale `neo4j-admin dump` would be strictly worse than rebuilding: it could reintroduce a projection that disagrees with the (just-restored, authoritative) Postgres state, violating D5's "Neo4j never holds data that exists nowhere else."

- **Mechanism:** a `neo4j-rebuild-drill` Job (Helm-shipped, K8s `Job`/Compose one-shot) that (1) drops/recreates the graph, (2) invokes the `engines/topology` full-rebuild path (L2/L3/DNS builders over `normalized_*`, ADR-0005 §2), and (3) **emits a `topology_rebuild_seconds` metric** (the **topology-RTO**, gate G-REL) plus a node/edge count it can assert against the prior projection's counts.
- **Re-run discovery, not just re-project, when needed:** projection assumes `normalized_*` is current. If the DR scenario also lost recent discovery results (RPO window), the drill chains a discovery run (ADR-0007/0008 `discovery` queue) before/with the projection so the rebuilt graph reflects live reality, not a stale snapshot. The metric measures the dominant path (projection at certified scale).
- **Optional dump is a convenience, not the recovery story:** PRODUCTION.md §8 allows a nightly `neo4j-admin dump` "to cut recovery time." We ship it as **opt-in** (off by default to stay true to D5: the projection is disposable). If enabled, it is a *fast-start* that the rebuild drill still validates against — never the authority.
- **Targets:** topology-RTO **< 30 min at 5,000-device scale (PROPOSED, G-REL)**; rebuild drill quarterly (PRODUCTION.md §8), which also validates G-REL's "destroy-and-rebuild" line item.

### 3. pcap volume — snapshot under the ADR-0023 retention contract

pcaps live on a disk volume (`/data/pcaps/{capture_id}.pcap`, ADR-0023 §3) with `pcap_metadata` in Postgres and a 30-day tombstone retention (ADR-0023 §4). DR for this volume is a **daily snapshot/rsync to the same MinIO/S3 object store** (PRODUCTION.md §8), with two hard constraints from ADR-0023:

- **The snapshot honors retention — it does not resurrect purged payloads.** ADR-0023 §4 deletes the file and tombstones the metadata row at expiry; the *audit record that a capture existed and was purged* survives in Postgres (and thus in the Postgres backup), while the *payload* is gone by design. The pcap-volume snapshot job therefore **snapshots only live (non-tombstoned) files and prunes from the object store any snapshot whose `pcap_metadata.tombstoned_at` is set** — otherwise DR would silently re-extend the lifetime of credential/PII-bearing payloads past their retention, defeating ADR-0023's data-minimization. The snapshot retention window is the *shorter* of (object-store policy) and (the pcap's `retention_expires_at`).
- **Restore is metadata-consistent.** A pcap restore re-checks the `sha256` recorded at capture-complete (ADR-0023 §3) against the restored file; a mismatch or a file for a tombstoned row is dropped, so a restored volume never serves a payload the metadata says was purged. A tombstoned capture's download still 404s post-restore (ADR-0023 §5).
- **Access stays gated.** Restored pcaps are reachable only through the existing `engineer`+ audited download path (ADR-0023 §5); object-store ACLs on the pcap prefix are least-privilege (the DR snapshot job's credential is a `credential_ref`, write-to-prefix only).
- **Target:** annual spot-restore (PRODUCTION.md §8) — the lowest-criticality tier, since pcaps are diagnostic artifacts, not system-of-record state.

### 4. Object store, scheduling, and ownership

| Item | Decision |
|---|---|
| Backup target | One MinIO/S3-compatible store, separate buckets/prefixes per tier (`pgbackrest/`, `pcaps/`); **PROPOSED** off-host (ideally off-cluster) so a node/cluster loss doesn't take the backups with it |
| Scheduling | K8s `CronJob`s (Helm-shipped) for pgBackRest full/incr, pcap snapshot, and the Neo4j rebuild drill; Compose parity via host cron / `ofelia`. Celery beat is **not** used — these are infra jobs, not application tasks (keeps DR independent of app/broker health, mirroring ADR-0023's job split rationale) |
| Helm posture | Backup/DR **on by default** in the chart (secure/resilient by default = opt-out, never opt-in — CLAUDE.md, PRODUCTION.md §9); object-store endpoint + credential are required values, supplied as external-secret references (PRODUCTION.md §9), never inlined |
| Owner | `wf-infra` (P1-PLAN.md §2/§3 W5); declarative infra + policy-as-test, not Python-TDD |
| What is **not** separately backed up | Redis (AOF only; broker state expendable — idempotent tasks, ADR-0008/PRODUCTION.md §8), `config_snapshots`/`raw_artifacts` (inside Postgres → covered by §1), Helm values/platform config (in git → single source, PRODUCTION.md §8) |

### 5. Restore drills (designed in P1, executed from P2)

P1 ships the drill *jobs and assertions*; P2 *runs* them (PRODUCTION.md §8, P1-PLAN.md §6). Each drill is policy-as-test (pass/fail, timed), feeding gate G-REL (PRODUCTION.md §11):

1. **Postgres PITR drill (quarterly):** restore the latest full + WAL to a clean instance; assert (a) RPO ≤ 5 min (WAL replay reaches within-window), (b) audit-log immutability re-asserted (grants + trigger + no-truncation, §1), (c) a credential row decrypts **only** with the matching KEK and **fails closed** without it (separation proof), (d) `pgbackrest verify` clean.
2. **Neo4j destroy-and-rebuild drill (quarterly):** wipe the graph, run the rebuild job, assert `topology_rebuild_seconds` < topology-RTO and node/edge counts match the pre-wipe projection (§2). This is the same job that runs the G-REL topology-RTO line.
3. **Full-platform DR drill (≥ twice yearly, from P2):** restore Postgres from object storage **alone** onto a clean cluster, rebuild Neo4j from the restored Postgres, spot-restore pcaps; assert end-to-end **RPO ≤ 5 min and RTO ≤ 1 h (PROPOSED)** — the G-REL "DR drill from backups alone" gate.
4. **pcap spot-restore (annual):** restore a sampled live capture, sha256-match it, confirm a tombstoned capture is *not* resurrected (§3).

The DR runbook for all four is generated and kept current by the Documentation Agent (PRODUCTION.md §8, dogfooding).

### 6. Targets are PROPOSED — Consultant confirmation required

RPO ≤ 5 min, RTO ≤ 1 h, and topology-RTO < 30 min at 5,000 devices are **PROPOSED** defaults (PRODUCTION.md §8 A2/Q2, §12 "HA/DR expectations"). They drive backup frequency (§1), the WAL-archiving cadence, and the certified scale point for the rebuild drill (§2). Per CLAUDE.md's Consultant principle ("do not assume"), these are flagged for confirmation at the §12 Consultant review; the baseline is sized to the defaults and re-bases on the answered numbers (PRODUCTION.md §11 G-REL: "PROPOSED targets per A2/Q2 until Consultant answer"). The object-store choice (MinIO vs. customer S3) is similarly bound to the §12 "air-gapped operation" answer.

## Consequences

**Positive**

- One backup story for everything that matters: because Postgres is the sole system of record (ADR-0004), pgBackRest of Postgres + the disposable-Neo4j contract (ADR-0005) means there is exactly **one** authoritative thing to restore and one thing to rebuild — no dual-master DR coordination.
- Restoring the database restores audit history *and its immutability* (grants + trigger travel with the cluster), and the drill **proves** it rather than trusting it — a credible answer to an enterprise security/audit review (ADR-0011, G-SEC).
- Backups never widen the credential blast radius: encrypted-at-column credentials plus a KEK held outside the backup repo mean a stolen backup yields no device access (ADR-0011 §1), validated by the G-SEC restore-sample leak check.
- The Neo4j topology-RTO is a *measured* number emitted by the rebuild drill, turning ADR-0005's "rebuildable" claim into a gate-checkable metric (G-REL) instead of an assertion.
- pcap DR respects retention: the snapshot/restore path cannot resurrect a purged payload, so DR does not become a loophole around ADR-0023's data-minimization and audit-tombstone contract.

**Negative**

- DR correctness now depends on the **rebuild path actually working at scale** (ADR-0005's incremental-vs-full-rebuild negative): if `normalized_*` is incomplete, the rebuilt graph is incomplete, so the Neo4j drill is really a test of the projection pipeline, and a slow rebuild on a large estate directly threatens the topology-RTO gate.
- Two integrity invariants (audit immutability, credential separation) must be re-asserted on **every** restore, adding post-restore verification steps that a naive `pg_restore` would skip — operationally heavier, but the alternative (a restore that silently re-opens the audit log) is unacceptable.
- The PROPOSED RPO/RTO numbers gate work that cannot be fully closed until the Consultant answers (§6); P1 builds to the defaults and may need re-sizing in P2, and full HA (streaming replication that tightens RPO) is explicitly P2 (PRODUCTION.md §3) — P1's RPO floor is the WAL-archive interval, not replication lag.
- A single off-host object store is itself a dependency; if it is mis-configured (wrong retention, missing encryption, reachable credential) it becomes a new exfiltration surface for audit/PII/pcap data — mitigated by repo encryption, least-privilege prefixes, and external-secret references (§1, §3, §4), but it is real surface the §5 drills must exercise.

## Alternatives considered

1. **`pg_dump`/`pg_basebackup` cron instead of pgBackRest.** Rejected: logical dumps give no PITR (RPO becomes "since last nightly dump," blowing the ≤ 5 min target), no incrementals (full-size transfer daily), and no built-in `verify`. pgBackRest's WAL archiving is what makes RPO ≤ 5 min and a scriptable, timed restore drill (G-REL) feasible — chosen.

2. **Back up Neo4j with nightly `neo4j-admin dump` and restore it on DR (treat the graph as restorable state).** Rejected as a contradiction of ADR-0005 D5: Neo4j "never holds data that exists nowhere else," so a graph dump is by definition redundant with Postgres, and restoring a *stale* dump after a Postgres restore could reintroduce a projection that disagrees with the authoritative store. Re-projection from the just-restored Postgres is the only consistent recovery; the dump is kept only as an **opt-in** fast-start that the rebuild drill must still validate (§2) — chosen posture.

3. **Encrypt backups only via the object store's server-side encryption (SSE), skip pgBackRest repo encryption.** Rejected: SSE protects bytes at rest in MinIO/S3 but leaves the backup unencrypted in transit to/from the repo and trusts the object store's key management with audit/PII/credential-bearing data. ADR-0011's separation posture wants the backup encrypted *independently* of the storage layer; pgBackRest `aes-256-cbc` repo encryption with a `credential_ref` passphrase gives that and is layered *with* (not instead of) any SSE — chosen.

4. **Include the platform master key (KEK) in the backup so a restore is immediately usable for device access.** Rejected outright: co-locating the KEK with the encrypted `device_credentials` it unwraps collapses ADR-0011's whole separation-of-duties model — a single stolen backup would then yield every device credential, the exact failure ADR-0011 §1 prevents. The KEK stays KMS/file-provided with its own escrow drill (PRODUCTION.md §8); a restored DB being inert for device access until the KEK is reachable is the **intended** safety property, not a defect.

5. **Run all DR jobs on Celery beat (reuse the app's scheduler).** Rejected: DR must survive the failure of the very app/broker it protects. Scheduling backups on Celery (Redis broker) couples DR liveness to Redis and the worker fleet — if those are degraded, backups silently stop right when you most need them. Plain K8s `CronJob`s (Compose: host cron) keep the backup/rebuild/snapshot jobs independent of application health, mirroring ADR-0023's deliberate split of the retention job from credential-bearing paths — chosen.
