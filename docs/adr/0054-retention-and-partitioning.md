# ADR 0054: Retention and Partitioning Policy

- **Status:** Proposed
- **Date:** 2026-07-16
- **Decision owners:** Platform Architecture, Security, and SRE

## Context

The platform stores operational records with different durability, legal, and
performance needs. Four high-volume PostgreSQL tables are partitioned:
`audit_log`, `raw_artifacts`, `reasoning_traces`, and
`reasoning_trace_steps`. Other operational tables remain unpartitioned. A
single undifferentiated retention interval would either discard evidence too
early or retain expensive data indefinitely.

Retention must also preserve the audit hash chain. Deleting an arbitrary audit
prefix without recording its terminal chain state makes the first retained row
impossible to verify. Export and deletion therefore form one controlled
operation, not independent maintenance jobs.

Two existing mechanisms are not sufficient for this policy. First,
`audit_chain_checkpoint` is a mutable singleton verification watermark whose
referenced audit row must still exist; it is not immutable prune history.
Second, the daily raw-artifact task hard-deletes rows selected by
`raw_artifact_retention_days` without archival. That legacy path conflicts
with the archive-before-delete decision below and must be replaced before this
policy is effective.

## Decision

Retention is configured by table class. The following values are initial
defaults; deployments may increase them to satisfy local policy, but may not
reduce audit retention below the documented security baseline without an
approved policy exception.

| Table class | Tables | Retention anchor | Hot window | Archive window | PostgreSQL action at hot cutoff | Archive action at archive cutoff |
| --- | --- | --- | ---: | ---: | --- | --- |
| Audit evidence | `audit_log` | Age by `created_at`; prune boundary by contiguous `seq` prefix | 90 days | 7 years | Archive and receipt-verify one contiguous chain prefix, append its signed prune checkpoint, then row-prune that exact prefix; drop a complete partition only when it contains no row outside the prefix. | Delete archive objects only after the seven-year cutoff and legal-hold/policy checks. |
| Raw evidence | `raw_artifacts` | `created_at` | 30 days | 1 year | Archive every eligible row and verify the immutable manifest before dropping a complete eligible partition. | Delete archive objects only after the one-year cutoff and legal-hold/policy checks. |
| Reasoning records | `reasoning_traces`, `reasoning_trace_steps` | The parent trace's non-NULL `completed_at` for the entire trace family | 90 days | 1 year | Archive each completed trace family across all partitions; drop a partition only when every row and cross-partition companion is eligible and archived, otherwise defer or row-prune eligible families. | Delete the complete archived trace family only after the one-year cutoff and legal-hold/policy checks. |
| Discovery snapshots | `topology_snapshots` | `created_at` | 180 days | 1 year | Archive snapshots with discovery-run identifiers, verify the manifest, then row-prune eligible snapshots in deterministic batches. | Delete archive objects only after the one-year cutoff and legal-hold/policy checks. |
| Configuration snapshots | `config_snapshots` | `captured_at` when never approved; otherwise the most recent closed baseline tenure's `superseded_at` | 180 days | 1 year | Archive and verify eligible versions, then row-prune them in deterministic batches. Any snapshot with an open baseline tenure is ineligible. | Delete archive objects only after the one-year cutoff and legal-hold/policy checks. |

The **hot window** is PostgreSQL residence measured from the exact anchor in
the matrix. At its cutoff the service archives and verifies the eligible data,
then removes it from PostgreSQL. The **archive window** is immutable external
archive residence measured from that same anchor. At its cutoff the archive
object may be deleted only when no legal hold or policy exception extends it.
Failure to obtain archive proof leaves the PostgreSQL data in place. A trace
with NULL `completed_at` never becomes eligible. Configuration baseline
approval/supersession is recorded in an append-only tenure table. An open
tenure makes the snapshot ineligible; re-promotion opens a new tenure, and a
later supersession resets the anchor to that newest closed tenure rather than
reusing an older timestamp.

Partition boundaries are calendar-month UTC boundaries. A partition may be
dropped only when it is wholly outside the hot window and every contained row
is eligible and covered by a verified archive receipt. The external archive
then remains until its separate archive cutoff. For `audit_log` this condition
is necessary but not sufficient: the sequence-prefix rules below also apply,
and a partition containing a retained or legacy NULL-`seq` row cannot be
dropped.

Reasoning eligibility is keyed by trace identity and `completed_at`, not by
matching partition suffixes. Trace and step rows partition independently on
their own `created_at`, steps have no database foreign key to traces, and a
trace can span months. The service must enumerate and archive every step for
an eligible completed trace across all partitions before deleting any member.
If a partition also contains an ineligible or incompletely archived family,
the service defers the drop or uses bounded row cleanup for eligible families.

### Unpartitioned snapshot trade-off

`topology_snapshots` and `config_snapshots` remain unpartitioned initially.
Their foreign-key, uniqueness, and current-baseline semantics make a direct
partition conversion more invasive than bounded row pruning, while their
expected volume is lower than raw artifacts and reasoning records. The
retention service therefore prunes them in deterministic primary-key batches
with a time budget and vacuum-aware pacing.

The implementation must measure row count, prune duration, dead-tuple ratio,
and lock wait time. A follow-up ADR and migration may introduce time
partitioning if a retention cycle cannot stay within its configured time
budget or routinely creates unacceptable vacuum/lock pressure. It must retain
the one-snapshot-per-run and one-current-baseline invariants.

### Audit-chain continuity

The current `audit_chain_checkpoint` remains the mutable incremental-verifier
watermark. A follow-up migration adds a separate append-only
`audit_prune_checkpoints` ledger; destructive pruning is disabled until the
schema and verifier understand both roles.

Audit age and audit deletion order are deliberately different dimensions.
`created_at` is assigned by application instances and selects the monthly
partition, while `seq` is assigned under the deployment-wide append lock and
is the authoritative chain order. Clock skew or an out-of-order timestamp can
therefore put a later sequence in an older partition, or an earlier sequence
in a newer partition. Calendar age alone must never choose the checkpoint or
deletion range.

Each prune starts immediately after the newest trusted prune checkpoint (or at
`seq = 1` when none exists) and walks retained rows in ascending `seq`. It
stops at the first row that is inside the hot window, under legal hold, not
receipt-verified in the exact archive range, or otherwise ineligible. Only the
dense range before that stop is the candidate prefix. The final locked
transaction must prove that the candidate has no missing/duplicate sequence,
that its first sequence follows the prior checkpoint, and that the first
retained row immediately follows its terminal sequence and names that terminal
hash as `prev_hash`. A later old-timestamp row may not be skipped past an
earlier ineligible sequence merely because its calendar partition is old.

The transaction removes every row in that exact prefix and no chained row
after it. It may drop a whole `audit_log` partition only when every row in the
partition belongs to the prefix and is receipt-covered; a retained row or a
legacy NULL-`seq` row forces the partition to remain. When clock skew spreads
the prefix across mixed partitions, the service uses bounded row deletion for
the prefix and defers partition drops until the affected partitions become
empty and independently eligible. This may reduce partition-drop efficiency,
but it cannot create an internal chain hole.

Before pruning an audit prefix, the maintenance process appends a signed prune
checkpoint containing:

- chain key plus the dropped range's first/last sequence, identifiers, and
  timestamps;
- the range's terminal hash and the first retained row's sequence, identifier,
  timestamp, hash, and expected predecessor hash;
- immutable archive object identifier, manifest SHA-256 digest, receipt
  identifier, and covered sequence range;
- retention policy version, actor, operation identifier, and completion time;
- signature algorithm and signing-key identifier. The signature is stored
  alongside, but is not part of, the unsigned payload.

The unsigned payload is RFC 8785 canonical JSON over every field above except
`signature`, encoded as UTF-8 and signed with Ed25519. Hashes and SHA-256
digests use lowercase hexadecimal; the Ed25519 signature uses unpadded
base64url; sequence values remain JSON integers; UUIDs use lowercase canonical
8-4-4-4-12 hyphenated text; and timestamps use UTC RFC 3339 with exactly six
fractional digits and a trailing `Z` (for example,
`2026-07-16T12:34:56.123456Z`). Chain/string identifiers are Unicode NFC
before JSON encoding. Algorithm and key identifier are inside the signed
payload. The exact canonical unsigned bytes are stored with the parsed fields;
a verifier must re-canonicalize them and reject any mismatch before signature
verification. The private key is secret/KMS backed. Each checkpoint records
its key identifier; rotation affects only new checkpoints, and old public
verification keys remain available for at least the longest archive window.
Checkpoints are never re-signed during rotation.

Verification of retained audit history starts from the newest trusted
prune checkpoint and treats its terminal hash as the signed virtual
predecessor of the first retained row. Full verification first validates each
archived segment's manifest, receipt, signature, sequence continuity, and hash
chain, then continues through retained rows. Incremental verification rebuilds
or resets the mutable `audit_chain_checkpoint` under the same lock so it
references only a retained row; it may never retain an identifier that the
prune will delete. Checkpoints are archived and retained at least as long as
the audit archive. Any identity, sequence, predecessor, digest, receipt, key,
or signature mismatch aborts pruning.

Archive upload, durable receipt, and authenticated readback occur before the
database mutation. After those external proofs exist, checkpoint insertion,
mutable-watermark reset/rebuild, final eligibility/chain recheck, and partition
drop or row deletion execute in **one PostgreSQL transaction under the same
transaction-scoped advisory lock**. The prune checkpoint becomes visible only
when that transaction commits; rollback exposes neither a trusted checkpoint
nor a partial deletion. A prepared checkpoint may be stored outside this
transaction only if it has an explicit non-trusted state, and verification may
use only a checkpoint atomically finalized with the corresponding deletion.

### Export prerequisite and concurrency

Current SIEM delivery is necessary but insufficient deletion proof. Syslog and
CEF success establishes only local socket drain, and current HTTPS handling
accepts a 2xx without retaining response metadata. A qualifying archive sink
must instead durably acknowledge the exact manifest digest and covered range,
return a stable receipt identifier, and support authenticated readback of the
manifest/object. A separate immutable archive sink is the default; HTTPS may
qualify only after its contract supplies those guarantees. Syslog/CEF alone
can never authorize deletion.

Audit deletion is forbidden unless both SIEM delivery policy and the
receipt-capable archive invariant are satisfied. Export failure, partial
coverage, failed readback, or an unavailable checkpoint signer fails closed.
Pre-hash-chain rows with NULL sequence values are outside the chain and cannot
be made verifiable merely by assigning sequence numbers: their genesis hashes
would not link to neighboring rows. They are ineligible for ordinary pruning.
Removal requires a one-time immutable archive with per-row identity/content
proof plus a separately signed reseal checkpoint that establishes an explicit
new trust boundary after the legacy range. That reseal requires its own
security review and operator ceremony; otherwise the legacy rows remain.

Audit appends and checkpoint/prune operations use the same fixed,
deployment-wide PostgreSQL advisory lock held through caller commit and, under
the HA design, synchronous quorum replication. Only one chain-mutating
transaction proceeds at a time. Performance finding #7 estimates a
cluster-wide ceiling of roughly **50–200 audited writes/second** until measured;
this is a planning estimate, not an SLA. Pruning uses bounded transactions and
lock timeouts so maintenance cannot indefinitely block ingestion.

If measured throughput or lock-wait objectives cannot be met, the approved
escape hatches are:

1. **Sharded audit chains:** deterministically shard by tenant and stable chain
   identifier, retaining an independent signed checkpoint per shard.
2. **Asynchronous durable outbox:** commit audit events to an ordered outbox in
   the business transaction, then serialize chain materialization and export
   asynchronously with replay, idempotency, and backlog alerting.

Neither escape hatch may weaken ordering, tenant isolation, checkpoint
verification, or fail-closed deletion. Adopting one requires a superseding ADR
and migration plan.

### Configuration contract

Implementation will add the following named `Settings` fields and regenerate
`.env.example` through the existing generator:

- `retention_audit_hot_days`
- `retention_audit_archive_days`
- `retention_raw_artifacts_hot_days`
- `retention_raw_artifacts_archive_days`
- `retention_reasoning_hot_days`
- `retention_reasoning_archive_days`
- `retention_topology_snapshots_hot_days`
- `retention_topology_snapshots_archive_days`
- `retention_config_snapshots_hot_days`
- `retention_config_snapshots_archive_days`
- `retention_prune_batch_size`
- `retention_prune_time_budget_seconds`
- `retention_advisory_lock_timeout_seconds`
- `retention_archive_uri`
- `retention_audit_pruning_enabled` (default `false`)
- `retention_checkpoint_signing_key_ref`
- `retention_archive_receipt_public_key_ref`

Configuration validation enforces positive windows, archive windows no shorter
than hot windows, and the minimum audit baseline. Enabling audit pruning cannot
disable SIEM delivery, receipt-capable archival, readback, or checkpoint
signing. Private keys and other secret material remain secret-backed settings
and are not placed in plaintext configuration; public verification-key
references may be rendered as non-secret identifiers.

### Legacy raw-artifact purge migration

The existing `raw_artifact_retention_days=90` setting and daily
`discovery.purge_expired_artifacts` hard-delete task are a known non-conforming legacy
path. The implementation that activates this ADR must disable and replace that
schedule, migrate/deprecate the old setting, and prove the old and new paths
cannot run concurrently. Archive-before-delete must be live and receipt-verified
before any replacement cleanup is enabled.

## Consequences

- Storage growth is bounded while audit and reasoning evidence retain explicit
  recovery and verification paths.
- Partition drops keep large-table cleanup predictable and avoid table-wide
  delete churn; unpartitioned tables still require vacuum-aware batched pruning.
- Audit pruning depends on SIEM/archive availability and checkpoint signing, so
  storage alerts must leave enough headroom for prolonged fail-closed periods.
- The advisory-lock design is simple and auditable but retains the estimated
  50–200 audited-writes/second deployment-wide ceiling until load tests replace
  that estimate with measured capacity.
- Operators must monitor export lag, oldest retained partition, prune failures,
  lock waits, outbox backlog (if adopted), and checkpoint verification.

## Alternatives considered

### Retain all records indefinitely

Rejected because it creates unbounded storage, index, backup, and restore cost
without improving the accessibility of archived evidence.

### Apply one retention window to every table

Rejected because audit, raw evidence, reasoning, and operational state have
different legal and operational value.

### Delete audit rows without checkpoints

Rejected because prefix deletion would destroy independently verifiable hash
chain continuity.

### Archive without requiring acknowledgement

Rejected because best-effort export can silently destroy the only durable copy
of security evidence.

### Start with sharded chains or an asynchronous outbox

Deferred until load evidence proves the single-chain advisory-lock design is
insufficient. Both add operational and verification complexity.

## Implementation follow-up

This ADR authorizes design only. A later implementation change must include:

1. an append-only `audit_prune_checkpoints` migration, canonical-signature/key
   handling, verifier support for virtual predecessors, and safe rebuilding of
   the mutable `audit_chain_checkpoint` watermark, plus an append-only
   configuration-baseline tenure table that supports repeated promotion and
   records each `approved_at`/`superseded_at` interval;
2. a receipt-capable immutable archive sink with manifest schema, digest,
   covered-range receipt, authenticated readback, and legacy NULL-sequence-row
   disposition;
3. an idempotent retention service with dry-run output, bounded row pruning,
   trace-family cross-partition eligibility, legal-hold checks, and fail-closed
   audit behavior;
4. disabling/replacing `discovery.purge_expired_artifacts`, migrating/deprecating
   `raw_artifact_retention_days`, and proving legacy/new jobs cannot overlap;
5. generated configuration documentation and validation for all named fields;
6. unit and PostgreSQL integration tests for hot/archive boundaries, archive
   expiry, cross-month trace/step handling, audit clock skew and out-of-order
   timestamps across mixed partitions, contiguous-sequence stop conditions,
   lock contention, partial export, receipt/readback failure, checkpoint
   continuity, key rotation, and crash-safe reruns;
7. operational metrics, alerts, runbooks, restore drills, and measured
   advisory-lock throughput before enabling destructive cleanup;
8. security review of checkpoint signing, archive immutability, tenant
   isolation, legal holds, and policy-exception authorization.

Accepting this ADR does not itself change runtime. The existing raw-artifact
purge remains a documented legacy risk until replaced, and no audit-chain
pruning may be enabled merely by accepting this ADR.
