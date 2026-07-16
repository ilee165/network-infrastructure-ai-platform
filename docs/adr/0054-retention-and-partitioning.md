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

## Decision

Retention is configured by table class. The following values are initial
defaults; deployments may increase them to satisfy local policy, but may not
reduce audit retention below the documented security baseline without an
approved policy exception.

| Table class | Tables | Hot window | Archive window | Terminal action | Semantics |
| --- | --- | ---: | ---: | --- | --- |
| Audit evidence | `audit_log` | 90 days | 7 years | Drop exported partitions | Export to the configured SIEM/archive, verify receipt and integrity, write a chain checkpoint, then drop only complete partitions older than the archive window. |
| Raw evidence | `raw_artifacts` | 30 days | 1 year | Drop archived partitions | Archive complete partitions, verify the archive manifest, then drop partitions older than one year. |
| Reasoning records | `reasoning_traces`, `reasoning_trace_steps` | 90 days | 1 year | Drop complete partitions | Archive trace and step partitions as one referential unit, verify the manifest, then drop matching complete partitions. |
| Discovery snapshots | `topology_snapshots` | 180 days | 1 year | Archive, then bounded row pruning | Export snapshots with their discovery-run identifiers, verify the archive manifest, then delete expired rows in deterministic primary-key batches. |
| Configuration snapshots | `config_snapshots` | 180 days | 1 year | Archive, then bounded row pruning | Export and verify expired versions before batched deletion. Never prune the current approved baseline for a device; it becomes eligible only after a newer baseline supersedes it. |

Partition boundaries are calendar-month UTC boundaries. A partition is never
dropped while it intersects the active hot or archive window. Parent/child
reasoning data is archived and removed in the same maintenance transaction or
in an idempotent sequence that cannot leave orphaned steps.

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

Before pruning an `audit_log` partition, the maintenance process records a
signed, immutable checkpoint anchored in `audit_chain_checkpoint` containing:

- the dropped range's first and last audit identifiers and timestamps;
- the terminal hash of the dropped range and the first retained row's expected
  predecessor hash;
- the archive object identifier, manifest digest, and SIEM receipt identifier;
- the retention policy version, actor, operation identifier, and completion
  timestamp.

Verification of retained audit history starts from the newest trusted
checkpoint preceding the retained range. Checkpoints are themselves exported
and retained at least as long as the audit archive. A prune is aborted if the
chain, archive digest, SIEM receipt, or checkpoint signature cannot be
verified.

### Export prerequisite and concurrency

Audit deletion is forbidden unless the configured SIEM/archive export is
enabled and has acknowledged the exact immutable manifest. Export failure,
partial acknowledgement, or an unavailable checkpoint signer makes the cycle
fail closed.

Audit appends and checkpoint/prune operations use the same PostgreSQL
advisory lock namespace. This protects chain continuity but constrains write throughput:
only one chain-mutating transaction may proceed for a chain at a time. Pruning
uses bounded transactions and lock timeouts so maintenance cannot indefinitely
block ingestion.

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
- `retention_siem_export_required`

Configuration validation enforces positive windows, archive windows no shorter
than hot windows, and the minimum audit baseline. Secrets and signing material
remain secret-backed settings and are not placed in plaintext configuration.

## Consequences

- Storage growth is bounded while audit and reasoning evidence retain explicit
  recovery and verification paths.
- Partition drops keep large-table cleanup predictable and avoid table-wide
  delete churn; unpartitioned tables still require vacuum-aware batched pruning.
- Audit pruning depends on SIEM/archive availability and checkpoint signing, so
  storage alerts must leave enough headroom for prolonged fail-closed periods.
- The advisory-lock design is simple and auditable but imposes a measurable
  throughput ceiling that must be load-tested and monitored.
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

1. migrations for checkpoint metadata and any indexes needed by bounded
   pruning, while preserving the existing monthly partition parents and their
   future-partition creation task;
2. an idempotent retention service with dry-run output, bounded row pruning,
   archive/SIEM acknowledgement verification, and fail-closed audit behavior;
3. generated configuration documentation and validation for all named fields;
4. unit and PostgreSQL integration tests for window boundaries, paired
   trace/step handling, lock contention, retries, partial export, checkpoint
   continuity, and crash-safe reruns;
5. operational metrics, alerts, runbooks, restore drills, and measured
   advisory-lock throughput before enabling destructive cleanup;
6. security review of checkpoint signing, archive immutability, tenant
   isolation, and policy-exception authorization.

No destructive retention job is enabled merely by accepting this ADR.
