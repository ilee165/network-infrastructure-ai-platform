# ADR-0038: Audit-Log Hash Chaining + Daily Verification

**Status:** Proposed | **Date:** 2026-06-25 | **Milestone:** P2 W0

## Context

`PRODUCTION.md` §5 requires the append-only `audit_log` to be **tamper-evident**,
and §11 G-SEC / G-MNT restate audit integrity as a release criterion. Today the log
is append-only (ADR-0011 §2; migration 0009 adds an append-only trigger + retention
index) but carries no cryptographic evidence that a privileged actor with DB access
has not mutated or deleted a row. This ADR is the design gate; the build is **W4-T1**
(`P2-SECURITY-PLAN.md` §3). The audit log is the integrity root, so this is a
secret-surface decision (strong review).

Bounded by ADR-0011 §2 (append-only `audit_log`), migration 0009 (trigger +
retention index), and ADR-0015 (observability — the verify-job emits a metric +
alert).

## Decision

**Each `audit_log` entry stores a predecessor hash, forming a hash chain seeded by a
fixed genesis value. A daily CronJob recomputes the chain from a verified checkpoint
and alerts (and exits non-zero) on any break. Chaining strengthens — never weakens —
the existing append-only trigger.**

### 1. Chain construction

`entry_hash = SHA-256(canonical(entry_fields) || prev_hash)`, where `prev_hash` is
the previous entry's `entry_hash` and the first entry chains from a fixed
**genesis** constant. Two columns are added to `audit_log` — `prev_hash` and
`entry_hash` (both `bytea`/fixed-width hex) — via a **new Alembic revision** (current
head `0010` → `0011`; forward + down).

### 2. Canonical serialization (byte-exact, deterministic)

The hashed form is the **canonical JSON** of the entry's immutable fields —
`id`, `created_at` (RFC 3339, UTC, fixed precision), `actor_id`, `action`,
`resource`, `request_id`, and the existing structured detail — with **sorted keys,
no insignificant whitespace, UTF-8**. The exact field list and encoding are fixed in
the W4-T1 implementation notes so an independent verifier reproduces `entry_hash`
**byte-for-byte**. Mutable / server-defaulted columns that are not part of the
audited fact are excluded.

### 3. Per-insert `prev_hash` — application write under the trigger

`prev_hash` / `entry_hash` are computed and written by the **application audit
writer** at insert time (the writer already serializes every audit append through a
single path), reading the current chain head under the same transaction. The
**append-only trigger (migration 0009) stays** and forbids UPDATE/DELETE, so a
`prev_hash` cannot be silently back-filled or rewritten. The writer is the only
INSERT path; a row without a valid `prev_hash` is rejected.

### 4. Daily verification job

A Helm-rendered **CronJob** recomputes the chain from the **last verified
checkpoint** (a stored `(entry_id, entry_hash)` watermark) to the current head —
avoiding a full-history recompute every day on a large log. It emits a Prometheus
metric (`audit_chain_verified` / last-verified position) and, on any mismatch,
**raises an alert (ADR-0015) and exits non-zero**. The checkpoint advances only over
a verified-clean segment. A chain break never silently passes.

### 5. No secret hashed in the clear

The canonical form covers only the already-secret-free audit columns
(ids/versions/action/resource — ADR-0032 §5 posture: audit rows carry no plaintext
secret). A W4-T1 test asserts no secret-bearing field participates in the hash.

### 6. Implementation note for W4-T1 (P1-W4-LESSONS)

- **L3:** the verify CronJob wraps any `$(VAR)` in `sh -c "tool \"$VAR\""` — K8s does
  not substitute `$(VAR)` in exec argv.
- **L5:** any piped step in the job uses `set -o pipefail` + `test -s`.

## Consequences

**Positive**
- Tamper-evidence on the integrity root: a mutated/deleted mid-chain row is detected
  by the daily job; append-only is now cryptographically backed, not trigger-only.
- Checkpointed verification scales to a long log without a daily full recompute.
- Deterministic canonical form lets any independent verifier reproduce the chain.

**Negative**
- A non-deterministic canonical form would false-alarm (or be tuned until it stops,
  masking tampering); §2 nails the byte-exact form — the load-bearing requirement.
- Chain writes add a small per-insert cost (read head + hash) on the audit path.
- Recovery after a legitimate break (e.g. a restored backup) needs a documented
  re-seal procedure (named for W4-T1 runbook).

## Alternatives considered

1. **Trigger-computed `prev_hash` instead of application write.** Considered;
   rejected for P2: hashing the canonical app-level fact in a PL/pgSQL trigger
   risks serialization drift from the application's canonical form (§2). The single
   application writer already serializes appends; keep one canonicalizer.
2. **External WORM / append-only object store for the audit log.** Rejected for P2:
   heavier operationally; the SIEM export that would carry this is re-scoped to
   P3-Platform (§0). Hash chaining gives in-DB tamper-evidence now.
3. **Per-entry digital signatures (asymmetric).** Rejected: key-management weight
   beyond P2's need; a hash chain detects tampering, which is the §5 requirement.
   Signing is a future enhancement if non-repudiation is required.
4. **Full-history daily recompute (no checkpoint).** Rejected: does not scale on a
   large/long log; the verified-checkpoint watermark (§4) bounds daily work.
