# Runbook — Audit-log hash-chain verification & re-seal (W4-T1)

> Operator procedure for the ADR-0038 tamper-evident `audit_log` hash chain: how the daily verification job works, how to read a break alert, and how to **re-seal** the chain after a *legitimate* break (e.g. a restored backup) — distinct from a *tampering* break, which is a security incident, never re-sealed away. Rehearsed-ready for PRODUCTION.md §5 (audit integrity), G-SEC / G-MNT.

## Objective

Continuously prove the append-only `audit_log` has not been mutated or deleted by a privileged actor with DB access. Each entry stores `entry_hash = SHA-256(canonical(immutable fields) || prev_hash)`, chaining from a fixed genesis; a daily CronJob recomputes the chain from the last verified-clean checkpoint to head and **alerts + exits non-zero on any break**. Append-only is now cryptographically backed, not trigger-only.

## Facts

| Field | Value |
|---|---|
| ADR | ADR-0038 (hash chaining + daily verify), ADR-0011 §2 (append-only), ADR-0015 (metric/alert), ADR-0032 §5 (no secret in audit rows) |
| Chain columns | `audit_log.prev_hash` / `audit_log.entry_hash` — raw 32-byte SHA-256 (`bytea`/`BLOB`), NO hex variant |
| Canonical form | sorted-key, no-whitespace, UTF-8 JSON of `{id, created_at (RFC3339 UTC, µs), actor, action, target_type, target_id, request_id, reasoning_trace_id, detail}` |
| Writer | `app.services.audit.record` (the single append path; sets the chain under the caller's transaction) |
| Verifier | `app.services.audit.verify.verify_chain` (shared by the job + the test) |
| Job entrypoint | `python -m app.services.audit.verify_job` (set `AUDIT_CHAIN_VERIFY_FULL=true` for a full genesis re-walk) |
| CronJob (daily) | `<release>-audit-chain-verify` (Helm; daily 02:30; incremental from checkpoint; `audit.chainVerify.enabled`) |
| CronJob (weekly full) | `<release>-audit-chain-verify-full` (Helm; weekly Sun 03:30; full scan from genesis; `audit.chainVerify.fullScan.enabled`) |
| Checkpoint | `audit_chain_checkpoint` (single-row `(entry_id, entry_created_at, entry_hash)` watermark) |
| Metrics | `audit_chain_verified` (1 clean / 0 break), `audit_chain_last_verified_position`, `audit_chain_checked_total` (node_exporter textfile) |
| Log line | `AUDIT_CHAIN_VERIFY OUTCOME=PASS\|FAIL ...` |

## How the daily (incremental) verify works

1. Loads the verified-clean checkpoint (the last entry a previous run confirmed). On the first ever run there is none, so it walks from the genesis.
2. Re-proves the checkpoint anchor (recomputes its `entry_hash`) so a tamper of the anchor row itself is still caught before resuming past it.
3. Walks every entry after the checkpoint in append order (the monotonic `seq` column), checking BOTH directions of each link: the stored `entry_hash` must equal the recompute, and the stored `prev_hash` must equal the predecessor's `entry_hash`.
4. **Clean** → advances the checkpoint over the verified-clean segment, writes `audit_chain_verified 1`, exits 0.
5. **Break** → does NOT advance the checkpoint, writes `audit_chain_verified 0` + the break's position/entry-id/reason, exits **non-zero** (the Job is Failed — the alert). It never silently passes.

## The weekly FULL scan — why the daily run is not enough

The daily run resumes **strictly after** the checkpoint, and it re-proves only the *anchor* row (the watermark itself), not the rows below it. So a tamper of an **already-checkpointed historical row that is not the anchor** is invisible to the daily incremental walk — it never re-visits that row. The full scan closes this gap:

- **What it does** — runs the same verifier with `AUDIT_CHAIN_VERIFY_FULL=true`, which **ignores the checkpoint and re-walks the whole chain from genesis**. A mutated pre-anchor row therefore surfaces as a normal `entry_hash_mismatch` / `prev_hash_mismatch` break, with the same loud signal (exit non-zero + `audit_chain_verified 0` + the structured log line). A clean full pass still advances the checkpoint to the head.
- **Cadence** — weekly (Helm default Sun 03:30, `audit.chainVerify.fullScan.schedule`), in addition to the daily incremental. The daily fast check catches *new* tampering within ~24h; the weekly full scan bounds detection of *historical* tampering to ~7 days.
- **Tradeoff** — the full scan is O(all audit rows) per run vs the daily O(new rows since the checkpoint), so it is heavier and runs infrequently. On a very large `audit_log` keep the weekly cadence (or lengthen it) rather than promoting the full scan to daily; the daily incremental remains the cheap continuous guard. Both write the SAME metric file, so the metric/alert wiring is unchanged.
- **Disabling** — `audit.chainVerify.fullScan.enabled=false` renders no full-scan CronJob and leaves the historical-tamper gap open; keep it on for G-SEC/G-MNT.

> A break reported by the weekly full scan but NOT the daily run means the tamper is in already-checkpointed history (below the watermark). Triage it exactly as any break (tampering vs. legitimate) below; the `position`/`entry_id` locate the offending row from genesis.

## `seq` nullability during the W4 rolling deploy (expand/contract)

`audit_log.seq` (the monotonic append-order key the verifier orders by) is added **NULLABLE** by the expand migration `0011` and **stays nullable** through this phase. `seq` is *app-assigned* (`MAX(seq)+1` under the append advisory lock), so — unlike `prev_hash`/`entry_hash`, which keep a genesis `server_default` — no DB default can supply a correct monotonic value for an **old (pre-W4) pod** still inserting audit rows during an N→N+1 rolling deploy; a NOT-NULL `seq` would crash those legitimate inserts. New rows are never NULL (the writer always assigns `seq`). A **NULL `seq` row is therefore exactly an old-writer / pre-chain row** — it also carries the genesis `entry_hash` default, so the verifier already treats it as untrusted pre-chain history (it orders `seq` ASC NULLS LAST and flags genesis-hash rows like any genesis row). **A later, separate CONTRACT migration will backfill residual NULL `seq` and `SET NOT NULL` once no pre-W4 pod can write** — it is intentionally NOT part of `0011`.

## Reading a break

A break carries a 1-based `position`, the offending `entry_id`, and a coarse `reason`:

| `reason` | Meaning |
|---|---|
| `entry_hash_mismatch` | A hashed field of that row was mutated (its stored `entry_hash` no longer matches its content). |
| `prev_hash_mismatch` | The chain link is broken — a predecessor row was deleted/reordered, or this row's `prev_hash` was rewritten. |
| `checkpoint_mismatch` | The verified-clean anchor row itself was mutated since it was checkpointed. |
| `missing_checkpoint_entry` | The watermarked entry row is gone (deleted). |

## Triage: tampering vs. a legitimate break

**A break is a security incident until proven otherwise.** Do NOT re-seal first.

1. **Capture evidence.** Snapshot the offending row(s) and the `AUDIT_CHAIN_VERIFY` line. The metric `audit_chain_last_verified_position` bounds where the chain was last known-good.
2. **Determine the cause.**
   - *Tampering* (an UPDATE/DELETE on `audit_log` by a privileged actor): a security incident. `audit_log` append-only is enforced by the migration 0001 `REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC` (line 222) — NOT by the migration 0009 trigger, which guards the `approvals` table only. Crucially, `REVOKE ... FROM PUBLIC` does **not** bind the table owner or a superuser (PostgreSQL owners always hold implicit privileges), so a privileged actor connecting as the owner can still mutate a row — which is exactly the threat this hash chain exists to catch. A break here therefore means either the REVOKE was loosened (a non-owner role gained UPDATE/DELETE) or, more likely, an owner/superuser-level write that no GRANT can stop. Investigate per the incident process; preserve the chain, do not re-seal.
   - *Legitimate* (e.g. a restored-from-backup database whose tail differs, or a one-time data migration that touched audit rows under maintenance): the chain is genuinely discontinuous but not malicious.
3. **Only after a legitimate cause is confirmed and signed off**, re-seal.

## Re-seal procedure (legitimate break only)

Re-sealing re-establishes a verifiable chain forward from the current head WITHOUT pretending the historical break did not happen.

1. **Freeze.** Pause the verify CronJob (`audit.chainVerify.enabled=false` on the next upgrade, or `kubectl patch cronjob ... -p '{"spec":{"suspend":true}}'`) so it does not re-alert during the re-seal.
2. **Record the break.** Write an operational note (this runbook's incident log) with the break position, entry id, reason, and the signed-off legitimate cause. The historical pre-break segment stays in the DB as-is — it is NOT rewritten (the migration 0001 `REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC` blocks any non-owner rewrite, and rewriting history would defeat the control).
3. **Re-anchor the checkpoint to the current head.** Point the `audit_chain_checkpoint` watermark at the current chain head so future verification starts from a clean boundary going forward. Because re-anchoring is the ONLY supported "advance past a known break" action, it is a deliberate operator step, logged here — never automated.
4. **Resume.** Re-enable the CronJob. The next run verifies cleanly from the re-anchored checkpoint forward; the recorded break remains documented.

> Re-sealing changes only the verification *boundary*, never the audit rows. The pre-break history is retained; the note in step 2 is the audit-of-the-audit.

## Invariants (proven by the test suite)

- **Tamper-detected** — an UPDATE/DELETE of a mid-chain row is flagged at the right index; an untouched chain verifies clean (`tests/services/test_audit_hash_chain.py`).
- **Deterministic** — the same rows recompute to identical `entry_hash` across runs (byte-exact canonical form; `created_at` always rendered at fixed µs precision).
- **No secret hashed** — the canonical field set excludes every secret/mutable column; the hash carries no credential/key material (ADR-0032 §5).
- **Append-only intact** — chaining adds no UPDATE/DELETE path; `audit_log` append-only is enforced by the migration 0001 `REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC` (it does not bind the owner/superuser — the hash chain is the backstop for that privileged-actor case). The 0009 trigger applies to `approvals`, not `audit_log`.
- **Loud on break** — a break yields exit non-zero + `audit_chain_verified 0`; the verify never silently passes (`tests/services/test_audit_verify_job.py`). The structured log line + exit code are emitted BEFORE the metric write, and the metric write is best-effort, so a metrics-write failure can never suppress the alert (`test_metric_write_failure_does_not_suppress_break_alert`).
- **Historical-tamper guard** — the full scan (`AUDIT_CHAIN_VERIFY_FULL=true`) re-detects a pre-anchor tamper that the daily incremental run does not (`test_pre_anchor_tamper_caught_by_full_scan_not_incremental`, `test_full_scan_catches_pre_anchor_tamper_via_job`).
- **No crash on a malformed-length hash** — a wrong-length stored `prev_hash`/`entry_hash` is reported as a chain break (so the metric/alert fires and the job exits cleanly), never an uncaught `ValueError` (`test_malformed_length_anchor_hash_is_checkpoint_break_not_a_crash`).

## Failure modes & response

| Symptom | Response |
|---|---|
| `audit_chain_verified 0` / Job Failed | A chain break — triage per "tampering vs. legitimate" above before any re-seal. |
| `reason=checkpoint_mismatch` | The verified anchor was mutated. Treat as tampering unless a signed-off legitimate cause exists. |
| Verify false-alarms on untouched data | A canonicalization regression (build bug, not tampering) — the deterministic-recompute test is the guard; do NOT "tune" the verifier to silence it. |
| CronJob renders nothing | `audit.chainVerify.enabled=false` — a warned opt-out (NOTES.txt). Re-enable; the audit chain must be verified daily for G-SEC/G-MNT. |
