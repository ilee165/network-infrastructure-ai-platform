# W5-T0 — Postgres-backed test harness: which SQLite false-PASS each PG test closes

**Task:** P2-Security W5-T0 (`docs/roadmap/p2-tasks/W5-T0-postgres-testcontainers.md`)
**ADRs validated (not re-decided):** ADR-0016/D16 (testing + CI), ADR-0038 (audit
hash-chain), ADR-0040 (credential rotation/scope).
**PRODUCTION.md:** §11 G-MNT / G-SEC — the W5-T3 gate evidence rests on PG-accurate
tests, not the SQLite-only suite that hid every W4 review major.

## Why this layer exists

The unit suite (`backend/tests/`) runs on in-memory **aiosqlite**, which silently
PASSes code that is wrong under **PostgreSQL**. Every documented W4 review major
traced to this class. This layer (`backend/tests/pg/`) re-asserts the W4
audit-hash-chain and credential-rotation controls against a **real Postgres**, run
via the **real `alembic upgrade head`** (not `create_all`) — so the migration path
itself (partitioned `audit_log`, the `REVOKE`, the per-partition `seq` index) is
exercised, which SQLite never does.

It is a **separate CI job** (`pg-integration` in `.github/workflows/ci.yml`, using
`services: postgres` with the `pgvector/pgvector:pg16` image — migration 0006 needs
the `vector` extension). It **skips cleanly** off-CI when no Postgres is reachable
(L1: never a silent green, never a hard failure on the no-Docker dev host); the CI
job runs it and **bites** on a regressed control. The job guards against a silent
no-collection green (`test -s` + a skip/no-tests grep, L5).

## The four documented SQLite false-PASSes → the PG test that closes each

| # | SQLite false-PASS (what SQLite hides) | PG-only semantic | Closing test |
|---|---|---|---|
| 1 | `NULLS FIRST` ordering / head selection by `seq` | PG sorts `NULLS FIRST` in `ORDER BY seq DESC`; the writer's `seq IS NOT NULL` filter keeps a NULL-`seq` pre-chain row from being picked as the head (else `int(None)+1` crashes every append). SQLite sorts NULLs the other way in DESC and masked it. | `test_audit_hash_chain_pg.py::test_head_read_ignores_null_seq_under_pg_nulls_first_ordering` (+ `test_equal_created_at_rows_order_by_seq_not_id_under_pg`) |
| 2 | Unique index on a partitioned table | A UNIQUE index on `seq` alone is INVALID on the `RANGE (created_at)` partitioned `audit_log` parent; the index must be NON-unique and `seq` uniqueness rests on the writer's under-lock `MAX(seq)+1`. SQLite has no native partitioning so the constraint shape was never exercised. | `test_audit_hash_chain_pg.py::test_seq_index_is_non_unique_on_partitioned_audit_log` (+ `test_seq_uniqueness_rests_on_writer_not_a_db_constraint_under_pg`) |
| 3 | `REVOKE ... UPDATE` append-only | SQLite ignores the GRANT/REVOKE model entirely; only on PG does `REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC` actually deny a non-owner role. | `test_audit_hash_chain_pg.py::test_revoke_update_blocks_a_non_owner_role_on_audit_log` |
| 4 | `prev_hash`/`entry_hash` chain-walk (incl. round-5 continuity) | The verifier recompute + chain walk runs against real `bytea` columns and the PG `ORDER BY seq` keyset, including the full-scan pre-anchor re-walk (the round-5 `prev_hash` continuity guard). | `test_audit_hash_chain_pg.py::test_mid_chain_update_is_flagged_under_pg`, `test_mid_chain_delete_breaks_prev_hash_link_under_pg`, `test_full_scan_catches_pre_anchor_tamper_under_pg` |

Additional PG-only coverage: `test_concurrent_appends_on_pg_do_not_fork_the_chain`
exercises the `pg_advisory_xact_lock` serialisation under real READ COMMITTED
cross-connection concurrency — the bite the single-connection SQLite suite cannot
surface.

## Credential rotation / scope (ADR-0040 / ADR-0032) under PG

`test_credentials_rotation_pg.py` re-asserts the credential-vault secret-surface
against real PG `bytea` envelope columns + JSONB `audit_log.detail`:

- confirm-then-swap KEK re-wrap migrates every row, payload byte-identical, secret
  still decryptable (`test_re_wrap_migrates_all_rows_payload_byte_identical_under_pg`,
  `test_re_wrap_keeps_secret_decryptable_under_pg`, `test_rotation_status_*`);
- per-credential scope deny refuses an out-of-scope device BEFORE any KEK access and
  audits the refusal with IDs only (`test_scope_deny_refuses_out_of_scope_device_under_pg`),
  while an in-scope device decrypts (`test_in_scope_device_decrypts_under_pg`);
- **no plaintext / key-material leak**: no secret, wrapped-DEK, or DEK-nonce bytes
  appear in any persisted PG audit row or the log stream
  (`test_rotation_emits_no_secret_or_key_bytes_under_pg`,
  `test_rotation_audit_carries_versions_and_counts_only_under_pg`).

## Bite verification (spec risk #1 — a PG test that also passes on SQLite proves nothing)

Verified against a real PostgreSQL 16 (pgvector-enabled) by regressing the W4 fix
and watching ONLY the PG layer fail — the regression was **never committed**:

- Removed the `seq IS NOT NULL` filter from `app/services/audit/service.py`
  `_current_chain_head` (the round-4 #01 fix).
- **PG result:** `test_head_read_ignores_null_seq_under_pg_nulls_first_ordering`
  FAILED (the NULLS-FIRST head read picked the NULL row → append crash).
- **SQLite result:** the entire `tests/services/test_audit_hash_chain.py` suite
  stayed GREEN (35 passed) — SQLite's DESC NULL ordering hides the bug.
- Restored the fix; both layers green again.

This is precisely the false-PASS class the harness closes: a regression invisible to
SQLite is caught by the PG layer.

The full PG layer (17 tests) was run green against a real PostgreSQL 16 instance via
the real `alembic upgrade head`. On the no-Docker authoring host the layer skips
cleanly (exit 0, explicit reason); CI's `pg-integration` job is the standing gate.
