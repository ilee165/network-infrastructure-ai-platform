# W1-T2 — App DB wiring: replica reads + synchronous-commit on the audit session

| | |
|---|---|
| **Wave** | P3 W1 — Data-tier HA |
| **Owner** | `wf-implementer` (escalated — audit path) |
| **Review tier** | **strong** spec + quality (audit write path) |
| **Depends on** | **W1-T1** (cluster + pooler), W0-T1 (ADR-0042) |
| **ADRs** | ADR-0042 (the contract), ADR-0004 (Postgres SoR), ADR-0002 (SQLAlchemy), ADR-0038 (audit hash-chain) |
| **PRODUCTION.md** | §3.2, §11 G-REL |
| **Status** | Proposed |

## Objective

Wire the application to the HA cluster: route through **PgBouncer**, enable
**read traffic on replicas** where safe, and set **`synchronous_commit`
(remote_apply/on)** on the **audit-log write session** so a committed audit row is
durable on a replica before ack — the app-side half of "zero committed-audit loss"
that W4-T3 asserts under a real primary kill.

## Scope

**In** — SQLAlchemy/psycopg connection config to the PgBouncer endpoint; an
audit-write session/engine with synchronous-commit set per ADR-0042; optional
read/write split (replica reads for read-only queries, primary for writes) if
ADR-0042 calls for it; ensuring the hash-chain append (ADR-0038) runs on the
sync-commit session. Tests on **real PG** (`tests/pg/`).

**Out** — the cluster manifests (W1-T1); the failover drill (W4-T3); pgvector
(W1-T1 verifies availability; app uses it unchanged).

## Requirements (grounded in ADR-0042, ADR-0038, PRODUCTION.md §3.2)

1. **Audit session is synchronous** — the audit append commits with
   `synchronous_commit` per ADR-0042; a unit/integration test on real PG asserts the
   session setting (the durability contract W4-T3 then exercises live).
2. **No SQLite assertion** — the sync-commit + read/write-split behaviour is
   asserted in `tests/pg/` against real PG (P2 lesson: SQLite hides write/isolation
   semantics).
3. **PgBouncer-compatible** — no session-pinning features that break transaction-
   mode pooling (e.g. session-level `SET` that PgBouncer can't carry); document any
   prepared-statement caveat.
4. **No secret leak / no behaviour change to the audit content** — only the
   durability of the write changes; the redaction + hash-chain stay intact.

## Contracts / artifacts

- App DB engine/session config (PgBouncer endpoint + sync-commit audit session);
  `tests/pg/` assertions for the sync-commit setting + read/write routing.

## Test & gate plan

- `tests/pg/` (real PG, `pytest.mark.integration`, the `pg-integration` job): assert
  the audit session's `synchronous_commit`; assert read-only queries can target a
  replica without breaking writes.
- Backend D16 gates green; `include_router` introspection green; mypy/ruff clean.
- The live zero-loss-on-failover proof is **W4-T3** (this task makes it possible).

## Exit criteria

- [ ] Audit-write session uses `synchronous_commit` per ADR-0042; asserted on real PG.
- [ ] App routes through PgBouncer; read/write routing per ADR-0042; no pooling-incompatible feature.
- [ ] `tests/pg/` green in `pg-integration`; backend D16 + `include_router` green; one atomic commit.

## Workflow

`wf-implementer` (escalated) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Sync-commit set on the wrong session** (e.g. all sessions) → throughput hit, or
  (worse) not on the audit session → W4-T3 fails to prove zero loss. Scope precisely.
- **PgBouncer transaction-mode incompatibility** (session `SET`, prepared
  statements) → silent connection errors under load; document + test.
- **Asserting on SQLite** → green locally, broken on PG. Use `tests/pg/`.
