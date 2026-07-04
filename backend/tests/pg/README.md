# `tests/pg/` — Postgres-backed test layer

The default unit suite (`backend/tests/`) runs on **SQLite** for speed and zero
external dependencies. SQLite does not implement several PostgreSQL semantics the
platform relies on, so a test that passes there can hide a real production bug.
This layer runs the same code against **real PostgreSQL** (the blocking
`pg-integration` CI job, `pgvector/pgvector:pg16`).

## Routing rule (audit ARCH_DEBT #2)

> Any code path that uses PostgreSQL-specific SQL or semantics **MUST** ship a
> test under `backend/tests/pg/`.

This closes a recurring bug class: the P2-W4 review majors were repeatedly rooted
in SQLite hiding PG behaviour, and every new PG-semantic feature re-opens the gap
unless its test lands here.

### PG-specific semantics that require a `tests/pg/` test

Non-exhaustive — these are the markers the CI heuristic flags:

- **Partial indexes** — `postgresql_where=` on an `Index` (SQLite ignores the
  predicate; uniqueness/partiality is not enforced the same way).
- **`SET LOCAL`** / transaction-scoped GUCs (e.g. `synchronous_commit`,
  statement timeouts) — no-ops or errors on SQLite.
- **Advisory locks** — `pg_advisory_lock` / `pg_advisory_xact_lock` and friends.
- **Partition DDL** — `PARTITION BY` / `PARTITION OF` / `ATTACH PARTITION`.
- **Ordering nullability** — `NULLS FIRST` / `NULLS LAST` (SQLite's default NULL
  ordering differs).
- **`REVOKE` / role-scoped grants**, row/write-locking (`FOR UPDATE`
  interactions), and other engine-specific behaviour.

## The CI heuristic

`ci/scripts/check-pg-test-routing.sh` greps the branch diff for the markers above
in `backend/app/**` and `backend/alembic/versions/**`. If a marker is **added**
without any matching change under `backend/tests/pg/`, the check fails and links
back to this rule.

It is a heuristic, not a proof. Satisfy it the normal way — by adding the PG test
the rule asks for. For a change that is genuinely already covered (or a false
positive), set `PG_ROUTING_ALLOW=1` for that run; that escape hatch is a reviewed
exception, not the default.

### Rollout

The heuristic ships **advisory first** (a non-blocking signal for one week to
confirm its false-positive rate on real PRs), then is promoted to blocking by
adding its job to the `all-gates` aggregator's `needs`. The script itself already
exits non-zero on a violation, so the promotion is a one-line CI change with no
script edit.
