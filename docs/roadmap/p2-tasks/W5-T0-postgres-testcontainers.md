# W5-T0 — Postgres-Backed Test Harness (close the SQLite-hides-PG-semantics class)

| | |
|---|---|
| **Wave** | P2 W5 — Evals + phase-exit gate |
| **Owner** | `wf-implementer` (strong — exercises the audit spine + credential vault under real PostgreSQL; secret-surface) |
| **Review tier** | **strong** spec + **strong** quality (audit hash-chain + credential rotation are the controls under test) |
| **Depends on** | **W4** (audit hash-chain ADR-0038 / cred rotation ADR-0040 — the controls whose PG semantics this validates) |
| **ADRs** | ADR-0016 / D16 (testing + CI), ADR-0038 (audit hash-chain), ADR-0040 (credential rotation); no new ADR — this is a test-infra hardening, not a decision |
| **PRODUCTION.md** | §11 G-MNT / G-SEC (the W5-T3 gate evidence rests on PG-accurate tests) |
| **Status** | Proposed |

## Objective

Close the recurring root cause behind **every** W4 review major: the unit suite
runs on **in-memory aiosqlite**, which silently passes code that is wrong under
**PostgreSQL**. Add a **Postgres-backed test layer** that re-asserts the W4
security controls under real PG semantics, so the W5-T3 phase-exit evidence is not
resting on a backend that hides the bug it claims to gate.

Folded into W5 per the build decision (2026-06-28): the gate flip (W5-T3) must
cite PG-accurate tests, not SQLite-only ones.

## Background — the four documented SQLite false-PASSes (W4)

Each is a known PG semantic the SQLite backend does not reproduce. These are the
**bite targets** — a test that would pass on SQLite but is meaningful only on PG:

1. **`NULLS FIRST` ordering** — audit hash-chain *head selection* ordered by `seq`;
   SQLite's NULL ordering differs from PG and masked a head-selection crash.
2. **Unique index on a partitioned table** — PG partitioned-index rules differ;
   SQLite has no native partitioning so the constraint was never exercised.
3. **`REVOKE ... UPDATE`** — append-only enforcement via revoked UPDATE; SQLite
   ignores the GRANT/REVOKE model, so the protection was untested.
4. **`prev_hash` chain-walk false-PASS** (round-5) — the chain-continuity assertion
   passed on SQLite while the PG walk would have caught a break.

## Scope

**In**
- A **Postgres-backed test module + fixtures** (e.g. `backend/tests/pg/`) that boots
  a real PostgreSQL, runs `alembic upgrade head`, and re-asserts the W4 controls:
  - audit hash-chain: head selection (`NULLS FIRST`/`seq`), append-only via
    `REVOKE UPDATE`, partitioned-index constraint, and the `prev_hash`/`entry_hash`
    chain walk including NULL-`seq` pre-chain rows (ADR-0038 expand-phase semantics).
  - credential rotation: confirm-then-swap + re-scope under PG (ADR-0040), no
    plaintext leak, scope-deny enforced.
- **Provisioning** (implementer chooses, **CI-gating-first**): a GitHub Actions
  **`services: postgres`** job is the recommended default (CI-native, no
  Docker-in-test). `testcontainers[postgres]` is allowed only if it runs reliably in
  CI **and** locally; if chosen, it must degrade to a clear skip when no Docker.
- **Local-skip discipline** (L1): the PG layer is a **separate CI job**, not added to
  the default SQLite smoke. Locally it **skips with an explicit reason** when no PG is
  reachable — never silently green, never a hard failure on the no-Docker dev host.
- **Bite proof**: at least one assertion per control that is **meaningful only on PG**
  — verify by confirming it errors/changes outcome if pointed at SQLite (the four
  semantics above). The existing SQLite suite stays the fast smoke; this is additive.

**Out**
- Changing any W4 control's behavior → W4 (this only tests it; if a real PG bug
  surfaces, loop back to a W4 fix commit, do not patch the assertion).
- Firewall-analysis / routing evals → W5-T1 / W5-T2.
- Gate evidence doc + ADR flips → W5-T3 (this is one of the artifacts it cites).
- A full PG migration of the whole suite — only the W4 secret-surface controls are
  in scope here; broad migration is a later hardening.

## Requirements (grounded in D16, ADR-0038, ADR-0040, L1/L5)

1. **Real PostgreSQL** (matched major to prod compose), `alembic upgrade head` first
   — the migration path itself is part of what SQLite never exercised.
2. **Bites under PG, skips cleanly without it** (L1): separate CI job; local run skips
   with a stated reason, CI job runs and fails on a real regression.
3. **`set -o pipefail` + `test -s` on any piped CI step** (L5) so a broken PG step
   cannot mask its exit code as green.
4. **No plaintext secret** in fixtures or assertions (credential-rotation path is
   secret-surface) — assert ciphertext/scope, never a raw credential.
5. **fastapi route-introspection stays green** (no lockfile — standing fact) after any
   incidental import/dependency touch (`testcontainers` add, if chosen).
6. **Deterministic**: each test sets up and tears down its own schema/data; no
   cross-test ordering dependence.

## Contracts / artifacts

- Postgres-backed test module + fixtures under `backend/tests/pg/` (or equivalent),
  parametrized to the four W4 controls.
- A CI job (postgres service or testcontainers) that runs them and **bites** on a
  seeded regression.
- A short `docs/` note (or test-module docstring) recording which SQLite false-PASS
  each PG test closes, so W5-T3 can cite it.

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff / mypy strict / import-linter / pytest green (SQLite smoke unchanged).
- **PG job green** on a clean tree; **bites** when a W4 control is regressed (verify by
  reverting one W4 fix locally against PG and seeing the PG test fail — do not commit
  the revert).
- **Local skip** path verified: with no PG reachable the module skips with a clear
  reason, exit 0, not a false green.
- markdownlint on any doc note.

## Exit criteria

- [ ] Postgres-backed tests re-assert audit hash-chain (head/append-only/partition/
      chain-walk) + credential rotation (swap/scope/no-leak) under real PG.
- [ ] Each of the four documented SQLite false-PASSes has a PG test that is
      meaningful only on PG (bite verified).
- [ ] Runs as a **separate CI job**; local run **skips cleanly** without PG (L1).
- [ ] No plaintext secret in fixtures/assertions; fastapi introspection green.
- [ ] D16 gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** in parallel → `wf-fixer` (strong) if findings →
`wf-verifier` → **one atomic commit**.

## Risks

- **A PG test that also passes on SQLite proves nothing** — every assertion must turn
  on a PG-only semantic; the bite check (regress + watch it fail) is the guard.
- **CI flake from container startup** (L1/L5): prefer the `services: postgres` job;
  health-gate the connection before tests; `pipefail` on piped steps.
- **Scope creep into a full PG migration** — confined to the four W4 controls;
  broader migration is a named later task, not this commit.
- **Patching the assertion instead of the bug** — if a PG test reveals a real W4
  defect, the fix is a W4 follow-up commit, never a loosened assertion.
