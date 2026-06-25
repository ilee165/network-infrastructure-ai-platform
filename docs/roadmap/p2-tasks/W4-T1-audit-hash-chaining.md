# W4-T1 — Audit-Log Hash Chaining + Daily Verification Job + Tamper-Detection Test

| | |
|---|---|
| **Wave** | P2 W4 — Security hardening + kind validation (audit stream) |
| **Owner** | `wf-implementer` (strong — audit spine; tamper-evidence is the integrity root) |
| **Review tier** | **strong** spec + **strong** quality (secret-surface: audit integrity root) |
| **Depends on** | **W0-T5** (ADR-0038); independent of the credential (T2) + network (T3–T5) streams |
| **ADRs** | ADR-0038 (the contract this builds), ADR-0011 §2 (append-only `audit_log`), migration 0009 (M5 append-only trigger + retention index), ADR-0015 (verify-job metric/alert), ADR-0032 §5 (no secret in audit rows) |
| **PRODUCTION.md** | §5 (audit-log integrity), §11 G-SEC / G-MNT |
| **Status** | Proposed |

## Objective

Implement exactly what **ADR-0038** ratified: make the append-only `audit_log`
**tamper-evident** by storing a **predecessor hash** per entry (a hash chain), add
a **daily verification job** that recomputes the chain and alerts on any break, and
land the **tamper-detection test** that mutating/deleting a mid-chain row is
detected. No design re-decided here — this realizes the W0-T5 design gate.

## Scope

**In** (`backend/app/` audit-write path + a new Alembic revision + a Helm-rendered
CronJob + tests)
- **Chain columns** on `audit_log` (`prev_hash`, `entry_hash`) via a **new Alembic
  revision** (current head `0010` → `0011`); forward + down migrations.
- **Chain write**: `entry_hash = SHA-256(canonical(entry_fields) || prev_hash)` with
  the **genesis** seed and the **byte-exact canonical serialization** fixed by
  ADR-0038 (field ordering, encoding). The `prev_hash` is set per-insert by the
  mechanism ADR-0038 chose (trigger vs application write) — implement that one;
  it cannot be back-filled silently (append-only trigger from migration 0009 stays).
- **Daily verification job**: a Helm-rendered **CronJob** that recomputes the chain
  end-to-end (or from the last verified checkpoint per ADR-0038), emits a Prometheus
  metric, and **alerts + exits non-zero on a break** (ADR-0015) — never silently passes.
- **Tamper-detection test**: an UPDATE/DELETE of a mid-chain row (in a test DB) is
  caught by the verifier; an untouched chain verifies clean.

**Out**
- ADR / canonicalization decision → **W0-T5** (this implements it).
- SIEM export of the audit log → **P3-Platform** (re-scoped, §0).
- mTLS / credential / network controls → W4-T2…T5.

## Requirements (grounded in ADR-0038, ADR-0011 §2, migration 0009, ADR-0015)

1. **Append-only preserved** (ADR-0011 §2): chaining adds columns + a hash write;
   it introduces **no UPDATE/DELETE path** and does not weaken the 0009 trigger.
2. **Deterministic recompute** (ADR-0038): the canonical hashed form is implemented
   byte-for-byte as the ADR specifies so the verifier reproduces `entry_hash`
   exactly — a recompute mismatch on untampered data is a build bug, not an alert.
3. **Break is loud** (ADR-0015): a chain break raises an alert **and** a failing
   (non-zero) verification status; tune toward false-positive over false-negative.
4. **No secret hashed in clear** (ADR-0032 §5): the canonical form covers only the
   already-secret-free audit columns (ids/versions); a test asserts no secret field
   participates.
5. **K8s exec-argv discipline** (P1-W4-LESSONS **L3**): the verify CronJob wraps any
   `$(VAR)` in `sh -c "tool \"$VAR\""` — K8s does **not** substitute `$(VAR)` in exec
   argv. **L5**: any piped step inside the job uses `set -o pipefail` + `test -s`.

## Contracts / artifacts

- Alembic revision `0011` adding `prev_hash` / `entry_hash` to `audit_log` (up+down).
- Chain-write path (trigger or application, per ADR-0038) wired into the audit writer.
- Verification CronJob (Helm template) + Prometheus metric + alert rule.
- Verifier module (recompute + checkpoint) reusable by the test and the job.

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff (check + format), mypy strict, import-linter, pytest **≥80%** on the audit
  writer + verifier modules.
- **Tamper-detection** (the exit bite): seed a chain, mutate/delete a mid row →
  verifier flags the break at the right index; an untouched chain verifies clean.
- **Deterministic recompute**: same rows → identical `entry_hash` across runs;
  genesis seeds entry 1.
- **No-secret-in-hash**: assert the canonical field set excludes secret columns.
- **Migration round-trip**: `alembic upgrade head` then `downgrade -1` clean;
  `alembic heads` is a single head `0011`.
- **Append-only intact**: an UPDATE on `audit_log` still raises (0009 trigger).
- **Determinism**: suite pinned to `NullPool` SQLite (W6 flaky-concurrency lesson);
  fastapi route-introspection stays green (no lockfile — standing fact).
- Helm: kubeconform / conftest / kube-linter green on the CronJob (L3/L5 noted).

## Exit criteria

- [ ] Migration `0011` adds chain columns; up/down clean; single `alembic heads`.
- [ ] Per-insert `prev_hash` / `entry_hash` written per ADR-0038; append-only intact.
- [ ] Daily verify CronJob recomputes, emits metric, **alerts + non-zero on break**.
- [ ] Tamper-detection test bites; untouched chain verifies clean.
- [ ] No secret participates in the hash; L3 exec-argv + L5 pipefail applied.
- [ ] D16 + Helm manifest gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **Non-deterministic canonicalization** ⇒ a verifier that false-alarms, then gets
  "tuned" until it stops — masking real tampering. Implement ADR-0038's byte-exact
  form; the recompute test is the guard.
- **Checkpoint scale**: a full daily recompute may not scale on a large log;
  implement the ADR-0038 verified-checkpoint strategy rather than bolting one on.
- **L3 silent no-op**: a `$(VAR)` in the CronJob exec argv runs against a literal,
  so the verify job "passes" against nothing — wrap in `sh -c`, assert in a render test.
