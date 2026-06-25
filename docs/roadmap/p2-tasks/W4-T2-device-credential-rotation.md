# W4-T2 — Device-Credential Rotation Job + Per-Credential (Site/Role) Scoping

| | |
|---|---|
| **Wave** | P2 W4 — Security hardening + kind validation (credential stream) |
| **Owner** | `wf-implementer` (strong — credential vault; device-secret blast radius) |
| **Review tier** | **strong** spec + **strong** quality (secret-surface: credential vault) |
| **Depends on** | **W0-T7** (ADR-0040); independent of the audit (T1) + network (T3–T5) streams |
| **ADRs** | ADR-0040 (the contract this builds), ADR-0011 (`device_credentials` vault, scoping, audit), ADR-0032 §6 (KMS envelope / re-wrap, no-leak — disjoint from KEK rotation / W6-T3), ADR-0020 (CR spine for any on-device write) |
| **PRODUCTION.md** | §5 (credential rotation + least-privilege scoping), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement exactly what **ADR-0040** ratified: a **rotation job** that re-issues /
re-stores a device login secret (new secret → re-wrapped DEK via the existing
ADR-0032 envelope) without ever exposing plaintext, plus **per-credential scoping**
(site / role / device-group) enforced **structurally** at session open so a
compromised credential is blast-radius bounded. Distinct from **KEK/master-key
rotation** (ADR-0032 / W6-T3) — this rotates *device* secrets inside the envelope,
not the envelope key.

## Scope

**In** (`backend/app/` credentials service + a scope model/migration + a
Helm-rendered Job + tests)
- **Rotation path**: re-store a device credential — new secret → re-wrapped DEK via
  the ADR-0032 provider — updating the vault row in place; **transient plaintext is
  zeroized**; trigger + cadence per ADR-0040 (scheduled Job and/or on-demand).
- **Per-credential scope** (ADR-0011): a `scope` model on `device_credentials`
  (column/relation per ADR-0040) binding a credential to a site / role /
  device-group; **migration** (head `0011`→`0012`, or sequence after W4-T1's `0011`).
- **Structural enforcement**: the credentials service **refuses** to open a session
  with a credential whose scope does not cover the target device — a code check, not
  documentation.
- **Confirm-then-swap, fail-closed** (per ADR-0040 §1/§3): stage the new wrapped
  credential, **verify it against the device**, then activate — never overwrite the
  only working secret in place. A failed rotation discards the unconfirmed credential
  (prior stays valid, no lock-out), retries, then marks degraded + alerts on repeated
  failure; the device outcome is never ambiguous, never silently unreachable.
- **On-device change**: if ADR-0040 scoped the device-side secret change **in**, it
  routes through the ADR-0020 CR spine (four-eyes); if deferred, only the stored copy
  rotates — implement whichever ADR-0040 fixed.
- **Audit + no-leak** (ADR-0011 / ADR-0032 §6): rotation emits audit events
  (ids/versions only); plaintext never logged, queued, cached, or returned.

**Out**
- ADR / scope-model / fail-closed decision → **W0-T7** (this implements it).
- **KEK / master-key rotation** → ADR-0032 / W6-T3 (shipped in P1) — stays disjoint.
- audit / mTLS / network controls → W4-T1, T3–T5.

## Requirements (grounded in ADR-0040, ADR-0011, ADR-0032 §6, ADR-0020)

1. **No plaintext leak** (ADR-0032 §6): rotation re-wraps via the envelope; transient
   plaintext zeroized; a test asserts no secret reaches an audit/trace row or a log.
2. **Scope enforced, not advisory** (ADR-0011 least-privilege): a session-open with
   an out-of-scope credential is **refused** — a structural test proves the deny.
3. **Fail-closed** (secure-by-default): a simulated rotation failure leaves the device
   reachable via the prior credential **or** degrades-and-alerts per ADR-0040; never
   a silent lock-out.
4. **Disjoint from KEK rotation** (ADR-0032 / W6-T3): this rotates device secrets, not
   the envelope key; no overlap with the W6-T3 code path.
5. **K8s exec-argv discipline** (P1-W4-LESSONS **L3**): the rotation Job wraps `$(VAR)`
   in `sh -c`. **L5**: piped job steps use `set -o pipefail` + `test -s`.

## Contracts / artifacts

- Rotation Job (Helm template) re-wrapping the DEK via the ADR-0032 provider.
- Scope model on `device_credentials` (+ Alembic migration) and enforcement in the
  credentials service at session open.
- Audit events for rotation (ids/versions only).

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff (check + format), mypy strict, import-linter, pytest **≥80%** on the rotation
  path + scope enforcement.
- **No-leak invariant** (the exit bite): after rotation, no plaintext in vault row /
  audit rows / logs; the DEK is a fresh wrap.
- **Scope-deny**: an out-of-scope credential→target session-open raises; an in-scope
  one succeeds.
- **Fail-closed**: a forced rotation failure leaves the prior credential usable (or
  degraded+alerted per ADR-0040) — device never silently unreachable.
- **Migration round-trip**: scope migration up/down clean; single `alembic heads`.
- **Determinism**: `NullPool` SQLite; fastapi route-introspection green (no lockfile).
- Helm: kubeconform / conftest / kube-linter green on the Job (L3/L5 noted).

## Exit criteria

- [ ] Rotation re-wraps via the ADR-0032 envelope; transient plaintext zeroized.
- [ ] Scope model + migration landed; session-open enforces scope (deny test green).
- [ ] Fail-closed posture per ADR-0040 implemented + tested (no silent lock-out).
- [ ] No-leak invariant test bites; audit events carry ids/versions only.
- [ ] Disjoint from W6-T3 KEK rotation; L3 exec-argv + L5 pipefail applied.
- [ ] D16 + Helm manifest gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **Conflation with KEK rotation** (ADR-0032): different keys at different layers; a
  blurred boundary re-implements W6-T3. Keep the device-secret path sharp.
- **Rotation locks out a device** (no fail-closed): a botched rotation invalidating
  the only working credential takes a device offline — the ADR-0040 fail-closed
  decision is the guard; the test proves it.
- **Scope as documentation** instead of a code check: an advisory scope bounds
  nothing. Enforce at session open; the deny test is the proof.
