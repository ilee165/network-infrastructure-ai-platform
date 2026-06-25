# ADR-0040: Device Credential Rotation + Per-Credential Scoping

**Status:** Proposed | **Date:** 2026-06-25 | **Milestone:** P2 W0

## Context

`PRODUCTION.md` §5 requires device-credential rotation and least-privilege scoping.
The platform holds device login secrets in the credential vault (ADR-0011), wrapped
by the KMS envelope (ADR-0032). This ADR decides how to **rotate those device
secrets** and **scope each credential** so a compromise is blast-radius bounded. It
is the design gate; the build is **W4-T2** (`P2-SECURITY-PLAN.md` §3). The credential
vault is a secret surface (strong review).

**This is distinct from KEK/master-key rotation (ADR-0032 / P1 W6-T3).** That
rotates the envelope key; this rotates the *device* secrets inside the envelope. The
two are different keys at different layers and must not be conflated.

Bounded by ADR-0011 (`device_credentials` vault, scoping, audit), ADR-0032 §6 (KMS
envelope / re-wrap / no-leak), ADR-0020 (CR spine if a rotation drives a device
write).

## Decision

**A rotation job re-stores a device credential as a freshly KMS-wrapped DEK,
zeroizing the transient plaintext and never leaking it. Each credential is bound to
a scope (site / role / device-group); the credentials service refuses, structurally,
to open a session with an out-of-scope credential. Rotation is fail-closed: a failed
rotation never silently locks a device out. P2 rotates the stored copy only; any
on-device secret change routes through the four-eyes CR spine.**

### 1. Rotation path — re-wrap via the ADR-0032 envelope

A rotation generates/accepts a new device secret, wraps it as a new DEK via the
existing ADR-0032 provider, and updates the `device_credentials` vault row in place.
The transient plaintext is **zeroized** after wrap; it never reaches a log, trace,
audit row, queue, or cache (ADR-0032 §6). Trigger: a scheduled Helm-rendered
**CronJob** (cadence policy) and/or on-demand. Rotation emits audit events carrying
ids/versions only.

### 2. Per-credential scope — enforced at session open

`device_credentials` gains a **scope** binding (a `site` / `role` / `device_group`
relation or column; final shape in W4-T2's migration). The credentials service
**refuses to materialize** a credential for a target device outside its scope — a
structural code check at session open, not advisory documentation. A blast radius is
thereby bounded to the credential's scope.

### 3. Fail-closed posture

A failed rotation **leaves the prior credential valid and usable** (no lock-out);
the rotation is retried and, on repeated failure, the credential is marked
**degraded** with an alert (ADR-0015). A device is never left silently unreachable.
(Chosen over "invalidate-then-replace," which risks locking out the only working
credential.)

### 4. On-device change — deferred; CR spine if scoped in later

P2 rotates the platform's **stored copy** of the secret. Changing the secret **on
the device** is **out of P2 scope** (named-deferred); if a later wave scopes it in,
that device write goes through the ADR-0020 four-eyes ChangeRequest spine — never a
direct write. This keeps W4-T2 unambiguous.

### 5. Disjoint from KEK rotation (ADR-0032 / W6-T3)

This ADR governs device-secret rotation only. KEK/master-key rotation is ADR-0032
(shipped P1 W6-T3) and is cited, not re-implemented. W4-T2 shares no code path with
W6-T3.

### 6. Implementation note for W4-T2 (P1-W4-LESSONS)

- **L3:** the rotation Job wraps `$(VAR)` in `sh -c`.
- **L5:** piped job steps use `set -o pipefail` + `test -s`.

## Consequences

**Positive**
- Rotatable device secrets + enforced scope bound the blast radius of a credential
  compromise (least-privilege, §5).
- Re-wrap-through-envelope reuses ADR-0032; no new crypto, no plaintext leak.
- Fail-closed rotation removes the lock-out risk that makes operators avoid rotating.

**Negative**
- A scope model + enforcement adds a structural check on the hot session-open path
  (small cost; correctness over convenience).
- The stored-copy-only boundary means on-device secrets are not auto-synced in P2
  (named-deferred, CR-gated when added).
- Conflation with KEK rotation would re-implement W6-T3 — the §5 boundary must stay
  sharp (the W4-T2 review guards it).

## Alternatives considered

1. **One rotation mechanism for both device secrets and the KEK.** Rejected:
   different keys at different layers; merging them produces a W4-T2 that duplicates
   W6-T3. Keep the boundary sharp (§5).
2. **Invalidate-then-replace rotation.** Rejected: a botched rotation invalidating
   the only working credential takes a device offline; §3 is fail-closed instead.
3. **Advisory scope (documentation / labels only).** Rejected: an unenforced scope
   bounds nothing; enforcement at session open is a structural check (§2).
4. **Rotate the on-device secret in P2.** Rejected for scope: a device write that
   must be four-eyes-gated (ADR-0020) and vendor-specific; deferred with a named
   follow-up, stored-copy rotation lands first.
