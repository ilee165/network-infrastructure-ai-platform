# W0-T7 — ADR-0040 Device Credential Rotation + Per-Credential Scoping

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** spec + **strong** quality (credential vault — the device-secret blast radius) |
| **Depends on** | — (independent of T1–T6) |
| **ADRs** | ADR-0011 (`device_credentials` vault, scoping, audit), ADR-0032 (KMS envelope / KEK — distinguish from KEK rotation in W6-T3), ADR-0020 (CR spine if a rotation drives a device write) |
| **PRODUCTION.md** | §5 (credential rotation + least-privilege scoping), §11 G-SEC |
| **Status** | Proposed |

## Objective

Decision record for **rotating the device login secrets the platform holds** and
**scoping each credential** (by site / role) so a compromise is blast-radius
bounded. This is distinct from **KEK/master-key rotation** (ADR-0032 / W6-T3) —
this rotates the *device* secrets inside the envelope, not the envelope key.
Design gate; build is **W4-T2**.

## Scope

**In**
- **Rotation job:** re-issues / re-stores a device credential (new secret →
  re-wrapped DEK via the existing ADR-0032 envelope), updating the vault row
  without ever exposing plaintext. Decide trigger (scheduled CronJob and/or
  on-demand) and cadence policy.
- **Per-credential scoping** (ADR-0011): a credential is bound to a **scope**
  (site / role / device-group) so it can only be used against devices in that
  scope — bounding blast radius. Decide the scope model (a column/relation on
  `device_credentials`) and how the credentials service enforces it at session open.
- **Rotation ↔ device-side change**: if rotating the platform's stored secret must
  also change the secret *on the device*, that device write goes through the
  ADR-0020 CR spine (four-eyes); decide whether P2 scopes the on-device change in
  or only rotates the stored copy (recommend: scope the on-device write decision
  explicitly to avoid ambiguity).
- **Audit + no-leak** (ADR-0011 / ADR-0032 §6): rotation emits audit events
  (ids/versions only); plaintext secret never logged, queued, cached, or returned.

**Out**
- Implementation (rotation job, scope column + enforcement, tests) → **W4-T2**.
- **KEK / master-key rotation** → ADR-0032 / W6-T3 (already shipped in P1) — this
  ADR cites it and stays disjoint.
- mTLS / network controls → W0-T6 / W0-T8.

## Requirements (grounded in ADR-0011, ADR-0032 §6, ADR-0020)

1. **No plaintext leak** (ADR-0032 §6): rotation re-wraps via the envelope; the
   transient plaintext is zeroized; no secret reaches an audit/trace row or a log.
2. **Scope is enforced, not advisory** (ADR-0011 least-privilege): the credentials
   service refuses to open a session with a credential outside the target's scope —
   a structural check, not documentation.
3. **Fail-closed on rotation failure** (secure-by-default, **settled by ADR-0040
   §1/§3**): rotation is **confirm-then-swap** — stage + verify the new credential
   against the device, then activate; never overwrite the only working secret in
   place. A failed rotation discards the unconfirmed credential, leaving the prior
   one valid (no lock-out), retries, then marks it degraded + alerts on repeated
   failure. A device is never left unreachable silently.
4. **K8s exec-argv discipline** (P1-W4-LESSONS **L3**): the rotation Job wraps
   `$(VAR)` in `sh -c` (recorded for W4-T2).
5. **CR spine for device writes** (ADR-0020): any on-device secret change is a
   four-eyes ChangeRequest, never a direct write.

## Contracts / artifacts

- Rotation Job (Helm-rendered) re-wrapping the DEK via the ADR-0032 provider.
- Scope model on `device_credentials` (+ enforcement in the credentials service).
- Audit events for rotation (ids/versions only).

## Validation / Test & gate plan (ADR review — strong)

- Repo ADR template; the **rotation-vs-KEK-rotation** distinction is explicit
  (no overlap with ADR-0032 / W6-T3).
- Scope-enforcement is described as a structural service check; the no-leak
  invariant is testable (a W4-T2 exit criterion).
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0040 written; status **Proposed**.
- [ ] Rotation mechanism (re-wrap, trigger, cadence) decided; fail-closed posture fixed.
- [ ] Per-credential scope model + enforcement-at-session-open decided.
- [ ] On-device-change scope decision (in P2 vs deferred) recorded; CR spine cited.
- [ ] No-leak invariant + L3 exec-argv named for W4-T2.
- [ ] Distinction from ADR-0032 KEK rotation stated; ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` writes ADR → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Conflation with KEK rotation** (ADR-0032): the two are different keys at
  different layers; an ADR that blurs them produces a W4-T2 that re-implements
  W6-T3. Keep the boundary sharp.
- **Rotation locking out a device** (no fail-closed): a botched rotation that
  invalidates the only working credential takes a device offline. The fail-closed
  decision must be in the ADR.
