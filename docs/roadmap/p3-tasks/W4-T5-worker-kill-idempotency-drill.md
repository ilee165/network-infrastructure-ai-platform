# W4-T5 — Worker-kill idempotency + Celery ≥99% success drill (real PG)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-reliability` (escalated — side-effecting tasks) |
| **Review tier** | **strong** spec + quality |
| **Depends on** | **W2-T4** (idempotency hardening), **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0008 (Celery `acks_late`), ADR-0020 (ChangeRequest) |
| **PRODUCTION.md** | §11 G-REL §319/§320 |
| **Status** | Proposed |

## Objective

Implement the G-REL §319/§320 drill: on the W4-T1 kind cluster, **kill a worker node
mid-run** and assert discovery/config jobs **complete via retry with no duplicate
side effect** (the W2-T4 idempotency), and **Celery success ≥ 99%** over the window.
Asserts against **real PG**. Ships with a negative control.

## Scope

**In** — the drill: enqueue side-effecting tasks (discovery write, CR-gated config
op, docs gen), kill a worker mid-run, assert each task completes exactly once (no
duplicate DB write, no double CR execution, no duplicate audit row) and the
success rate ≥ 99%; the negative control (`acks_late`/idempotency disabled →
duplicate side effect → red); real PG.

**Out** — the idempotency code (W2-T4); the KEDA manifests (W2-T3); the kind topology
(W4-T1); certified-scale soak success rate (the compressed window here; 30-day soak
named-deferred → W4-T7 compressed + GA).

## Requirements (grounded in ADR-0047/0008, PRODUCTION.md §11 G-REL §319/§320)

1. **Worker kill mid-run → complete via retry** — no task lost; no duplicate side
   effect (single DB write, single CR execution, single audit row). Asserted on
   **real PG** (SQLite hides the write-lock/isolation semantics — P2 lesson).
2. **Celery ≥ 99% success** after retries over the window.
3. **CR gate intact** — a retried CR-gated op does not bypass four-eyes or
   double-execute (ADR-0020).
4. **Negative control bites** — disable `acks_late`/idempotency → duplicate side
   effect → red.
5. **Reduced-scale, stated**; **L5 pipefail**.

## Contracts / artifacts

- Worker-kill drill harness (enqueue → kill → assert exactly-once + success rate);
  negative-control variant; CI wiring on the W4-T1 topology.

## Test & gate plan

- Drill on kind: worker kill → tasks complete once, success ≥ 99%, real PG.
- **Negative control:** idempotency off → duplicate side effect → red; revert.
- L5 pipefail; local/kind-runner first (L1).

## Exit criteria

- [ ] Worker-node kill mid-run → jobs complete via retry, **no duplicate side effect** (real PG).
- [ ] Celery success ≥ 99% over the window; CR gate not bypassed on retry.
- [ ] Negative control **bites** (duplicate on idempotency-off → red), then reverted.
- [ ] Scale stated; L5 pipefail; one atomic commit.

## Workflow

`wf-reliability` (escalated) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Asserting on SQLite** → races invisible; the duplicate-on-retry bug ships. Real PG.
- **A drill that doesn't actually kill the worker** → false green; the negative
  control proves the duplicate path is reachable.
- **Idempotency that bypasses the CR gate** → security regression; assert the gate holds.
