# W0-T6 — ADR-0047 Reliability/scale drill harness + N-2 upgrade rehearsal (reduced-scale + named-ceiling stance)

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | — |
| **Builds on** | ADR-0030 (backup/DR baseline), ADR-0029 (Helm GA), ADR-0008 (Celery), ADR-0005 (Neo4j projection rebuild), ADR-0016 (testing/CI) |
| **PRODUCTION.md** | §8 (DR drills), §10 (upgrade), §11 G-REL/G-SCA/G-MNT |
| **Status** | Proposed |

## Objective

Ratify the drill-harness design and — critically — the **reduced-scale +
named-ceiling validation posture** (P3-PLATFORM-PLAN §0, user decision 2026-06-29).
Fix: the drills run against an **ephemeral HA kind cluster** at reduced scale, each
with a **negative control** that proves it bites; the certified-scale numbers
(500-device / 100-user / 5,000-device / 30-day soak) are **deferred-accepted → GA**
with a **written promotion path**; and the N-2 → N upgrade rehearsal shape
(expand/contract + rolling order + Neo4j rebuild on seeded data).

## Scope

**In** — the drill catalogue + their §11 criteria + target numbers (failover ≤60 s
+ zero audit loss, Neo4j rebuild ≤ topology-RTO, worker-kill idempotency, Celery
≥99%, queue-burst isolation, load p95, compressed soak); the **drill-as-test +
negative-control** rule; the **reduced-scale posture** and the explicit
**promotion path** to certified scale; the N-2 upgrade rehearsal procedure
(expand/contract migration, Celery warm-shutdown rolling order, post-upgrade Neo4j
rebuild, N-1/N-2 seed dataset).

**Out** — the kind topology itself (ADR-0048 + W4-T1); the drills' implementation
(W4-T3..T8); procuring real hardware (declined, §0).

## Requirements (grounded in PRODUCTION.md §8/§10/§11)

1. **Reduced-scale, mechanism-proving:** each drill proves the mechanism on kind at
   reduced scale; states the scale it ran at.
2. **Named ceiling + promotion path:** 500-device / 100-user / 5,000-device /
   30-day soak deferred-accepted → GA/customer cluster; the promotion path is
   written here (what hardware + what re-run flips it to full PASS). ADR-0033 §1
   discipline — named, never silent.
3. **Drill-as-test + negative control:** every drill ships a planted regression
   that turns it red (async audit path, removed PDB, disabled KEDA trigger) — the
   anti-false-green guard (P1-W4 lesson).
4. **Real-PG assertions:** idempotency / audit-loss drills assert against real PG,
   never SQLite (P2 lesson).
5. **Upgrade rehearsal:** expand/contract (PRODUCTION.md §10) + rolling order +
   Neo4j rebuild on a seeded N-2 dataset (G-MNT §346).

## Contracts / artifacts

- `docs/adr/0047-reliability-scale-drill-harness.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only. The ADR is the contract W4-T3..T8 implement; it names each
  drill's assertion + negative control + the deferred ceiling.

## Exit criteria

- [ ] ADR-0047 written: drill catalogue + §11 targets; reduced-scale posture; **named ceiling + written promotion path**; drill-as-test + negative-control rule; real-PG rule; N-2 upgrade procedure.
- [ ] ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Posture drift to "we validated at scale"** — the ADR must keep the ceiling
  named-deferred so W5 can't over-claim.
- **A drill that asserts nothing** — the negative-control rule is the guard; it
  belongs in the ADR.
