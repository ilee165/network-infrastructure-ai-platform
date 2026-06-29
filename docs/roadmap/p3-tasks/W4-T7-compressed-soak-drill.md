# W4-T7 — Compressed-soak drill (§6 SLOs hold over the compressed window)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-reliability` |
| **Review tier** | sonnet |
| **Depends on** | **W3** (recording rules + alerts), **W4-T1** (kind) |
| **ADRs** | ADR-0047 (drill harness), ADR-0046 (SLOs), ADR-0008 (Celery) |
| **PRODUCTION.md** | §11 G-REL §315/§321 |
| **Status** | Proposed |

## Objective

Implement a **compressed soak** on the W4-T1 kind cluster: drive steady synthetic
load over a **compressed window** (CI-runnable — e.g. tens of minutes, not 30 days)
and assert the §6 SLOs (W3-T2 recording rules) **hold** and no burn-rate alert
(W3-T3) fires spuriously. The **30-day calendar soak is named-deferred → GA**; this
proves the SLOs are *measurable and held* over a sustained-but-compressed run.

## Scope

**In** — a soak driver (steady mixed load: API reads, discovery/config/docs jobs)
over a compressed window; assertions that the §6 SLO recording rules stay within
budget and no alert fires (no leak/regression over time — connection growth, memory
creep, queue backlog); the explicit named-deferral of the 30-day calendar soak.

**Out** — the recording rules/alerts (W3); the kind topology (W4-T1); the 30-day
calendar soak (named-deferred → GA); chaos events (those are T3–T6).

## Requirements (grounded in ADR-0047/0046, PRODUCTION.md §11 G-REL §315)

1. **Steady load over a compressed window** — CI-runnable; the window length stated
   (and why it's representative of the mechanism, not the calendar SLA).
2. **SLOs held** — the §6 recording rules stay within budget for the window; no
   burn-rate alert fires.
3. **No slow regression** — connection counts, memory, and queue depth stay bounded
   (a leak that would surface over time shows as a trend → fail).
4. **30-day soak named-deferred → GA** — explicitly, with the promotion path; not
   claimed.
5. **L5 pipefail**; **L1** local/kind-runner first.

## Contracts / artifacts

- Soak driver + SLO-held assertions + trend/leak guards; CI wiring; the
  named-deferral note.

## Test & gate plan

- Drill on kind: compressed soak → SLOs held, no alert fires, no bounded-resource
  trend breach.
- L5 pipefail; local/kind-runner first (L1).

## Exit criteria

- [ ] Compressed-window soak runs in CI; §6 SLOs held, no burn-rate alert fires.
- [ ] No slow resource regression (connections/memory/queue bounded).
- [ ] **30-day calendar soak named-deferred → GA** (promotion path); window length stated; L5 pipefail; one atomic commit.

## Workflow

`wf-reliability` → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Over-claiming the 30-day SLA** from a 30-minute run → dishonest. Name the
  deferral; state the window.
- **Soak too short to surface a leak** → no signal. Long enough to show a trend, and
  guard bounded resources.
