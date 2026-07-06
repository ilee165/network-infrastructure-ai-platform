# W0-T5 — `PRODUCTION.md` "P4 in progress" marker + Consultant §12 re-check + per-task specs + ADR index

| | |
|---|---|
| **Wave** | P4 W0 — entry/roadmap |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | W0-T1..T4 (cites the four ADRs) |
| **Builds on** | `docs/roadmap/PRODUCTION.md` §1/§12, `docs/consultant/QUESTIONS.md`, `docs/roadmap/p3-tasks/` (structure precedent), P3 W0-T9 (marker precedent) |
| **PRODUCTION.md** | §1 (phase table), §12 (Consultant dependencies), §11 G-MNT |
| **Status** | **Done** (W0, `feat/p4-w0-adrs` — this task's commit) |

## Objective

Open the phase in the roadmap index: add the **"P4 IN PROGRESS"** marker to
`PRODUCTION.md` §1 (mirroring the P3 IN PROGRESS marker — links the four ADRs +
the plan, records the validation posture, entry-not-exit); record the
**Consultant §12 re-check** for the four P4-relevant open items (compliance
regimes, data retention, flow telemetry, app-tagging ownership); author the
**per-task specs** `docs/roadmap/p4-tasks/` for ALL waves (W0–W4) mirroring the
p3-tasks structure; add **ADR index entries 0050–0053** (Proposed).

## Scope

**In** — the §1 marker; the §12 re-check recorded per the existing convention
(§1 marker bullet + `docs/consultant/QUESTIONS.md` "Phase kickoff re-checks"
entry + a new §12 row for the app-tagging-ownership item): *compliance regimes*
→ SOC 2 CC-series stays PROPOSED; *data retention* → 7-year audit stays
PROPOSED; *flow telemetry* → stays OUT of the dependency graph; *app-tagging
ownership* → write-path DECIDED (direct write, RBAC `engineer`+, full audit —
owner decision 2026-07-05), role floor still refinable; 22 per-task specs +
README with explicit exit criteria, owner agentType + review tier per the
P4-PLAN §3 table (with the ADR-0052 strong-escalation amendment), and
dependencies; ADR index rows 0050–0053.

**Out** — the P4 *exit* marker (W4-T4, on green); answering Consultant
questions for the owner; any ADR re-decision; edits to the four ADR files or
`P4-PLAN.md` (owned by T1–T4 / the plan).

## Requirements (grounded in PRODUCTION.md §1/§12, §11 G-MNT, P4-PLAN §5 W0)

1. **Marker, not exit:** §1 records P4 as *in progress*, links ADRs + plan +
   specs, and mirrors `P4-PLAN.md` §0/§1/§5 — the two must agree.
2. **§12 re-check recorded** with the four verdicts above; defaults
   re-confirmed or converted — no silent carry (G-MNT per-phase requirement).
3. **Specs must not contradict the ADRs** — content derives from P4-PLAN §3/§5
   and ADR-0050…0053; every spec carries explicit exit criteria.
4. **Index format preserved** — 0050–0053 rows follow the existing
   `| ADR | Title | Status | Decision |` shape, Status Proposed, Decision P4 W0.

## Contracts / artifacts

- `PRODUCTION.md` §1 marker + §12 row; `docs/consultant/QUESTIONS.md` P4
  kickoff entry; `docs/roadmap/p4-tasks/` (README + 22 specs);
  `docs/adr/README.md` rows 0050–0053. No code.

## Test & gate plan

- D16 docs gates only. Cross-checks: the marker's ADR list matches the ADRs
  created in W0-T1..T4 (no dangling reference); spec review-tier columns match
  the P4-PLAN §3 table + the recorded escalation amendment.

## Exit criteria

- [x] `PRODUCTION.md` §1 carries the "P4 IN PROGRESS 2026-07-05" marker linking ADRs 0050–0053 + plan + specs.
- [x] Consultant §12 re-check recorded (four items, verdicts above); app-tagging-ownership row added to the §12 table.
- [x] `docs/roadmap/p4-tasks/` specs exist for W0-T1..T5, W1-T1..T3, W2-T1..T4, W3-T1..T6, W4-T1..T4 + README, each with explicit exit criteria.
- [x] ADR index updated (0050–0053, Proposed).
- [x] One atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Marker drift** — the §1 marker and the plan/ADRs must agree (the P2 "the
  two must agree" rule); a stale ADR list or tier mismatch is a G-MNT finding.
- **Spec/ADR contradiction** — specs implement, never re-decide; each cites the
  binding ADR sections.
