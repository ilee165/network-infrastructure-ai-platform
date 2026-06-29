# W0-T9 — PRODUCTION.md "P3 in progress" marker + Consultant §12 re-check

| | |
|---|---|
| **Wave** | P3 W0 — entry/roadmap |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | W0-T1..T7 (cites the new ADRs) |
| **Builds on** | `docs/roadmap/PRODUCTION.md` §1/§12, `docs/consultant/QUESTIONS.md` |
| **PRODUCTION.md** | §1 (phase table), §12 (Consultant dependencies), §11 G-MNT |
| **Status** | Proposed |

## Objective

Open the phase in the roadmap index: add a **"P3-Platform in progress"** marker to
`PRODUCTION.md` §1 (pointing at the ADRs 0042–0048 + the plan), and **re-check the
Consultant §12 open items** that materially shape P3 — scale targets, HA/DR
expectations, GPU availability, data retention — converting any answered items to
ADR updates and re-confirming PROPOSED defaults for the rest (the G-MNT §348
per-phase requirement).

## Scope

**In** — the §1 "P3 in progress" marker (mirrors the P2 exit-marker style); a
`docs/consultant/QUESTIONS.md` re-check note for the four P3-relevant open items;
re-confirmation (or conversion) of the PROPOSED defaults: certified-scale numbers
(G-SCA ceiling), RPO/RTO + Neo4j-Enterprise opt-in (§8/§3.2), Ollama GPU pool +
first-token SLO (§6), retention windows (SIEM/log/audit).

**Out** — the P3 *exit* marker (W5-T3, on green); answering the questions for the
customer (we re-confirm defaults; only the customer answers); any ADR re-decision.

## Requirements (grounded in PRODUCTION.md §1/§12, §11 G-MNT)

1. **Marker, not exit:** §1 records P3 as *in progress* and links the ADRs + plan;
   the green exit marker is W5-T3.
2. **§12 re-check recorded:** the four P3-relevant open items reviewed; defaults
   re-confirmed or converted to ADR updates — no silent default carry (§348).
3. **Ceiling numbers traceable:** the named-deferred G-SCA numbers (500/100/5,000 +
   30-day soak) are tied to the "scale targets" Consultant item so a future answer
   re-bases them cleanly.

## Contracts / artifacts

- `PRODUCTION.md` §1 marker; a §12 re-check note (in `docs/consultant/QUESTIONS.md`
  or the plan); no code.

## Test & gate plan

- D16 docs gates only. Cross-check: the marker's ADR list matches the ADRs created
  in W0-T1..T7 (no dangling reference).

## Exit criteria

- [ ] `PRODUCTION.md` §1 carries a "P3-Platform in progress" marker linking ADRs 0042–0048 + the plan.
- [ ] §12 re-check recorded for scale/HA-DR/GPU/retention; defaults re-confirmed or converted; no silent default.
- [ ] One atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Marker drift** — the §1 marker and the plan/ADRs must agree (the P2 "the two
  must agree" rule); a stale ADR list is a G-MNT finding.
