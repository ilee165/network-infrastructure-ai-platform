# W0-T9 — `PRODUCTION.md` §1 Re-scope Amendment (HA/scale-out + SIEM + obs-SLO → P3-Platform)

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet spec + sonnet quality (roadmap doc edit; no code, no secret surface) |
| **Depends on** | W0-T1..T8 (the amendment cites the ADRs it leaves in P2-Security) |
| **ADRs** | none new — this is a **sequencing change, not a decision reversal** (P2-SECURITY-PLAN.md §0); no superseding ADR |
| **PRODUCTION.md** | §1 (phase table — the row being split), §11 G-MNT §308 (no silent drift) |
| **Status** | Proposed |

## Objective

Record the §0 re-scope **in the master roadmap**: amend `PRODUCTION.md` §1 to move
the HA/scale-out track, audit→SIEM export, and observability-SLO enforcement out
of P2 into a new **P3-Platform** phase, with **dated rationale**, and renumber the
downstream phases. This is the task that makes the re-scope **not silent**
(G-MNT §308). Last task in W0 — it cites the ADRs that stay in P2-Security.

## Scope

**In**
- Edit `PRODUCTION.md` §1: split the current "P2" row into **P2-Security**
  (Vendor Wave 2 + Security Agent + the kind-validatable hardening subset) and
  **P3-Platform** (HA + scale-out: api HPA, KEDA workers, CloudNativePG, Redis
  Sentinel, PgBouncer; audit→SIEM export; obs-SLO recording-rules/alerts/
  dashboards + fault-injection MTTD; N-2 upgrade rehearsal).
- **Dated rationale** inline (2026-06-25): these require a live/certified-scale
  cluster to *validate*; on a no-hardware host they would be ~entirely
  deferred-accepted — quarantining them keeps P2-Security's gates honest (verbatim
  the §0 reasoning).
- **Renumber downstream**: the former Wave-3 (F5/VMware + app-topology +
  compliance) and Wave-4 (cloud + hybrid) phases shift accordingly; update every
  in-doc cross-reference (§2.4/§2.5 wave headers, gate refs) to the new numbers.
- Name the **deferred gates** explicitly in the amended table: **G-SCA** and the
  **G-REL live failover/soak/scale drills** → P3-Platform (mirror
  P2-SECURITY-PLAN.md §5).

**Out**
- The P3-Platform *plan itself* — authored when P2-Security exits (P2-SECURITY-PLAN.md §6).
- Any binding D1–D16 change — none; this is sequencing only (§0).
- Editing ADR-0034..0041 statuses — that is W5-T3 (flip to Accepted on green).

## Requirements (grounded in P2-SECURITY-PLAN.md §0, G-MNT §308)

1. **Recorded, not silent** (G-MNT §308): the move appears in the master roadmap
   with a dated rationale; cross-checks against P2-SECURITY-PLAN.md §0 (the two
   must agree — no drift between the plan and the roadmap).
2. **Sequencing, not reversal** (§0): no D1–D16 decision is overturned, so **no
   superseding ADR** is created; the amendment notes this explicitly.
3. **Deferred gates named** (§5): G-SCA + G-REL-live are listed as
   deferred-accepted → P3-Platform, never dropped.
4. **No orphan references**: every downstream wave/gate cross-reference in
   `PRODUCTION.md` resolves after renumbering.

## Contracts / artifacts

- `docs/roadmap/PRODUCTION.md` §1 (amended phase table + dated rationale note) and
  any §2.x wave headers / gate refs that renumber.

## Validation / Test & gate plan (doc review)

- **Consistency:** `PRODUCTION.md` §1 ↔ `P2-SECURITY-PLAN.md` §0/§1/§5 agree on
  what is in P2-Security vs P3-Platform and which gates defer.
- **No orphan cross-refs** after renumber (grep the doc for stale wave/phase numbers).
- markdownlint; links resolve.

## Exit criteria

- [ ] `PRODUCTION.md` §1 split into P2-Security / P3-Platform with dated rationale.
- [ ] Downstream phases renumbered; all in-doc cross-references updated, no orphans.
- [ ] G-SCA + G-REL-live named deferred-accepted → P3-Platform.
- [ ] "Sequencing not reversal; no superseding ADR" stated.
- [ ] `PRODUCTION.md` ↔ `P2-SECURITY-PLAN.md` consistent; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-implementer` edits roadmap → `wf-spec-reviewer` (sonnet) + `wf-quality-reviewer`
(sonnet) → `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Drift between plan and roadmap**: if §1 and the P2-SECURITY-PLAN §0 disagree,
  G-MNT §308 fails at W5. The consistency cross-check is the guard.
- **Stale cross-references after renumber**: a missed §2.4→§2.x ref points at the
  wrong wave; grep for every phase/wave number before committing.
