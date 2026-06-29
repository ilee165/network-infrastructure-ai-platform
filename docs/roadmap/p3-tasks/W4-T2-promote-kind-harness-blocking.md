# W4-T2 — Promote P2 kind-harness mTLS-handshake + collector-egress-deny to blocking

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-infra` (strong) |
| **Review tier** | **strong** spec + quality (G-SEC gate change) |
| **Depends on** | **W4-T1** (reliable kind topology) |
| **ADRs** | ADR-0048 (the contract), ADR-0039 (mTLS), ADR-0041 (collector segmentation), ADR-0016 (CI); `docs/runbooks/kind-harness.md` |
| **PRODUCTION.md** | §9, §11 G-SEC; P2-RELEASE-READINESS §5 (the P3 inheritance) |
| **Status** | Proposed |

## Objective

Close the P2 carry: move the two PARTIAL P2 kind-harness **live-enforcement**
sub-items — **mTLS api/worker↔pg handshake + plaintext-refused** and **collector
default-deny egress** — from `continue-on-error` into **blocking membership of
`all-gates`**, after proving each **BITES** on a planted regression. Update the
runbook to record the promotion.

## Scope

**In** — drop `continue-on-error` on the mTLS + collector-deny steps in
`kind-harness.sh`/`ci.yml` and add `kind-harness` (or those steps) to the
`all-gates needs` list; the **prove-it-bites** step (plant: plaintext allowed /
NetworkPolicy removed → gate red → revert); `docs/runbooks/kind-harness.md` updated
to record blocking status.

**Out** — the HA topology (W4-T1); the HA drills T3–T8 (those are G-REL/G-SCA, not
this G-SEC promotion); widening to any new security claim (promote only the two
named P2 sub-items, per ADR-0048).

## Requirements (grounded in ADR-0048, P2-RELEASE-READINESS §5, PRODUCTION.md §11 G-SEC)

1. **Promote, don't widen** — only the two named sub-items become blocking; no new
   claims.
2. **Prove-it-bites first** — the mTLS-handshake step goes red when plaintext is
   permitted; the collector step goes red when the default-deny egress policy is
   removed; both reverted after the bite is shown (P1-W4 + the explicit P2 carry
   "does NOT yet bite").
3. **In `all-gates`** — a regression now blocks merge (no orphan advisory gate); the
   `all-gates` aggregator fails if these steps fail.
4. **Runbook updated** — `kind-harness.md` records the promotion + the new blocking
   status.

## Contracts / artifacts

- `ci.yml` change (remove `continue-on-error`, add to `all-gates needs`); the
  bite-proof commits (planted + reverted); `kind-harness.md` update.

## Test & gate plan

- **Bite proof:** plaintext-allowed → mTLS step red; NetworkPolicy-removed →
  collector step red; revert both, gate green.
- `all-gates` fails when either step fails (verified on the planted regression).
- Local/kind-runner first (L1).

## Exit criteria

- [ ] mTLS-handshake + collector-egress-deny steps are **blocking** members of `all-gates` (no `continue-on-error`).
- [ ] Each **proven to bite** on a planted regression, then reverted.
- [ ] Scope limited to the two P2 sub-items; `kind-harness.md` updated; one atomic commit.

## Workflow

`wf-infra` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Promoting a non-biting gate** → a false-green *blocking* gate, worse than
  signal-only. The bite proof is mandatory.
- **Flaky kind** → blocks every merge. W4-T1 reliability is the prerequisite; if not
  met, do not promote.
- **Scope creep** to new security claims — promote only the two P2 sub-items.
