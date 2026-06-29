# W0-T7 — ADR-0048 kind-harness gate promotion (mTLS + collector-deny → blocking)

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | — |
| **Builds on** | ADR-0039 (mTLS between containers), ADR-0041 (collector egress NetworkPolicy), ADR-0016 (CI/CD), `docs/runbooks/kind-harness.md` |
| **PRODUCTION.md** | §9, §11 G-SEC; the P2-RELEASE-READINESS §5 P3 inheritance |
| **Status** | Proposed |

## Objective

Ratify the decision to **promote the P2 kind-harness *live-enforcement* run from
`continue-on-error` to a blocking member of `all-gates`** — the two PARTIAL P2
sub-items (mTLS api/worker↔pg handshake + plaintext-refused, collector default-deny
egress) become biting gates. Fix the prerequisites (the W4-T1 HA/enforcing-CNI kind
topology) and the proof-it-bites requirement before promotion.

## Scope

**In** — the gate-policy change (move `kind-harness.sh` live assertions into
`all-gates needs`, drop `continue-on-error` on the mTLS + collector-deny steps);
the prerequisite (a reliable enforcing-CNI kind cluster, W4-T1); the
**proof-it-bites** requirement (a planted regression — async plaintext allowed,
NetworkPolicy removed — must turn the gate red before promotion); the
`docs/runbooks/kind-harness.md` update recording the promotion.

**Out** — building the kind topology (W4-T1); the actual promotion commit (W4-T2);
the HA-drill gates (those are G-REL/G-SCA, ADR-0047), not this G-SEC promotion.

## Requirements (grounded in P2-RELEASE-READINESS §5, PRODUCTION.md §9/§11 G-SEC)

1. **Promote, don't widen:** only the two named P2 sub-items (mTLS handshake +
   plaintext refused; collector default-deny egress) move to blocking. No new
   security claims.
2. **Prove-it-bites first:** the gate must be shown to go red on a planted
   regression (the P1-W4 lesson + the explicit P2 carry that the live run "does NOT
   yet bite"). Promotion without a bite proof is forbidden.
3. **CI stability:** the kind bring-up must be reliable enough to be `all-gates`-
   blocking (no flakiness that blocks merges) — depends on the W4-T1 topology.
4. **Runbook updated:** `docs/runbooks/kind-harness.md` records the promotion and
   the new blocking status (closes the P2 "promotion path" note).

## Contracts / artifacts

- `docs/adr/0048-kind-harness-gate-promotion.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only. The ADR names exactly which `ci.yml` steps W4-T2 moves into
  `all-gates` and the bite-proof it must show.

## Exit criteria

- [ ] ADR-0048 written: which steps promote; prove-it-bites prerequisite; CI-stability prerequisite (W4-T1); runbook-update requirement.
- [ ] Scope limited to the two P2 sub-items (no new claims); ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Promoting a flaky gate** → blocks every merge. The W4-T1 stability prerequisite
  is mandatory before promotion.
- **Promoting a non-biting gate** → a false-green blocking gate, worse than
  `continue-on-error`. The bite proof is non-negotiable.
