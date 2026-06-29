# W5-T3 — G-* gate evidence doc + P3-Platform readiness; flip ADRs 0042–0048; PRODUCTION.md exit marker

| | |
|---|---|
| **Wave** | P3 W5 — Evals + phase-exit gate |
| **Owner** | `wf-release-auditor` (strong) |
| **Review tier** | **strong** quality |
| **Depends on** | **W5-T1**, **W5-T2**, **W4** (all controls + drills + gate promotion in place) |
| **ADRs** | flips 0042–0048; cites ADR-0033 §1 (named deferrals) |
| **PRODUCTION.md** | §11 (all five gates), §1 (exit marker) |
| **Status** | Proposed |

## Objective

The phase-exit gate (mirrors P1-W7-T4 / P2-W5-T3): re-evaluate each §11 gate against
**live repo/CI evidence** on the P3 release HEAD, write `P3-RELEASE-READINESS.md`,
and **on green** flip ADRs 0042–0048 → Accepted and add the `PRODUCTION.md` §1 P3
exit marker. Record the **reduced-scale mechanism-PASS + named certified-scale
ceiling** verdicts honestly; flip nothing that isn't biting.

## Scope

**In** — `docs/roadmap/P3-RELEASE-READINESS.md` with a per-gate verdict + a cited
HEAD artifact (green CI job + test/drill path, commit, manifest) per criterion; the
gate-bites confirmation (each cited gate RAN and BITES — drills' negative controls,
alerts' firing tests, the kind-promotion bite); the ADR 0042–0048 flips on their
implementing-wave evidence; the `PRODUCTION.md` §1 P3 exit marker + the P4
inheritance note; the named-deferral list.

**Out** — building any control (W1–W4); the eval corpora (W5-T1/T2); editing product
code (auditor is read-most + docs-write only).

## Requirements (grounded in PRODUCTION.md §11, ADR-0033 §1)

1. **Per-gate verdict, cited, on HEAD:**
   - **G-OBS — PASS (full):** every §6 SLO has a recording rule + burn-rate alert +
     runbook; dashboards exist; fault-injection MTTD < 5 min proven; export-lag
     within SLO (W3 + W5-T1).
   - **G-SCA — mechanism PASS at reduced scale + named ceiling:** scale-out/in,
     queue-burst isolation, load p95, PgBouncer budget bite on kind (W4-T6); the
     500/100/5,000 numbers **deferred-accepted → GA** with promotion path.
   - **G-REL — mechanism PASS at reduced scale + named ceiling:** failover (≤60 s,
     zero audit loss), Neo4j rebuild, idempotency, Celery ≥99%, compressed soak bite
     on kind (W4-T3/T4/T5/T7); 30-day calendar soak + certified-scale DR
     **deferred → GA**; P2 baseline holds.
   - **G-SEC — PASS (continuous + promotion):** P2 controls inherited; the kind-live
     mTLS + collector-deny now **blocking** (W4-T2, bite-proven); pentest +
     break-glass GA/operational, named.
   - **G-MNT — PASS:** D16 green; ADRs 0042–0048 Accepted; N-2 upgrade rehearsal
     green (W4-T8); dependency lockfile added (W0-T8); `PRODUCTION.md` amended.
2. **Gate-bites discipline** — every gate that flips an ADR is confirmed to RUN and
   BITE on HEAD (cite the negative control / firing test / bite proof). A gate green
   only at setup is not counted.
3. **Named deferrals, none silent** — certified-scale numbers, 30-day calendar soak,
   external pentest, 6-month break-glass, live-lab vendor golden-paths — each named
   with its promotion path (ADR-0033 §1).
4. **Flip only on green** — ADRs/roadmap flip in the same atomic commit only when the
   in-scope criteria are PASS on a green HEAD CI run (cite the run id + sha).
5. **Vault/MEMORY sync flagged** — the out-of-repo P3 status update is noted (not
   silently skipped).

## Contracts / artifacts

- `docs/roadmap/P3-RELEASE-READINESS.md`; ADR 0042–0048 status flips; `PRODUCTION.md`
  §1 P3 exit marker + P4 inheritance note.

## Test & gate plan

- All in-scope §11 gates PASS simultaneously on the release HEAD (cite the green CI
  run id + sha); each ADR-flipping gate confirmed to bite.
- D16 docs gates green; no product-code edits.

## Exit criteria

- [ ] `P3-RELEASE-READINESS.md` written: per-gate verdict + cited HEAD artifact; gate-bites confirmation; named deferrals + promotion paths.
- [ ] G-OBS full PASS; G-SCA/G-REL mechanism-PASS + named ceiling; G-SEC continuous + kind-promotion blocking; G-MNT PASS (incl. lockfile + N-2 rehearsal) — all on a green HEAD.
- [ ] ADRs 0042–0048 flipped Accepted (on implementing-wave green evidence); `PRODUCTION.md` §1 P3 exit marker + P4 inheritance added.
- [ ] Vault/MEMORY sync flagged; one atomic commit.

## Workflow

`wf-release-auditor` (strong) drafts the readiness doc + flips → **`wf-quality-reviewer` (strong)** audits the evidence → `wf-fixer` if findings → `wf-verifier` → one atomic commit. **Rebase onto `origin/main` first.**

## Risks

- **Flipping an ADR on a non-biting gate** → a false-green phase exit (the P1-W4
  trap at phase scale). Cite the bite for every flip.
- **Silently claiming certified scale** → dishonest exit. The named ceiling +
  promotion path is mandatory (the whole §0 posture).
- **Stale §1 marker / ADR list** → G-MNT drift; the marker and the plan/ADRs must agree.
