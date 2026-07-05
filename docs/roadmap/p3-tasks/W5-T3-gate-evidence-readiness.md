# W5-T3 — G-* gate evidence doc + P3-Platform readiness; flip ADRs 0042–0047 (0048 stays Rejected); PRODUCTION.md exit marker

| | |
|---|---|
| **Wave** | P3 W5 — Evals + phase-exit gate |
| **Owner** | `wf-release-auditor` (strong) |
| **Review tier** | **strong** quality |
| **Depends on** | **W5-T1**, **W5-T2**, **W4** (all controls + drills in place; kind-harness live-run stays opt-in signal-only — ADR-0048 Rejected, no promotion) |
| **ADRs** | flips 0042–0047 → Accepted; **ADR-0048 stays Rejected** (kind-harness gate promotion abandoned, cite as-is); cites ADR-0033 §1 (named deferrals) |
| **PRODUCTION.md** | §11 (all five gates), §1 (exit marker) |
| **Status** | Proposed |

## Objective

The phase-exit gate (mirrors P1-W7-T4 / P2-W5-T3): re-evaluate each §11 gate against
**live repo/CI evidence** on the P3 release HEAD, write `P3-RELEASE-READINESS.md`,
and **on green** flip ADRs 0042–0047 → Accepted (ADR-0048 stays **Rejected** — the
kind-harness promotion was abandoned 2026-07-03; its two controls stay statically +
runtime enforced) and add the `PRODUCTION.md` §1 P3 exit marker. Record the
**reduced-scale mechanism-PASS + named certified-scale ceiling** verdicts honestly;
flip nothing that isn't biting.

## Scope

**In** — `docs/roadmap/P3-RELEASE-READINESS.md` with a per-gate verdict + a cited
HEAD artifact (green CI job + test/drill path, commit, manifest) per criterion; the
gate-bites confirmation (each cited gate RAN and BITES — drills' negative controls,
alerts' firing tests); the ADR 0042–0047 flips on their implementing-wave evidence;
**reconciling the stale kind-promotion language** in `P3-PLATFORM-PLAN.md` and
`PRODUCTION.md §11` to the ADR-0048 Rejected reality (no blocking kind gate); the
`PRODUCTION.md` §1 P3 exit marker + the P4 inheritance note; the named-deferral list.

**Out** — building any control (W1–W4); the eval corpora (W5-T1/T2); editing product
code (auditor is read-most + docs-write only).

## Requirements (grounded in PRODUCTION.md §11, ADR-0033 §1)

1. **Per-gate verdict, cited, on HEAD:**
   - **G-OBS — PASS (full):** every §6 SLO has a recording rule + burn-rate alert +
     runbook; dashboards exist; fault-injection MTTD < 5 min proven; export-lag
     within SLO (W3 + W5-T1).
   - **G-SCA — mechanism PASS at reduced scale + named ceiling:** scale-out/in,
     queue-burst isolation, load p95, PgBouncer budget drills bite at reduced scale
     (W4-T6); the drills run under the **opt-in / continue-on-error kind job**
     (signal-only, not a blocking CI gate — ADR-0048 Rejected), so cite the drill's
     own planted-regression bite, not a blocking gate; the 500/100/5,000 numbers
     **deferred-accepted → GA** with promotion path.
   - **G-REL — mechanism PASS at reduced scale + named ceiling:** failover (≤60 s,
     zero audit loss), Neo4j rebuild, idempotency, Celery ≥99%, compressed soak
     drills bite at reduced scale (W4-T3/T4/T5/T7) under the **opt-in /
     continue-on-error kind job** (signal-only — cite each drill's planted-regression
     bite, not a blocking gate); 30-day calendar soak + certified-scale DR
     **deferred → GA**; P2 baseline holds.
   - **G-SEC — PASS (continuous):** P2 controls inherited and continuously enforced;
     the mTLS (api/worker↔postgres) + collector egress-deny controls stay enforced by
     **static rego (`conftest` pg_hba weak-hostssl) + NetworkPolicy render tests +
     the P2 baseline** — **NOT** a blocking kind gate (W4-T2 promotion abandoned,
     ADR-0048 Rejected 2026-07-03; the live kind-harness mTLS/collector run stays
     opt-in / continue-on-error / signal-only); pentest + break-glass GA/operational,
     named.
   - **G-MNT — PASS:** D16 green; ADRs 0042–0047 Accepted (ADR-0048 recorded
     Rejected); N-2 upgrade rehearsal green (W4-T8); dependency lockfile added
     (W0-T8); `PRODUCTION.md` amended (incl. kind-promotion language reconciled).
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

- `docs/roadmap/P3-RELEASE-READINESS.md`; ADR 0042–0047 status flips (0048 unchanged,
  Rejected); reconciled kind-promotion language in `P3-PLATFORM-PLAN.md` +
  `PRODUCTION.md §11`; `PRODUCTION.md` §1 P3 exit marker + P4 inheritance note.

## Test & gate plan

- All in-scope §11 gates PASS simultaneously on the release HEAD (cite the green CI
  run id + sha); each ADR-flipping gate confirmed to bite.
- D16 docs gates green; no product-code edits.

## Exit criteria

- [ ] `P3-RELEASE-READINESS.md` written: per-gate verdict + cited HEAD artifact; gate-bites confirmation; named deferrals + promotion paths.
- [ ] G-OBS full PASS; G-SCA/G-REL mechanism-PASS + named ceiling (drills bite under opt-in signal-only kind job); G-SEC continuous (mTLS/collector-deny static+runtime enforced, no blocking kind gate); G-MNT PASS (incl. lockfile + N-2 rehearsal) — all on a green HEAD.
- [ ] ADRs 0042–0047 flipped Accepted (on implementing-wave green evidence); ADR-0048 left Rejected; stale kind-promotion language reconciled in `P3-PLATFORM-PLAN.md` + `PRODUCTION.md §11`; `PRODUCTION.md` §1 P3 exit marker + P4 inheritance added.
- [ ] Vault/MEMORY sync flagged; one atomic commit.

## Workflow

`wf-release-auditor` (strong) drafts the readiness doc + flips → **`wf-quality-reviewer` (strong)** audits the evidence → `wf-fixer` if findings → `wf-verifier` → one atomic commit. **Rebase onto `origin/main` first.**

## Risks

- **Flipping an ADR on a non-biting gate** → a false-green phase exit (the P1-W4
  trap at phase scale). Cite the bite for every flip.
- **Silently claiming certified scale** → dishonest exit. The named ceiling +
  promotion path is mandatory (the whole §0 posture).
- **Stale §1 marker / ADR list** → G-MNT drift; the marker and the plan/ADRs must agree.
- **Flipping/claiming a kind-promotion that was abandoned** → false G-SEC. ADR-0048
  is Rejected; W4-T2 did not ship. Do NOT cite a blocking kind gate or flip 0048;
  the plan/`PRODUCTION.md` text that still says "promote to blocking" must be
  corrected in this same commit, not left to contradict the ADR.
