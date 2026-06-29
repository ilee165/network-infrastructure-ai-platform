# W0-T8 — Dependency lockfile (backend + frontend) + CI drift assertion

| | |
|---|---|
| **Wave** | P3 W0 — build hygiene (closes the P1 systemic TODO) |
| **Owner** | `wf-infra` |
| **Review tier** | sonnet |
| **Depends on** | — |
| **Builds on** | ADR-0016 (testing/CI), ADR-0002 (backend stack) |
| **PRODUCTION.md** | §10 (upgrade/dep pinning), §11 G-MNT |
| **Status** | Proposed |

## Objective

Close the **P1 systemic TODO** ("add a dep lockfile — drift bit twice"): introduce
a reproducible **lockfile for backend and frontend** and a **CI assertion that
fails on drift**, landed in W0 **before** P3's new deps (CloudNativePG client,
KEDA-adjacent tooling, SIEM/syslog libs, promtool/k6 invocations) arrive — so the
drift that broke P1 CI twice (the `fastapi 0.137 include_router` break, root cause
"no lockfile") cannot re-bite during P3.

## Scope

**In** — a backend lockfile (pip-tools `requirements*.txt` hashes or `uv.lock`,
matching the existing toolchain) compiled from the declared deps; the frontend
lockfile assertion (`npm ci` against `package-lock.json`, fail on out-of-sync);
a CI step asserting the lockfile is in sync with the manifests (drift → red);
documentation of the regen procedure.

**Out** — upgrading any dep (lock the *current* resolved set; bumps are separate);
removing the existing `fastapi<0.137` cap (a follow-up once locked); the N-2
upgrade rehearsal (W4-T8).

## Requirements (grounded in P1 lesson, PRODUCTION.md §10, §11 G-MNT)

1. **Lock the current resolved set** — no version changes; the lockfile reflects
   what CI currently installs, so the baseline stays green.
2. **CI drift assertion bites** — a planted out-of-lock dependency (or a manifest
   edit without re-lock) **fails CI**; revert the negative after proving the bite
   (L1: prove a new gate bites before relying on it).
3. **`include_router` introspection still green** — the P1 trap; verify the
   route-introspection tests pass against the locked set.
4. **Regen documented** — the lock-update command is in the README/docs so future
   waves re-lock instead of drifting.

## Contracts / artifacts

- Backend lockfile + frontend lockfile-sync CI step; a CI job/step asserting drift
  fails; a short doc note on the regen procedure.

## Test & gate plan

- **Prove-it-bites (L1):** plant an out-of-lock dep → CI red → revert.
- Backend + frontend D16 gates green against the locked set; `include_router`
  introspection green.
- Run the lock + assertion **locally first** where it installs (L1: local ≠ CI).

## Exit criteria

- [ ] Backend + frontend lockfiles committed, reflecting the current resolved set (no bumps).
- [ ] CI drift assertion present and **proven to bite** (planted drift → red → reverted).
- [ ] `include_router` route-introspection green; regen procedure documented; one atomic commit.

## Workflow

`wf-infra` implements → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Locking a broken set** — lock the green current set, not a speculative upgrade.
- **A drift assertion that doesn't actually fail on drift** — the bite proof is
  mandatory (else it's a false-green gate that re-permits the drift it was added to stop).
