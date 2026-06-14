# Security finding — Trivy base-image CVEs (backend image)

**Date:** 2026-06-14
**Source:** CI `docker (build images + Trivy scan)` job, run 27503147963 (`main` @ `700c5f6`)
**Status:** ACKNOWLEDGED — deferred to M4 hardening. Not a blocker for current development.
**Gate:** non-required CI check; does not block merges.

## Summary

The Trivy scan of `netops-backend:ci` fails the docker job because the image
contains **12 CVEs (2 CRITICAL, 10 HIGH)** at `severity: CRITICAL,HIGH` +
`exit-code: "1"` (`.github/workflows/ci.yml`). **All 12 are Debian 13 (trixie)
base-image OS packages — none are in our Python application dependencies — and
every one is currently `fix_deferred` / `affected`, i.e. Debian has released no
fixed version. Fixable today = 0.**

## Findings

| Package | Example CVEs | Severity | Status | Fix |
|---------|-------------|----------|--------|-----|
| `perl-base` (perl-archive-tar, Archive::Tar, IO::Compress/Uncompress) | CVE-2026-42496, CVE-2026-42497, CVE-2026-48959, CVE-2026-48962, CVE-2026-9538, CVE-2026-8376 | CRITICAL + HIGH | fix_deferred / affected | none available |
| `libsqlite3-0` | CVE-2026-11822, CVE-2026-11824 | HIGH | affected | none available |
| `libncursesw6` / `libtinfo6` | CVE-2025-69720 | HIGH | affected | none available |

## Exploitability assessment (current usage)

- **perl-base** is a transitive Debian OS package; the backend is Python/FastAPI
  and never invokes perl to extract untrusted tar/zip archives → the
  archive-traversal / archive RCE vectors are not reachable through our code.
- **libsqlite3-0**: production datastore is PostgreSQL (asyncpg); sqlite
  (`aiosqlite`) is used only by the offline test suite. The CVEs require
  processing a malicious SQLite database → not exposed at runtime.
- **ncurses**: not used at runtime.
- The platform is **not deployed** (M0–M3 complete; M4 next), so there is no
  live, network-exposed instance.

Conclusion: **no emergency.** These are unpatched-upstream OS CVEs in a
not-yet-released image, off the reachable attack surface.

## Remediation — schedule for M4 (or a dedicated hardening pass)

Pick one (recommended order):

1. **`ignore-unfixed: true`** on both `aquasecurity/trivy-action` steps in
   `ci.yml`. Makes the gate *actionable*: it fails only when a fix EXISTS and we
   have not applied it, instead of on upstream-unpatched OS CVEs. Lowest effort,
   highest signal-to-noise. Strongly recommended regardless of the others.
2. **Shrink the base image.** Move `deploy/docker/backend.Dockerfile` to a
   minimal runtime (e.g. `python:3.x-slim` on the newest Debian point release,
   or a distroless / Chainguard Python base) that excludes `perl`/`ncurses`
   entirely — removes most of these packages from the image.
3. **`.trivyignore`** for the specific unpatched CVE IDs above, each with a
   one-line justification + a re-review date, if a CVE must be temporarily
   accepted.

Re-run `gh run view --job <docker-job-id> --log` after any change to confirm the
Trivy step passes. Re-check whether Debian has since published fixes (status
moves off `fix_deferred`).

## Related
- CI docker job history / Trivy gate: tracked in agent memory `docker-ci-job-broken`.
