# Architecture Debt & Developer Experience

Production readiness audit, 2026-07-09 (HEAD `5403c3b`). Backend ~3589 unit tests; frontend 461. Items that tax future change more than they break today.

---

## 1. README phase status and migration head are stale

- **Severity:** High (DX / onboarding honesty)
- **Location:** `README.md:5` (status still “P1 in progress” + Vendor Wave 1 NX-OS/JunOS/BlueCat); `README.md:37` (migrations `0001`→`0010`; tree head is `0018_p4_application_dependency_topology`)
- **Root cause:** Status banner not updated through P2 exit, P3 exit, P4 W1–W2. Migration wording hard-coded a past ceiling.
- **User impact:** New contributors and operators mis-judge maturity and first-run schema steps.
- **Proposed fix:** Rewrite status to MVP complete + P3 exited + P4 in progress (W1–W2 landed, W3 reporting pending); say `alembic upgrade head` without a stale numeric ceiling; mention F5/VMware plugins + Applications.
- **Effort:** S | **Risk:** None

---

## 2. `pg-test-routing` still advisory

- **Severity:** Medium
- **Location:** `.github/workflows/ci.yml` (`pg-test-routing` not in `all-gates` needs); `backend/tests/pg/README.md`; `ci/scripts/check-pg-test-routing.sh`
- **Root cause:** Wave 3 introduced the heuristic as advisory during a false-positive soak; promotion (~2026-07-10 target in IMPLEMENTATION_WAVES) not flipped.
- **User impact:** New PG-semantic code can land without `tests/pg/` and only surface as a non-blocking signal.
- **Proposed fix:** Review soak false-positive rate; add job to `all-gates` needs when ready.
- **Effort:** S | **Risk:** Low (false positives)

---

## 3. Monolithic `ci.yml`

- **Severity:** Medium (DX)
- **Location:** `.github/workflows/ci.yml` (backend, frontend, security-scan, docker, docker-publish, infra, kind-harness*, drills, kms-emulators, pg-integration, packet bite-proof, lockfile, observability, pg-test-routing, all-gates, …)
- **Root cause:** Every phase appended gates to one file. Gate graph is sound; review/conflict cost is high.
- **Proposed fix:** Keep `all-gates` as single required check; document job map in CONTRIBUTING or a short CI README; optional later path-filtered splits.
- **Effort:** M | **Risk:** Low

---

## 4. P4 plan / PRODUCTION header markers lag as-built

- **Severity:** Medium (process docs)
- **Location:** `docs/roadmap/P4-PLAN.md` (still “W0 not started” in header while W1–W2 code exists); `PRODUCTION.md` header still “Draft v0.1”
- **Root cause:** Design docs not re-stamped after implementation waves.
- **Proposed fix:** Bump P4 status to in-progress with W1–W2 complete / W3 pending; refresh PRODUCTION status line (body markers remain authoritative).
- **Effort:** S | **Risk:** None

---

## 5. Unbounded secondary list endpoints

- **Severity:** Medium
- **Location examples:**
  - `applications.py` GET `/{id}/dependencies` — all rows
  - `devices.py` interfaces / neighbors — full list
  - `auth/users.py` GET `/users` — all users
- **Root cause:** Primary inventory lists paginate (`limit ≤ 500`); nested or admin lists do not.
- **Proposed fix:** Cap or paginate; update UI assumptions.
- **Effort:** S–M | **Risk:** Low–Medium for client shapes

---

## 6. JWT access tokens HS256 + no aud/iss pin

- **Severity:** Low (architecture debt; ADR-0010)
- **Location:** `backend/app/core/security.py`
- **Root cause:** Symmetric shared secret; refresh path is stronger (stateful jti). Compromised API secret forges roles.
- **Proposed fix:** Long-term RS256/ES256 + rotation; short-term enforce prod secret strength (already partially gated).
- **Effort:** L | **Risk:** High if done poorly

---

## 7. Frontend production bundle size

- **Severity:** Low
- **Location:** `vite build` advisory — main JS ~861 kB minified / ~257 kB gzip
- **Root cause:** Single chunk; topology/cytoscape weight.
- **Proposed fix:** Route-level `import()` code-splitting for heavy pages.
- **Effort:** M | **Risk:** Low

---

## Closed since 2026-07-01

| Prior debt | Status |
|---|---|
| Packet opt-in default vs ADR-0031 | **CLOSED** — ADR-0049 executor-split |
| FastAPI `<0.137` upper pin | **CLOSED** — lifted |
| Monolithic `auth.py` (~1.5k LOC) | **CLOSED** — package split |
| Topology unbounded full-graph UI | **CLOSED** — scoped reads + `topology_max_nodes` 413 (Wave 5) |
| Shared UI primitives missing | **CLOSED** — Wave 4 components |

---

## SQLite vs PG posture (ongoing)

- Unit suite: aiosqlite, no external services — correct for speed.
- PG layer: `tests/pg/` covers refresh reuse, applications concurrency/tagging/derivation, audit/credentials, etc.
- Residual risk remains for any new PG-only SQL that only gets SQLite unit tests until `pg-test-routing` blocks.

---

## Strengths

- Import-linter module-boundary contracts kept.
- Dual lockfiles + CI drift gate.
- pip-audit / npm-audit / gitleaks / Trivy / SBOM / cosign publish path.
- Zero TODO/FIXME scatter in `backend/app` and `frontend/src` — debt lives in docs/ADRs.
- P4 plugins follow documented secret-redaction patterns (name-mangled slots, typed PluginError, conformance leak tests).
