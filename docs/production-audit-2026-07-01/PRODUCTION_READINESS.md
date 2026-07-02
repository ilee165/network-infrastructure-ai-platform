# Production Readiness Assessment

Production readiness audit, 2026-07-01. Assessed against the repo's own gate framework (`docs/roadmap/PRODUCTION.md` §11: G-SEC / G-REL / G-SCA / G-OBS / G-MNT) plus the PROAUDIT.md production dimensions (logging, monitoring, error boundaries, hardening, performance, configuration).

**Posture summary:** P1 and P2-Security exited green with named deferrals; P3-Platform is mid-flight (W0–W4 merged, W5 phase-exit pending). The platform's readiness *machinery* — SLO enforcement, drills that bite, hash-chained audit, KMS gating — is ahead of most production systems. The open items below are dominated by **already-named deferrals**; the genuinely new findings from this audit are #4, #5, #8, #9.

---

## 1. Live kind-harness enforcement gates still non-blocking

- **Severity:** High (named deferral, promotion pending)
- **Location:** `.github/workflows/ci.yml:1115` (P2 kind-harness live step `continue-on-error: true`), `ci.yml:1481` (kind-harness-ha live bring-up, same), `all-gates` needs-list omissions (documented inline ~`ci.yml:1976–1989`); `docs/adr/0048-kind-harness-gate-promotion.md`
- **Root cause:** The mTLS-handshake and collector-egress-deny live enforcement checks (P2 deferral) and the HA bring-up (P3-W1) run SIGNAL-ONLY. The promotion is authored but deliberately held until the bite proof runs green-then-red on the ubuntu runner (ADR-0048's "false-green blocking gate is worse than continue-on-error" stance — correct). W4-T2's promotion was merged in PR #88 with the bite proof still on hold.
- **Impact:** Until promoted, a regression in mTLS enforcement, collector egress-deny, or HA topology can merge on a green build.
- **Proposed fix:** Execute the held W4-T2 bite proof (plant a violation, confirm the job goes red, revert, drop `continue-on-error`, join `all-gates`). This is the single highest-leverage readiness action available right now.
- **Effort:** S–M | **Risk:** Low — the machinery exists; this is execution.

## 2. External penetration test not performed

- **Severity:** High (named G-SEC exit item)
- **Location:** `PRODUCTION.md` §5/§11 G-SEC: "External penetration test completed with no open high/critical findings."
- **Root cause:** GA-scoped item; requires an engaged third party and a representative deployment. Everything upstream of it (rate limiting, lockout, prompt-injection eval suite at 100%, audit chain) is in place, so the platform is *ready to be tested*.
- **Proposed fix:** Schedule once P3 exits; scope to include the agent/LLM surface (prompt-injection → tool-call escalation) and the device-credential paths, not just the web tier.
- **Effort:** External + M internal remediation window | **Risk:** —

## 3. Scale & soak certification deferred to GA/customer cluster

- **Severity:** High (named, accepted)
- **Location:** `PRODUCTION.md` §1 P3 marker + ADR-0047: 500-device discovery / 100 concurrent users / 5,000-device projection / 30-day soak are deferred-accepted; drills prove the *mechanism* bites at reduced scale on ephemeral kind.
- **Root cause:** No hardware in the build environment — an honest constraint, correctly ledgered, never silently claimed.
- **Proposed fix:** Keep the ledger discipline; pair the eventual certified-scale runs with ARCHITECTURE_DEBT #7 (scoped topology queries) which will otherwise fail the 5k-device UI criterion.
- **Effort:** L (at GA) | **Risk:** Medium — first contact with real scale always finds something; the reduced-scale bite proofs bound it.

## 4. Default quickstart serves the SPA without security headers

- **Severity:** Medium — **new finding**
- **Location:** `deploy/docker/nginx.conf` (only `Cache-Control` headers; no `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Content-Security-Policy`, `Referrer-Policy`); headers exist only in `deploy/docker/tls/edge.nginx.conf` (opt-in TLS overlay) and the K8s ingress annotations.
- **Root cause:** Hardening landed on the TLS edge and ingress layers; the base nginx config every compose quickstart user actually runs was never given the header set. Violates "secure by default" for the documented default path.
- **Proposed fix:** Add the standard header block to the base `nginx.conf` (CSP can start report-only if the topology canvas needs inline styles): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, and a CSP scoped to self + the API path. Keep HSTS in the TLS overlay only (meaningless without TLS).
- **Effort:** S | **Risk:** Low — verify the SPA + `/api/` proxy under the CSP before merging.

## 5. Refresh-token rotation lacks reuse detection

- **Severity:** Medium — documented accepted risk, worth closing
- **Location:** `backend/app/api/v1/auth.py:28–33` (module docstring): rotation reuses the same `sid` with a fresh, never-persisted `jti`; "a rotated-out (superseded) refresh token … remains valid — replayable — until that session is logged out / revoked or the token reaches its 8 h expiry."
- **Root cause:** Deliberate simplicity: per-session revocation without per-token state. The trade-off is that a stolen refresh cookie is silently usable in parallel with the victim's for up to 8 h, and nothing detects the theft.
- **Proposed fix:** Standard rotation-reuse detection: persist the current `jti` on the `refresh_sessions` row; a refresh presenting a stale `jti` revokes the whole session (both parties re-authenticate) and emits an audit event. **Prerequisite:** frontend single-flight refresh (FUNCTIONAL_BUGS #4), or legitimate parallel refreshes will trip it.
- **Effort:** M (migration + audit event + tests, PG layer included) | **Risk:** Medium — auth-path change; sequence carefully with the frontend fix.

## 6. Unfixed base-image CVEs accepted via `ignore-unfixed`

- **Severity:** Medium (named, ongoing posture)
- **Location:** Trivy gate config (CI `security-scan`/`docker` jobs), `deploy/docker/.trivyignore-image`, `docs/security/2026-06-14-trivy-baseimage-cves.md`; pip-audit floor-pins + paramiko allowlist (`backend/.pip-audit-allowlist.txt`)
- **Root cause:** The gate correctly fails only on *fixable* critical/high CVEs; unfixed base-image CVEs are accepted with a dated note. The GA gate (G-SEC) tightens to zero critical **and** high at release — the delta between today's posture and that bar is unowned work that accrues silently as the CVE feed moves.
- **Proposed fix:** Monthly allowlist/ignore review (calendar-owned, not best-effort); before GA, evaluate distroless/chiseled bases for api/worker to shrink the unfixed set structurally. The frontend Dockerfile's cache-bust-date mechanism for `apk upgrade` needs the same periodic owner.
- **Effort:** S recurring | **Risk:** Low.

## 7. P3 phase-exit not yet run — ADRs 0042–0048 still Proposed

- **Severity:** Medium (process state, on plan)
- **Location:** `docs/adr/0042…0048` (Proposed), `PRODUCTION.md` P3 entry marker; W5 (evals + release-readiness audit + gate re-evaluation) unbuilt.
- **Root cause:** Mid-phase reality, not a defect — recorded so this audit's snapshot is honest: the P3 controls (CNPG HA, KEDA, Sentinel fan-out, SIEM export, SLO enforcement, drills) are merged but their phase-exit evidence doc and ADR flips don't exist yet.
- **Proposed fix:** Run W5 per plan; the audit ledger in these reports can feed the W5-T3 release-readiness evidence.
- **Effort:** Per P3 plan | **Risk:** —

## 8. Compose data-tier images float on major tags

- **Severity:** Low — **new finding**
- **Location:** `deploy/docker/docker-compose.yml`: `pgvector/pgvector:pg16`, `neo4j:5-community`, `redis:7-alpine`, `ollama/ollama` (untagged = `latest`)
- **Root cause:** The app images are locally built and the K8s path is the hardened one; compose tags were left floating. A `redis:7-alpine` or Neo4j minor bump can change behavior under the platform without any repo change (the class of surprise the lockfile gate exists to prevent).
- **Proposed fix:** Pin to minor+patch (e.g. `redis:7.4-alpine`, `neo4j:5.26-community`) or digests; add a compose-pin check alongside the lockfile gate; give Ollama an explicit tag.
- **Effort:** S | **Risk:** Low.

## 9. CORS middleware allows all methods/headers with credentials

- **Severity:** Low — **new finding**
- **Location:** `backend/app/main.py:161–167`: `allow_credentials=True` with `allow_methods=["*"]`, `allow_headers=["*"]`; origins correctly restricted via `NETOPS_CORS_ORIGINS`.
- **Root cause:** Convenience defaults. Origin restriction does the heavy lifting, but wildcard methods/headers widen the preflight surface for any future origin-config mistake and fail hardening scanners.
- **Proposed fix:** Enumerate: methods `GET, POST, PUT, PATCH, DELETE`, headers `Authorization, Content-Type, X-Request-ID`.
- **Effort:** S | **Risk:** Low — verify the WS ticket + refresh flows after tightening.

## 10. OIDC two-IdP live validation outstanding

- **Severity:** Low (named)
- **Location:** `PRODUCTION.md` §4 exit criteria: "login via OIDC end-to-end against two IdPs (one self-hosted Keycloak, one cloud IdP)."
- **Root cause:** Integration is provider-agnostic and test-covered; live multi-IdP validation needs real IdP tenants (same class as the lab-accepted vendor validations).
- **Proposed fix:** Fold into the GA validation pass alongside the break-glass drill (G-SEC: "executed in the last 6 months" — needs a first execution + calendar).
- **Effort:** S–M | **Risk:** Low.

---

## Dimension check (PROAUDIT §5) — what's already strong

| Dimension | State |
|---|---|
| **Logging** | structlog JSON, request-id middleware with `X-Request-ID` echo, no secrets in logs (tested by credential-leak tests); machine-readable Job output lines (`AUDIT_CHAIN_VERIFY …`, `REBUILD neo4j_auto …`) for scrapers |
| **Monitoring hooks** | `/metrics` on api via templated-route middleware; SLO recording rules + multi-window burn-rate alerts (`deploy/observability/`), per-SLO runbooks (`docs/runbooks/slo-*.md`), fault-injection MTTD harness with bite proof |
| **Error handling** | RFC 7807 problem details end-to-end (`core/errors.py` ↔ `frontend/api/client.ts`); frontend render-error boundary is the gap (UI_UX #1) |
| **Security hardening** | KMS KEK with refuse-to-start prod gate; audit hash-chain + daily verify; login lockout fail-closed / API limiter fail-open (deliberate asymmetry); mTLS api/worker↔pg; collector egress NetworkPolicy; image signing + SBOM; gitleaks/pip-audit/npm-audit gates. Gaps: #1, #4, #5 above |
| **Performance** | Pagination everywhere except topology `/graph` (ARCH_DEBT #7); HPA/KEDA autoscaling with queue-burst drill; PgBouncer; `worker_prefetch_multiplier=1` |
| **Configuration** | `.env.example` ↔ `config.py` 1:1 rule (one documented exception); Settings via pydantic-settings; compose requires `--env-file` (documented footgun — consider a compose-level guard that fails fast when the neo4j credential is unset) |

## Go/no-go summary

**Current state supports:** pilot / friendly-customer deployments on the K8s path with the named deferrals disclosed.
**Blockers for GA-labeled production:** items #1–#3 (gate promotion, pen test, scale certification) + P3/W5 exit (#7) + the packet-analysis design resolution (ARCHITECTURE_DEBT #1). The quick wins (#4, #8, #9, Redis `aclose()`, ErrorBoundary) should ship in the next maintenance wave regardless.
