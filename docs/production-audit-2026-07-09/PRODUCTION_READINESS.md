# Production Readiness Assessment

Production readiness audit, 2026-07-09 (HEAD `5403c3b`). Assessed against `docs/roadmap/PRODUCTION.md` §11 gates (G-SEC / G-REL / G-SCA / G-OBS / G-MNT) and PROAUDIT production dimensions.

**Posture summary:** P1–P3 platform machinery is **exited with named deferrals**. P4 is mid-flight (W0–W2 landed; W3 compliance reporting not started). Security spine and CI gates remain strong. Largest production-readiness *delta* for P4 is vertical integration of API vendors (see FUNCTIONAL_BUGS #1–#2), not regression of P3 controls.

---

## Gate posture (summary)

| Gate | Posture | Notes |
|---|---|---|
| **G-SEC** | Strong / incomplete at GA bar | Pen test still named-deferred; CSP soft on compose; refresh reuse **closed**; nginx base headers **closed** |
| **G-REL** | Mechanism PASS (P3) | Drill bite-proofs blocking; certified scale + 30-day soak still GA-deferred |
| **G-SCA** | Mechanism PASS (P3) | Reduced-scale drills; certified numbers deferred |
| **G-OBS** | PASS (P3) | Recording rules, burn-rate alerts, MTTD harness, SIEM export lag SLO |
| **G-MNT** | PASS continuous | Lockfiles, N-2 upgrade rehearsal, ADR currency mostly restored; README status drift is a new G-MNT smell |

---

## 1. Named GA / operational deferrals (unchanged class)

- **Severity:** High (named, accepted)
- **Items:** External penetration test; 500-device / 100-user / 5k projection certified scale; 30-day calendar soak; OIDC two-IdP live validation; recurring break-glass drill calendar; live vendor lab demos.
- **Root cause:** No full production hardware/lab on authoring host — correctly ledgered, never silently claimed.
- **Proposed fix:** Keep ledger discipline; schedule at GA / customer cluster.
- **Effort:** External + L | **Risk:** First real scale always finds something

---

## 2. kind live harness remains signal-only (ADR-0048)

- **Severity:** Resolved / WONTFIX (accepted residual)
- **Location:** ADR-0048 Rejected; `kind-harness` / `kind-harness-ha` opt-in; not in `all-gates`
- **Residual risk:** Runtime CNI/Postgres enforcement regressions with correct manifests are not merge-blocking. Static rego + render-twice + NetworkPolicy + drill-bite-proofs still block code regressions.

---

## 3. CSP still Report-Only on compose edge

- **Severity:** Medium
- **Location:** `deploy/docker/nginx.conf` (`Content-Security-Policy-Report-Only`, TODO to enforce)
- **Root cause:** Wave 2 added full header set with CSP soft to avoid breaking topology canvas.
- **Proposed fix:** Smoke SPA + API + WS under report-only; flip to enforcing; tighten `connect-src`.
- **Effort:** S | **Risk:** Medium if premature

---

## 4. API rate limiter fail-open when Redis is down

- **Severity:** Medium (documented tradeoff)
- **Location:** `backend/app/api/deps.py` rate-limit path
- **Root cause:** Availability bias: Redis outage disables general API rate limits. Login lockout is separate fail-closed path.
- **Proposed fix:** Fail-closed for auth routes; metric/alert on limiter backend error; optional fail-closed for admin mutations.
- **Effort:** M | **Risk:** Availability vs security

---

## 5. Vault Transit token: single renew, no refresh loop

- **Severity:** Medium (ops)
- **Location:** `backend/app/core/crypto.py` Vault provider
- **Root cause:** Long-lived workers can hit expired tokens; readiness fail-closed is the backstop.
- **Proposed fix:** Periodic renew or shorter readiness + alert on `KeyProviderUnavailable`.
- **Effort:** M | **Risk:** Medium operational

---

## 6. Default collector egress CIDR is broad placeholder

- **Severity:** Medium (deploy)
- **Location:** Helm `values.yaml` collector egress (`10.0.0.0/8` class)
- **Root cause:** Chart boots with wide RFC1918; operators must narrow. Fail-closed empty CIDR in NetworkPolicy template is good.
- **Proposed fix:** Prod values profile requiring non-placeholder CIDR; install NOTES.
- **Effort:** S | **Risk:** Low

---

## 7. Packet pcap handoff still `emptyDir` placeholder

- **Severity:** Medium (multi-node / DR)
- **Location:** Helm packet volume config
- **Root cause:** Capture/analysis shared volume does not survive reschedule across nodes.
- **Proposed fix:** PVC / RWX per ADR-0023 before multi-node packet GA.
- **Effort:** M | **Risk:** Medium deploy complexity

---

## 8. Unfixed base-image CVEs via ignore-unfixed

- **Severity:** Medium (ongoing posture)
- **Location:** Trivy config, `.trivyignore-image`, pip-audit allowlist
- **Root cause:** Gate fails on *fixable* critical/high; unfixed base CVEs accepted with notes.
- **Proposed fix:** Monthly allowlist review; distroless evaluation before GA.
- **Effort:** S recurring | **Risk:** Low

---

## Closed since 2026-07-01 (readiness)

| Item | Status |
|---|---|
| Compose nginx missing security headers | **CLOSED** |
| Refresh-token reuse detection | **CLOSED** |
| Packet analysis default-OFF | **CLOSED** (ADR-0049) |
| P3 phase-exit ADRs 0042–0047 | **Accepted** (0048 Rejected) |
| Compose data-tier floating tags | **CLOSED** (Wave 2 pin) |
| CORS wildcard methods/headers | **CLOSED** (enumerated) |

---

## Dimension check (PROAUDIT §5)

| Dimension | State |
|---|---|
| **Logging** | structlog JSON, request-id, secret redaction filters on API plugins |
| **Monitoring** | `/metrics`, SLO rules, burn-rate alerts, MTTD harness, runbooks |
| **Error handling** | RFC 7807; frontend ErrorBoundary present |
| **Security hardening** | KMS refuse-to-start, audit hash-chain, mTLS static gates, collector NetworkPolicy, image signing, refresh jti reuse |
| **Performance** | Pagination on primary lists; topology node cap; HPA/KEDA machinery from P3 |
| **Configuration** | `.env.example` ↔ settings discipline; compose `--env-file` footgun still documented |

---

## Local unit-gate evidence (this audit)

Run on authoring host 2026-07-09 against HEAD `5403c3b` (venv + `node_modules` present). **No compose smoke.**

| Command | Result |
|---|---|
| `ruff check .` | PASS |
| `ruff format --check .` | PASS (511 files) |
| `mypy` | PASS (238 source files) |
| `lint-imports` | PASS (2 kept, 0 broken) |
| `pytest` | **3589 passed**, 90 skipped, ~12m04s |
| `npm run lint` | PASS (0 errors, 2 warnings) |
| `npm run typecheck` | PASS |
| `npm test` (vitest) | **461 passed** (41 files) |
| `npm run build` | PASS (chunk size advisory) |

Notes:

- Pytest emitted many `InsecureKeyLengthWarning` for short HMAC keys in **test fixtures** — not a production settings finding; consider longer test secrets to quiet noise.
- Starlette deprecation: `httpx` with `starlette.testclient` — test-only debt.
- ESLint warnings confined to `ErrorBoundary.tsx` (react-refresh export + unused eslint-disable).

---

## P4 readiness slice

| Deliverable | Code | Live path | Ready? |
|---|---|---|---|
| F5 plugin + conformance | Yes | Discovery collection **no** | Partial |
| VMware plugin + conformance | Yes | Discovery collection **no** | Partial |
| ADC / virt inventory UI | Yes | Depends on data | Partial |
| App schema + derivation + Neo4j | Yes | Empty sources in prod | Partial |
| Manual tagging + If-Match | Yes | Yes | Yes |
| Impact API + agent tool | Yes | Empty graph edges | Partial |
| Compliance report suite (W3) | No | — | Not started |

**Do not claim P4 W1/W2 operationally complete until API collection (and DNS feed) land or operator docs explicitly scope “fixture/manual only.”**
