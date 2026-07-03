# Production Readiness Audit — Executive Summary

**Date:** 2026-07-01
**Scope:** Full repository at `main` (HEAD `868911d`, post P3-W4 Batch 2)
**Method:** Staff-Engineer review per `PROAUDIT.md` — structure review, targeted deep dives on risk areas (auth, streaming, workers, deploy, CI), static sweeps (exception handling, pagination, async misuse, a11y/responsive signals), and reconciliation against the repo's own readiness ledger (`docs/roadmap/PRODUCTION.md` §11 gates, release-readiness docs). **Report only — no code was modified.**

Companion reports:

| Report | Contents |
|---|---|
| [FUNCTIONAL_BUGS.md](FUNCTIONAL_BUGS.md) | Broken features, races, resource leaks, contract issues |
| [UI_UX_IMPROVEMENTS.md](UI_UX_IMPROVEMENTS.md) | Error boundaries, responsiveness, component reuse, a11y |
| [ARCHITECTURE_DEBT.md](ARCHITECTURE_DEBT.md) | Structural debt, dependency pins, test-infrastructure divergence, DX |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Gate-by-gate posture: security, reliability, observability, deferred items |

---

## Overall verdict

This codebase is in **unusually strong shape for a pre-GA platform**. The engineering discipline is visible everywhere: 2,789 backend tests + 294 frontend tests, twelve blocking CI gates, dependency lockfiles in both ecosystems, an append-only hash-chained audit log, envelope-encrypted credential vault with KMS refuse-to-start gating, RFC 7807 error contract honored end-to-end, and — rarest of all — an **honest, named deferral ledger**: every gap deferred out of P1/P2/P3 is recorded in `PRODUCTION.md` rather than silently claimed.

The audit found **no Critical-severity issues**. It found **3 High-severity issues** (one genuinely broken feature, one missing UI safety net, one unresolved design contradiction), a set of Medium items concentrated in hardening and debt, and confirmed that the largest production-readiness gaps are the **already-named deferrals** (external pen test, 30-day soak, certified-scale numbers, live kind-gate promotion) — not undiscovered problems.

## Top findings (severity-ordered)

| # | Severity | Finding | Report |
|---|---|---|---|
| 1 | **High** | **Troubleshooting Agent live-capability reads are dead code**: every live BGP/OSPF/route read returns "not yet wired: the credential/transport session lands in M5" — M5 shipped 2026-06-19; the transport-injection seam was wired for discovery/config workers but never for this agent (`backend/app/agents/troubleshooting/tools.py:166`) | FUNCTIONAL_BUGS #1 |
| 2 | **High** | **No React ErrorBoundary anywhere in the frontend** — any render exception blanks the whole SPA with no recovery path | UI_UX #1 |
| 3 | **High** | **Packet-analysis service is opt-in/default-OFF, contradicting ADR-0031's secure-by-default sandbox design** — recorded as a deferred contradiction in PR #86, still unresolved | ARCH_DEBT #1 |
| 4 | ~~High~~ **Resolved (WONTFIX)** | Live kind-harness enforcement gates — promotion **Rejected** (ADR-0048, 2026-07-03, audit-W2 T7); live jobs now opt-in, controls stay protected by blocking static gates | PROD_READINESS #1 |
| 5 | High (named) | External penetration test not performed (G-SEC exit item) | PROD_READINESS #2 |
| 6 | Medium | Default docker-compose quickstart serves the SPA with **no security headers** (no CSP, X-Frame-Options, X-Content-Type-Options) — headers exist only in the TLS edge overlay and K8s ingress | PROD_READINESS #4 |
| 7 | Medium | Refresh-token rotation has **no reuse detection**: a superseded refresh token stays valid until session revoke / 8 h expiry (documented, but fixable) | PROD_READINESS #5 |
| 8 | Medium | Known flaky WebSocket fan-out relay race (`test_live_frame_published_by_another_replica_is_relayed`) — real fix still pending | FUNCTIONAL_BUGS #2 |
| 9 | Medium | Unit suite runs on SQLite and hides PostgreSQL semantics; the PG-backed test layer covers only the P2-W4 controls | ARCH_DEBT #2 |
| 10 | Medium | `fastapi` capped `<0.137` (upstream `include_router` change); upgrade debt accrues security-patch lag | ARCH_DEBT #3 |

## Scorecard by PROAUDIT dimension

| Dimension | Grade | One-line assessment |
|---|---|---|
| Functionality | **B+** | One dead feature path (live troubleshooting reads) and one known race; everything else exercised by a deep test suite |
| Code quality | **A−** | Exception handling deliberate and annotated, zero `any`/`@ts-ignore` in frontend, only 1 TODO in 50k backend LOC; debt is structural (module size, plugin duplication), not hygiene |
| UI/UX | **B−** | Solid data/error/empty states via react-query; but no error boundary, desktop-only layout, thin shared-component layer, text-only loading UX |
| Developer experience | **A−** | Lockfiles, 12-gate CI, conformance suites, generated docs; held back by a 2,020-line monolithic `ci.yml` and stale facts in `CLAUDE.md` |
| Production readiness | **B** | Observability and reliability engineering are genuinely strong (SLO burn-rate alerts, MTTD harness, drills that bite); gaps are the named deferrals plus quickstart security headers |

## Issue census

| Severity | Count | Distribution |
|---|---|---|
| Critical | 0 | — |
| High | 5 | 1 functional, 1 UI, 1 architecture, 2 named readiness gates |
| Medium | 11 | hardening (4), debt (4), functional (2), UI (1) |
| Low | 14 | hygiene, polish, doc drift |

## Recommended sequencing

1. **Fix now (days):** Troubleshooting transport injection (#1) · app-level ErrorBoundary (#2) · shutdown Redis `aclose()` · security headers in base `nginx.conf`.
2. **Next wave:** WS relay race real fix · refresh-token reuse detection · packet-analysis design resolution (supersede or satisfy ADR-0031). ~~kind-gate promotion bite proof~~ — **dropped (ADR-0048 Rejected, 2026-07-03).**
3. **Before GA (already ledgered):** pen test, 30-day soak, certified-scale runs, OIDC two-IdP live validation, P3 W5 phase-exit audit flipping ADRs 0042–0047 (0048 is **Rejected** — not flipped).
