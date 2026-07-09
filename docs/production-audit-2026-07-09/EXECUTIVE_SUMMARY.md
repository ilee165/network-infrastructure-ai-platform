# Production Readiness Audit — Executive Summary

**Date:** 2026-07-09  
**Scope:** Full repository at `main` (HEAD `5403c3b`)  
**Method:** Delta-aware Staff-Engineer review per `docs/PROAUDIT.md` — re-verify 2026-07-01 findings and remediation waves; deep-dive P4 W1–W2 surfaces; targeted security/agent/worker/deploy review; static quality sweeps; local unit-gate evidence. **Report only — no product code was modified.**

Companion reports:

| Report | Contents |
|---|---|
| [FUNCTIONAL_BUGS.md](FUNCTIONAL_BUGS.md) | Broken features, races, vertical-integration gaps |
| [UI_UX_IMPROVEMENTS.md](UI_UX_IMPROVEMENTS.md) | Console UX, a11y, pagination, product-copy honesty |
| [ARCHITECTURE_DEBT.md](ARCHITECTURE_DEBT.md) | Structural debt, DX, test routing, CI complexity |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Gate posture, named deferrals, local gate evidence |

Baseline: [`docs/production-audit-2026-07-01/`](../production-audit-2026-07-01/EXECUTIVE_SUMMARY.md) (HEAD `868911d`). Remediation waves W1–W5 are **complete** (`IMPLEMENTATION_WAVES.md`). Since baseline: P3-Platform exit, P4 W0 design + W1 (F5/VMware) + W2 (application-dependency topology), license/contrib docs (~233 commits).

---

## Overall verdict

The platform remains in **unusually strong engineering shape**. All 2026-07-01 High *bugs* re-check as **CLOSED** (or intentional **WONTFIX** for kind live promotion). Local unit gates are green at scale: **3589** backend tests / **461** frontend tests, ruff/mypy/import-linter/tsc/build clean.

The new material findings are not “hidden rot” in the security spine — that surface is still excellent (vault, OIDC, ChangeRequest four-eyes, audit hash-chain, packet executor-split, refresh jti reuse). They are **vertical-integration and product-honesty gaps** on the P4 path:

1. F5/VMware plugins, ADC/virt tables, and UI exist, but **discovery never collects API vendors** (named deferral in models, still a production completeness High).
2. App-dependency derivation/impact therefore **stay empty** unless data is hand-seeded.
3. README and the Audit page **overclaim** phase status / full audit-log coverage.

No **Critical** issues. P4 W3 (compliance reporting suite) is **not started** — expected by plan, not a defect.

---

## Scorecard by PROAUDIT dimension

| Dimension | 2026-07-01 | 2026-07-09 | Delta |
|---|---|---|---|
| Functionality | B+ | **B** | Remediation closed live-read/WS bugs; P4 vertical gap pulls grade |
| Code quality | A− | **A−** | Auth split, shared UI primitives, FastAPI unpin landed; monoworkflow remains |
| UI/UX | B− | **B+** | ErrorBoundary, skeletons, drawer, jsx-a11y, axe — large lift; audit-copy + pagination gaps remain |
| Developer experience | A− | **A−** | Lockfiles + gates still excellent; README phase drift is the main regression |
| Production readiness | B | **B+** | P3 exit + packet default-on + refresh reuse + nginx headers; named GA deferrals unchanged |

---

## Top findings (severity-ordered)

| # | Severity | Finding | Report |
|---|---|---|---|
| 1 | **High** | F5/VMware **not wired into discovery collection** — SSH/SNMP only; ADC/virt tables stay empty in live runs | FUNCTIONAL_BUGS #1 |
| 2 | **High** | App-dependency derivation / impact **empty by default** without API collection + DNS fetch | FUNCTIONAL_BUGS #2 |
| 3 | **High** | `README.md` status still claims **P1 in progress**; migrations text ends at `0010` (head is `0018`) | ARCHITECTURE_DEBT #1 |
| 4 | **High** | Audit page title/description claim **platform-wide append-only audit log**; UI is session tool-call trace only | UI_UX #1 |
| 5 | High (named) | External pen test / certified scale / 30-day soak still deferred to GA | PRODUCTION_READINESS |
| 6 | Medium | F5 token revocation embeds token in URL path (docs claim “never in URL”) | FUNCTIONAL_BUGS #3 |
| 7 | Medium | F5 UCS archive ops incomplete end-to-end (plugin yes; worker/automation path no) | FUNCTIONAL_BUGS #4 |
| 8 | Medium | CSP still **Report-Only** on compose nginx | PRODUCTION_READINESS |
| 9 | Medium | Devices/Changes UI silent truncation (no Pagination) | UI_UX #2–3 |
| 10 | Medium | `pg-test-routing` still **advisory** (not in `all-gates`) | ARCHITECTURE_DEBT #2 |

---

## Baseline re-verification (2026-07-01)

| Prior item | Status @ HEAD |
|---|---|
| Troubleshooting live reads dead | **CLOSED** — transport wired + regression pin |
| React ErrorBoundary missing | **CLOSED** — app + layout boundaries + tests |
| Packet default-OFF contradiction | **CLOSED** — ADR-0049 executor-split, default on |
| kind live promotion | **WONTFIX** — ADR-0048 Rejected |
| nginx security headers (compose) | **CLOSED** (CSP soft) |
| Refresh-token reuse detection | **CLOSED** — jti hash + PG tests |
| WS fan-out relay race | **CLOSED** — deterministic relay tests |
| Redis aclose on shutdown | **CLOSED** |
| SQLite hides PG semantics | **PARTIAL** — policy + PG tests + advisory gate |

---

## Local gate evidence (2026-07-09)

| Gate | Result |
|---|---|
| `ruff check` / `ruff format --check` | PASS (511 files) |
| `mypy` | PASS (238 files) |
| `lint-imports` | PASS (2 contracts kept) |
| `pytest` | **3589 passed**, 90 skipped (~12 min) |
| `eslint` | PASS (0 errors, 2 warnings in ErrorBoundary) |
| `tsc --noEmit` | PASS |
| `vitest run` | **461 passed** (41 files) |
| `vite build` | PASS (chunk-size advisory only) |

Compose smoke and live kind were **out of scope** for this run (user-confirmed).

---

## Recommended sequencing

1. **Docs honesty (days):** README phase/migration head; Audit page copy; refresh P4-PLAN status marker.
2. **P4 vertical close (wave):** API credential kind + discovery collection for F5/VMware; DNS dependency feed; then declare impact production-ready.
3. **Hardening polish:** F5 revoke/upload/paging; CSP enforce after smoke; Devices/Changes Pagination; promote `pg-test-routing` when soak is done.
4. **Before GA (already ledgered):** pen test, scale/soak, OIDC two-IdP live, certified numbers.

---

## Issue census

| Severity | Count | Notes |
|---|---|---|
| Critical | 0 | — |
| High | 4 new + named GA items | 2 functional integration, 1 docs, 1 UI product-claim |
| Medium | ~12 | plugin edges, CSP, pagination, advisory gates, deploy residuals |
| Low | ~10 | a11y polish, redaction edge cases, JWT alg debt |

**Bottom line:** Security and platform machinery improved since July 1. The honest next risk is **shipping P4 inventory/impact as complete when collection is still SSH/SNMP-only** — close that vertical or document it loudly in operator-facing surfaces.
