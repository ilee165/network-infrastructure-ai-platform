# Settings hub feature

**Status:** First-cut hub **complete** on `main` (PRs #124–#127). Remaining items are optional depth (SIEM lag, audit browser) and polish.

**Role:** Role-gated operator hub for day-to-day platform configuration and readiness — not a dump of every env var.

## Documents in this folder

| Document | Description |
|---|---|
| [PLAN.md](PLAN.md) | Living plan: invariants, delivery sequence, success criteria |
| [COMPLETED.md](COMPLETED.md) | What shipped (P0–T2.3 + T1.3) with PR / task mapping |
| [REMAINING.md](REMAINING.md) | Open tasks with design notes and recommended next build |

## Quick status

| Track | State |
|---|---|
| P0 hub IA + P1 vault/agents/LLM | **Done** — [#124](https://github.com/ilee165/network-infrastructure-ai-platform/pull/124) |
| Path A (honesty + OIDC + KEK) | **Done** — [#125](https://github.com/ilee165/network-infrastructure-ai-platform/pull/125) |
| Path B (integrations + health + retention) | **Done** — [#126](https://github.com/ilee165/network-infrastructure-ai-platform/pull/126) |
| Path C / T1.3 credential soft-disable | **Done** — [#127](https://github.com/ilee165/network-infrastructure-ai-platform/pull/127) |
| T2.4 SIEM export lag status | **Open** (optional) |
| T2.5 full audit-log browser | **Open** (separate program; P4 compliance alignment) |
| T0.3 / T0.4 LLM probe test polish | **Open** (optional, test-only) |

## Invariants (every Settings change)

| Rule | Meaning |
|---|---|
| **No secrets in SPA** | Provider API keys, OIDC client secrets, vault secrets never shown, entered, or returned (ADR-0009, ADR-0011) |
| **Backend RBAC is source of truth** | Frontend `RoleRoute` is defense-in-depth only |
| **Env-owned deploy knobs** | OIDC issuer, SIEM sinks, retention days stay deploy-time; UI reports *effective* status |
| **Audit mutations** | Profile changes, connection tests, vault create/rotate/disable audited; new writes must too |

## Related code

| Area | Paths |
|---|---|
| Hub UI | `frontend/src/pages/SettingsPage.tsx`, routes in `frontend/src/App.tsx` |
| Tests | `frontend/src/__tests__/SettingsPage.test.tsx`, `SettingsRoute.test.tsx` |
| Admin settings API | `backend/app/api/v1/auth/settings.py` |
| Integrations inventory | `backend/app/api/v1/integrations.py` |
| Credential vault | `backend/app/api/v1/credentials.py`, `backend/app/services/credentials/` |
| Lessons | `docs/roadmap/LESSONS.md` (L-FE-1 partial mocks, L-IMG-1 apk cache-bust) |

## Related ADRs / audits

- ADR-0009 multi-LLM provider abstraction (keys never in SPA)
- ADR-0010 authentication and authorization
- ADR-0011 credential vault + audit
- ADR-0028 OIDC SSO
- ADR-0032 KMS master key / rotation
- ADR-0040 device credential rotation
- ADR-0045 audit SIEM export
- Production-audit UI honesty (`docs/production-audit-2026-07-09/UI_UX_IMPROVEMENTS.md`)
