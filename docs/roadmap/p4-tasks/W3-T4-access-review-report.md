# W3-T4 — Access review report: users, roles, OIDC mappings, last login, break-glass usage — admin floor

| | |
|---|---|
| **Wave** | P4 W3 — Compliance & audit reporting suite |
| **Owner** | `wf-implementer` (strong) |
| **Review tier** | **strong** spec + quality (escalated: users/roles/OIDC/break-glass surface) |
| **Depends on** | **W3-T1** (engine) |
| **ADRs** | ADR-0053 §7.3 (binding), ADR-0028 (OIDC/break-glass), ADR-0010 (roles) |
| **PRODUCTION.md** | §7 (access review report), §4, §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement the ADR-0053 §7.3 access-review report: **users (local + OIDC), role
assignments, IdP group→role mappings, last login per user, dormant accounts,
and every break-glass local login in the period** (from its audit entries) —
monthly evidence for periodic access reviews (SOC 2 CC6-series). The
highest-sensitivity report: **admin floor on generation and download**, its own
downloads audited.

## Scope

**In** — payload + queries over users/roles/OIDC mapping config/audit entries
(last-login + break-glass events); dormant-account derivation (no login within
a configurable window); CSV + PDF templates; regime tags
(`soc2:CC6.1–CC6.3`); monthly cadence (PROPOSED); **admin** floor at
generation AND download.

**Out** — user-management mutations (read-only roll-up); password/credential
material of any kind (no such column is readable from `engines/reports/` —
layer-1 allowlist); SCIM/IdP-side data beyond the platform's own mapping
config.

## Requirements (grounded in ADR-0053 §7.3/§3/§6)

1. **Admin-only both ends** — generation and download; a role change between
   the two is honored at download (engine contract, asserted here for this
   kind).
2. **No credential-adjacent data** — usernames/roles/mappings/timestamps only;
   password hashes, tokens, session data are behind the layer-1 allowlist and
   must stay unreachable.
3. **Break-glass completeness** — every break-glass login in the period
   appears (ADR-0028 makes them alerted + audited; the report is the periodic
   review surface).
4. **Never RAG-embedded** — structural via the dedicated model (the exact
   leak this report motivated in the ADR).
5. **All queries under `tests/pg/`.**

## Contracts / artifacts

- Payload + queries + templates + regime tags; golden fixture for W4-T3.

## Test & gate plan

- Full gate suite; `tests/pg/`: last-login aggregation, dormant derivation,
  break-glass event extraction, mixed local/OIDC estates, empty period.
- Authz tests: engineer rejected at generation AND download for this kind.
- Redaction sanity: payload passes `enforce_redaction`; a planted
  password-named field rejects (engine-level).
- Golden CSV/PDF structure fixture green.

## Exit criteria

- [ ] Report generates monthly + on demand at admin only (both ends), CSV + PDF.
- [ ] Users/roles/mappings/last-login/dormant/break-glass complete for the period; zero credential-adjacent data.
- [ ] Downloads of this report are themselves audited (evidence about evidence).
- [ ] `tests/pg/` coverage; golden fixture in place; one atomic commit.

## Workflow

`wf-implementer` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **PII surface** — this artifact aggregates the platform's user population;
  the admin floor + download audit are the containment; never widen the floor
  without the Consultant answer.
- **Dormancy false signal** — service/break-glass accounts need honest
  classification, not silent exclusion.
