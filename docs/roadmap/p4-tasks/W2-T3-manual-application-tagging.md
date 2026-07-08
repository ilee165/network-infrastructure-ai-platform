# W2-T3 — Manual application tagging: API + UI — direct write under RBAC (`engineer`+), full audit

| | |
|---|---|
| **Wave** | P4 W2 — Application-dependency topology |
| **Owner** | `wf-implementer` (authz/API) + `wf-implementer-light` (UI) |
| **Review tier** | **strong** on the authz surface; sonnet on the UI |
| **Depends on** | **W0-T3** (ADR-0052 §7, the decided write path), **W2-T1** (tables). ∥ W2-T2; no W1 dependency |
| **ADRs** | ADR-0052 §1/§3.3/§7 (binding), ADR-0010 (RBAC), ADR-0038 (audit spine) |
| **PRODUCTION.md** | §2.4, §11 G-SEC |
| **Status** | Implemented — backend `7d64a29`, UI `1a59567`/`c920f48`/`8f9961d` (P4 W2) |

## Objective

Implement the ADR-0052 §7 decision: **manual tagging as a direct write at the
`engineer` role floor with a full audit entry on every mutation** — create/
update/delete `manual`-origin applications, add/remove `source='manual'`
dependency rows — plus the tagging UI. CR-gating was considered and **declined
(user decision 2026-07-05)**; this task implements the decision, it does not
revisit it.

## Scope

**In** — tagging API (`require_role("engineer")` write floor, viewer+ reads,
the `api/v1/devices.py` precedent): application CRUD (manual-origin only),
dependency-row add/remove (`source='manual'`, `created_by` stamped), input
validation (length caps; `target_kind` ∈ device|ip_address; target existence);
audit entry per mutation via `services/audit/service.py::record`
(`application.create`/`application.update`/`application.delete`/
`application_dependency.create`/`application_dependency.delete`; actor, target
ids, before/after state); standard rate limiting applies; UI: tag-object-into-
application flow, application create/edit, manual-edge removal — a manual tag
is exactly one row (no separate tag table); frontend tests.

**Out** — CR-gating (declined); any agent-facing tagging tool (**none ships in
P4** — a future one is STATE_CHANGING and CR-gated by the unchanged brief-§5
rule); deleting/suppressing `derived` applications (lifecycle-owned by
derivation; suppress flag named-deferred); role-floor changes (Consultant item
refines the floor only, later).

## Requirements (grounded in ADR-0052 §7)

1. **Floor: `engineer` write / `viewer` read**; enforcement in the single
   permission-check module per house pattern.
2. **Every mutation audited** — hash-chained, append-only; audit answers
   who/what/when for every edge that ever influenced an impact answer.
3. **Users cannot delete `derived` applications** (would resurrect on
   re-derivation); manual deletes cascade their dependency rows, audited.
4. **No secret surface** — payloads are names/descriptions/FQDNs/owner strings/
   row references; no credential field exists; provenance for manual rows is
   the single `{"kind":"user","ref":<user_id>}` step.
5. **Manual rows are user-owned** — no derivation pass may mutate them
   (asserted with W2-T2's ownership tests).

## Contracts / artifacts

- Tagging API routes + schemas; audit action constants; UI flows + tests;
  API docs.

## Test & gate plan

- Full gate suite + frontend gates (vitest/eslint/tsc).
- Authz tests: viewer/operator rejected on writes; engineer/admin accepted;
  agent-session tokens have no tagging tool to call.
- Audit tests: entry per mutation with before/after; `tests/pg/` where PG
  semantics bind (cascade delete + audit ordering).
- Hash-chain membership: tagging audit entries are part of the ADR-0038
  chain — chain verification passes over a sequence containing tagging
  mutations, and a tampered tagging entry breaks verification (negative
  control).
- Derived-row protection: API refuses delete of `origin='derived'` rows.

## Exit criteria

- [ ] Direct-write tagging API live at `engineer`+ with full audit per mutation; reads at viewer+.
- [ ] UI tag/create/edit/remove flows working; frontend tests green.
- [ ] Derived-application delete refused; manual-row ownership asserted.
- [ ] No agent tagging tool exposed; rate limiting covers the endpoints.
- [ ] One atomic commit.

## Workflow

`wf-implementer` (authz) + `wf-implementer-light` (UI) → **strong review on the authz surface** + sonnet UI review → fixer if findings → verifier → one atomic commit.

## Risks

- **Authz drift** — a later refactor moving the floor out of the single
  check-site would silently widen access; keep to the house pattern.
- **Graph pollution via bulk tagging** — bounded by rate limiting, fully
  audited, reversible from audit; never touches devices (worst case named in
  the ADR).
