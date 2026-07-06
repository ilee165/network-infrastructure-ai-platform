# W1-T3 — Inventory surfacing: API endpoints + UI pages for ADC and virtualization inventory

| | |
|---|---|
| **Wave** | P4 W1 — Vendor Wave 3 plugins |
| **Owner** | `wf-implementer-light` |
| **Review tier** | sonnet |
| **Depends on** | W1-T1 (ADC rows), W1-T2 (virtualization rows) |
| **ADRs** | ADR-0050 §4 / ADR-0051 §5 (the models being surfaced), ADR-0010 (RBAC) |
| **PRODUCTION.md** | §2.4, §11 G-MNT |
| **Status** | Proposed |

## Objective

Surface the new Wave-3 inventory read-only: **API endpoints + UI pages for
virtual-server/pool(member) inventory and VM/host/cluster/port-group
inventory**, mirroring the existing device-inventory pages one-for-one
(template-following task — no novel design).

## Scope

**In** — read-only list/detail API endpoints over the W1 persisted rows
(viewer+ floor, matching the existing inventory read surface); frontend pages
mirroring the existing inventory page patterns (tables, filters, detail
panes) for: virtual servers (VIP/port/protocol/pool/availability), pools with
nested members (address/port/state badges), VMs (placement, power state, guest
IPs), hosts (cluster, connection state, maintenance mode), clusters, port
groups (switch type, VLAN); pagination on list endpoints; vitest/RTL coverage
mirroring existing page tests.

**Out** — any write surface; the app-dependency graph view + impact UI
(W2-T4); tagging UI (W2-T3); new visual design (mirror the existing pages).

## Requirements

1. **Mirror, don't invent** — endpoint shapes, RBAC floors, and UI patterns
   copy the existing device-inventory surface; deviations need justification.
2. **Availability/admin-state shown as separate dimensions** (ADR-0050 §4.4
   rationale) — do not collapse them in the UI.
3. **No secret-adjacent fields** — the models carry none by design; the UI
   adds none (no raw-artifact rendering).
4. **Empty states honest** — Tools-less VMs, empty pools, standalone hosts
   render as data, not errors.

## Contracts / artifacts

- API routes + schemas; frontend pages + tests; API docs.

## Test & gate plan

- Full gate suite: `pytest` (API), `vitest`/`eslint`/`tsc` (frontend), `ruff`,
  `mypy`, `lint-imports`; coverage per D16.
- Endpoint tests: RBAC floor, pagination, empty-inventory, detail-not-found.

## Exit criteria

- [ ] Read-only ADC + virtualization inventory endpoints live (viewer+), documented.
- [ ] UI pages render all six collections mirroring existing inventory pages; frontend tests green.
- [ ] No write path introduced; one atomic commit.

## Workflow

`wf-implementer-light` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Scope creep into W2 UI** — the dependency-graph/tagging views belong to
  W2; this task is flat inventory only.
- **Large-pool rendering** — nested members can be hundreds of rows; reuse the
  existing table pagination patterns.
