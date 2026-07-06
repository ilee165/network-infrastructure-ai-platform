# W3-T2 — Change report: CR lifecycle roll-up (requester/approver/executor, diff statistics, trace links)

| | |
|---|---|
| **Wave** | P4 W3 — Compliance & audit reporting suite |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | **W3-T1** (engine) |
| **ADRs** | ADR-0053 §7.1 (binding), ADR-0020/0021 (CR lifecycle, redaction-safe diffs) |
| **PRODUCTION.md** | §7 (change report), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement the ADR-0053 §7.1 change report on the W3-T1 engine: per-period CR
roll-up — **requester, approver(s), executor (human or agent), state
transitions with timestamps, before/after as snapshot references +
redaction-safe diff statistics, reasoning-trace links** — as change-management
evidence (every state change traversed the CR lifecycle with four-eyes
approval).

## Scope

**In** — the typed payload + queries over `change_requests`/`approvals`/
`audit_log`/`reasoning_traces` (link ids only); CSV + PDF templates; regime
tags per W3-T6 defaults (`soc2:CC8.1`); beat cadence weekly (PROPOSED);
`engineer`+ floor; period handling (UTC, closed-open).

**Out** — config text in any form (ADR-0021 posture: statistics + references
only); trace *content* (links resolvable under the viewer's own RBAC); engine
changes (T1 owns the render/redaction path).

## Requirements (grounded in ADR-0053 §7.1)

1. **Never config text** — `applied_diff` statistics (line counts) + snapshot
   references only; the §6 layer-3 posture.
2. **Trace links, not trace content** — URLs into the platform, RBAC-resolved
   at view time.
3. **Complete lifecycle evidence** — every CR in the period appears with its
   full transition history and approver identities (IdP subject per D11).
4. **All queries under `tests/pg/`** (aggregation-heavy; SQLite must not hide
   PG semantics).

## Contracts / artifacts

- Payload model + queries + templates + regime tags; golden fixture for
  W4-T3's structure checks; API docs note.

## Test & gate plan

- Full gate suite; `tests/pg/` for the roll-up queries (multi-CR periods,
  empty period, agent-executor rows, rejected/rolled-back CRs).
- Redaction: payload passes `enforce_redaction`; a planted config-text field
  in a test payload is rejected (engine-level, sanity-checked here).
- Golden CSV/PDF structure fixture green.

## Exit criteria

- [ ] Change report generates on schedule + on demand at `engineer`+, CSV + PDF.
- [ ] Rows carry requester/approvers/executor/transitions/diff-statistics/trace links; zero config text.
- [ ] `tests/pg/` coverage on every query; golden fixture in place.
- [ ] One atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Sibling bug classes** with T3–T5 (period edges, empty results, pagination
  of large periods) — sweep all four reports on a class find.
- **Trace-link leakage** — links must be ids/URLs, never embedded reasoning
  content (which could quote device output).
