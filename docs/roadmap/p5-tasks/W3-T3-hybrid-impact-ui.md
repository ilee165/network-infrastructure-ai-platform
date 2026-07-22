# W3-T3 — Hybrid impact/reachability tool and topology UI

| Field | Contract |
|---|---|
| Owner | `wf-implementer` |
| Depends on | W3-T2 |
| Review | sonnet spec + quality |
| Status | Proposed |

## Objective and scope

Extend topology reads, the Troubleshooting Agent, and topology UI so users can
query and explain on-prem-to-cloud reachability with provenance. Out: write
actions, speculative remediation, and a second graph authority.

## Requirements and contracts

1. Typed read facade accepts source, target, optional snapshot/scope, bounded
   depth, and returns ordered path nodes/edges, confidence, and evidence refs.
2. Tenant/site/provider scope and RBAC are applied before graph traversal;
   stale/conflict candidates are not traversed as connected edges.
3. Agent tool is read-only, allowlisted for Troubleshooting, records evidence
   in reasoning traces, and states uncertainty rather than inventing a path.
4. UI renders cloud groups/interconnects and distinguishes confirmed, inferred,
   conflict, loading, empty, partial, and error states accessibly.

## Test and gate plan

Topology/API tests cover scoped paths, no-path, cycles/depth, provenance,
snapshot, stale/conflict exclusion, and RBAC. Agent tests assert evidence-bound
answers and no fabricated connectivity; they enumerate the registered
Troubleshooting tool set and assert it equals the read-only allowlist, so no
write-capable tool can be registered. UI tests cover filters, legend,
keyboard/axe, provenance panel, and partial failures; update sibling API mocks.
Run backend and frontend full gates plus OpenAPI drift.

## Exit criteria

- [ ] API/tool/UI answer hybrid impact with cited provenance and confidence.
- [ ] Scope, RBAC, no-path, conflict, and uncertainty behaviors are tested.
- [ ] OpenAPI/types/docs and agent allowlist are synchronized.
- [ ] D16 passes; one atomic commit.
