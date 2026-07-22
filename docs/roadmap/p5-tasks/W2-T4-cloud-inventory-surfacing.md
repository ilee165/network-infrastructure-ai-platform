# W2-T4 — Cloud inventory API and UI surfacing

| Field | Contract |
|---|---|
| Owner | `wf-implementer-light` |
| Depends on | W2-T2, W2-T3 |
| Review | sonnet combined review |
| Status | Proposed |

## Objective and scope

Expose normalized AWS/Azure inventories through paginated read APIs and an
RBAC-protected UI, following existing inventory patterns. Out: collection
configuration, topology stitching, credential reveal, and cloud writes.

## Requirements and contracts

1. API lists accounts/subscriptions, networks, subnets, routes,
   interconnects, NICs, and provider collection status with stable cursor/order,
   provider/account/region filters, timestamps, and provenance IDs.
2. Viewer may read inventory; collection controls retain existing engineer/admin
   floors. Responses contain no credential fields or unrestricted raw payload.
3. Frontend query keys include all filters; loading, empty, partial, stale,
   error, pagination, and provider states are accessible and deterministic.
4. OpenAPI export/types and user/API docs update in the same task.

## Test and gate plan

API tests cover RBAC, scope/filter isolation, pagination, partial states, and
secret-field absence. UI tests change provider, account, and region filters and
assert distinct query keys/refetches; they explicitly cover loading, empty,
error, pagination, provider, stale, and partial states plus keyboard/
accessibility. Update every partial `vi.mock` sibling when adding exports. Run
backend gates, OpenAPI drift, frontend lint/type/test/build, axe, and coverage
ratchets.

## Exit criteria

- [ ] API/UI expose the complete normalized inventory without secrets.
- [ ] RBAC, pagination, partial/stale states, and accessibility are tested.
- [ ] OpenAPI/types/docs are synchronized.
- [ ] D16 passes; one atomic commit.
