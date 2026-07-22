# W3-T1 — Cloud topology PostgreSQL schema and Neo4j projector

| Field | Contract |
|---|---|
| Owner | `wf-implementer` |
| Depends on | ADR-0058; W2-T1 model contract |
| Review | sonnet spec + quality |
| Status | Proposed |

## Objective and scope

Persist normalized cloud observations in expand-only PG tables and project all
ADR-0058 cloud node/edge kinds to Neo4j, including full rebuild. Out: hybrid
derivation and impact UI.

## Requirements and contracts

1. Migration keys identities by provider/account/region/external ID, records
   discovery provenance and lifecycle, and supports idempotent upsert under PG.
2. Projector maps only normalized non-secret properties and source IDs;
   incremental sync and full rebuild produce equivalent graphs.
3. Stale observations close deterministically without cross-provider deletion;
   retry/replay cannot duplicate nodes or edges.
4. Projection metrics extend existing lag/error series with bounded labels.

## Test and gate plan

PG tests cover concurrent/repeated upserts, stale closure, partial run rollback,
and identity collisions under `backend/tests/pg/` with
`pytestmark = pytest.mark.integration`; prove selection with
`pytest -m integration --collect-only backend/tests/pg`. Neo4j integration
compares incremental versus rebuilt graph. Run topology suites, migration checks, PG integration, kind
`neo4j-rebuild-bite.sh`, SLO rules, and full backend gates.

## Exit criteria

- [ ] Cloud source state is authoritative in PG and idempotent.
- [ ] Incremental projection and clean rebuild are graph-equivalent.
- [ ] Projection-lag SLO remains valid with new kinds.
- [ ] D16, PG integration, and rebuild bite pass; one atomic commit.
