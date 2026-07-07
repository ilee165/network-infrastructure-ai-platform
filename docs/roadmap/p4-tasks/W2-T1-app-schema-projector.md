# W2-T1 — PG schema + projector: `applications`/`application_dependencies`, mandatory-pass Neo4j projection, rebuild-bite green

| | |
|---|---|
| **Wave** | P4 W2 — Application-dependency topology |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet (data-tier; flag the manual-wins dirty-tracking invariant for explicit review) |
| **Depends on** | **W0-T3** (ADR-0052, the contract) — can start alongside W1 |
| **ADRs** | ADR-0052 §1/§3/§5/§6 (binding), ADR-0005 D5, ADR-0004 |
| **PRODUCTION.md** | §2.4, §11 G-REL, §6 (projection-lag SLO) |
| **Status** | Implemented — `e0a9af5` (P4 W2) |

## Objective

Implement the ADR-0052 persistence + projection layer: **the `applications` +
`application_dependencies` tables behind one expand-only Alembic migration,
projected to Neo4j as `Application` nodes and union `DEPENDS_ON` edges under the
existing projector mechanics, wired into the MANDATORY whole-inventory pass**
(sync, rebuild, auto-rebuild) so the layer is reproduced from Postgres alone —
with `ci/kind/selftest/neo4j-rebuild-bite.sh` staying green over the extended
kind set.

## Scope

**In** — the two tables field-for-field (ADR-0052 §1: CHECK constraints,
case-insensitive unique `lower(name)`, partial-unique `origin_ref` where not
null, natural-key unique `(application_id, target_kind, target_ref, source)`,
reverse index); String-plus-CHECK enum columns (SQLite/PG agreement); schema
constants (`LABEL_APPLICATION`, `NODE_KEY_PROPERTY["Application"]="pg_id"`,
`REL_DEPENDS_ON`); projector integration — node set + edge groups per target
label, endpoints `MATCH`-ed never created, `last_projected_at` stamping, union
edge per (app, target) with `sources`/`derived_at`/compact provenance (§3.2);
**mandatory-pass wiring** (§5: `_load_inventory` in both
`workers/tasks/topology.py` and `engines/topology/rebuild.py`; a required
application component in `derive_topology`/`DerivedTopology` so no pass can
omit the layer); manual-wins dirty-tracking mechanism (§3.3.3); rebuild +
auto-rebuild + bite-script extension (§6.1/§6.2); `test_rebuild_exit_criteria`
extension.

**Out** — the derivation pipelines (W2-T2 writes the rows; this task projects
whatever rows exist); tagging API/UI (W2-T3); impact reads (W2-T4); re-wiring
the M5 `dns=` display layer (out of ADR scope).

## Requirements (grounded in ADR-0052 §1/§3/§5/§6)

1. **Expand-only migration** — new tables only; no existing table/column
   altered (N-2 upgrade discipline).
2. **Mandatory pass, not optional kwarg** — the `dns=` deletion hazard must
   not be repeated; every production projection path carries the layer.
3. **No phantom endpoints** — edge endpoints `MATCH`-ed only; unprojected
   targets emit no edge that pass.
4. **Rebuild-bite stays green AND biting** — the count comparison includes the
   application tables; the PARTIAL (projection-source gap) case goes RED if
   the application layer is missing from a rebuild.
5. **Projection-lag SLO unbroken** — `slo:netops_topology_projection_lag:seconds`
   and the recording-rule tests pass unmodified.
6. **Manual-wins invariant PG-asserted** — derivation-managed refresh never
   overwrites operator-edited `name`/`description`/`owner`/`fqdns`.

## Contracts / artifacts

- Alembic migration; SQLAlchemy models; `app/knowledge/schema.py` constants;
  projector/rebuild/auto-rebuild wiring; extended
  `neo4j-rebuild-bite.sh`; `tests/pg/` coverage.

## Test & gate plan

- Full gate suite (`pytest`, `ruff`, `mypy`, `lint-imports`).
- `tests/pg/` under the blocking `pg-integration` job: unique/partial-unique
  semantics, CHECK constraints, natural-key upsert, dirty-tracking invariant.
- Rebuild isomorphism/pg-id tests extended to `Application`/`DEPENDS_ON`;
  stale-sweep convergence test (unstamped app elements swept).
- Recording-rule tests (`slo-recording.rules.test.yaml`) unregressed.

## Exit criteria

- [ ] Tables live behind one expand-only migration, constraints per ADR-0052 §1.
- [ ] `Application`/`DEPENDS_ON` project under existing mechanics; union-edge properties per §3.2; no phantom endpoints.
- [ ] Layer is part of EVERY production projection pass (sync + rebuild + auto-rebuild) — no optional kwarg.
- [ ] `neo4j-rebuild-bite.sh` green with the new kinds; PARTIAL case proven to still bite.
- [ ] Projection-lag SLO rule + tests unregressed; `tests/pg/` green.
- [ ] One atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review (dirty-tracking + sweep semantics called out) → fixer if findings → verifier → one atomic commit.

## Risks

- **Optional-kwarg relapse** — any new call path that can omit the layer
  reintroduces the DNS-layer deletion hazard; the required-component design
  prevents it structurally.
- **Dirty-tracking wrong in either direction** — clobbers operator edits or
  freezes derived metadata (ADR-0052 "Negative" list); PG-asserted both ways.
- **Sweep over-deletion** — a pass that loads apps but not dependencies (or
  vice versa) would sweep valid elements; the loader loads both or neither.
