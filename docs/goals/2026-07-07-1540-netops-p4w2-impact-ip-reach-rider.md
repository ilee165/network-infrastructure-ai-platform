Rider for docs/goals/2026-07-07-1540-netops-p4w2-impact-ip-reach-goal.md. Supersedes nothing in prior riders (docs/goals/2026-07-07-1004-netops-p4w2-impact-rider.md) — their invariants still apply: reads-only `knowledge/` boundary, `MAX_NEIGHBORHOOD_DEPTH` discipline, JSON-safe payloads, per-edge `sources`/provenance/`projected_at`.

## Posture (decided — do not redesign)

- Fixes a review-found gap on an ALREADY-OPEN PR (#119), not new feature work. Branch stays `feat/p4-w2-app-dependency-topology`.
- No Alembic migration. No projector write-path change (`project`/`full_rebuild` in `backend/app/engines/topology/projector.py` are untouched — the fix reads data already projected).
- No new Neo4j relationship type. The mechanism (below) is a **read-side Cypher join on an existing shared key**, not a new edge.
- No new pytest marker, no new test directory. `integration` already means "compose-backed Postgres/Neo4j/Redis" (`backend/pyproject.toml` L225) and `test_projector.py` already has the exact skip-clean live-Neo4j convention to copy.
- No new CI job/service. This round proves the fix once, locally, against `docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d neo4j`, captured in the transcript. Wiring a `neo4j:` service block into the `pg-integration` CI job is a named out-of-scope follow-up (below).
- No V1 invention: don't redesign the impact contract, don't add new target kinds, don't touch the tagging/derivation write paths.

## The mechanism (grounded in verified code, HEAD of feat/p4-w2-app-dependency-topology)

**The empirical fact this fix exploits:** `backend/app/engines/topology/nodes.py`:

```python
# L273 InterfaceNode construction (per normalized_interfaces row):
InterfaceNode(pg_id=row.id, name=row.name, ...)  # row: NormalizedInterfaceRow

# L286-294 IPAddressNode construction (per de-duped addressed interface):
addressed = [(ip_interface(row.ip_address), row) for row in interfaces if row.ip_address]
IPAddressNode(pg_id=row.id, address=str(iface.ip))  # SAME row, SAME row.id
```

Both nodes are keyed `pg_id`. When several interfaces share an address, `_ip_deduped` (L294+) keeps the **lowest `pg_id`** — but that `pg_id` is always some real `Interface` row's id. So: **for the "winning" interface, `IPAddress.pg_id == Interface.pg_id`** (same UUID, different label). This is a genuine co-key, not a coincidence — confirm it still holds by reading L138-160 and L260-300 at HEAD before writing any Cypher against it; if a future refactor changes `IPAddressNode`'s key derivation, this entire mechanism needs re-deriving, not patching.

**Why this closes the gap:** `_PHYSICAL_REL_TYPES = (REL_CONNECTED_TO, *_L3_REL_TYPES)` where `_L3_REL_TYPES` includes `REL_HAS_INTERFACE` (Device→Interface) and `REL_IN_SUBNET` (Interface→Subnet). So a Device target's physical neighborhood at depth ≥1 already contains its `Interface` nodes; a Subnet target's neighborhood already contains the `Interface` nodes `IN_SUBNET` to it. **Every `IPAddress` node is derived from some `Interface` row** (never orphaned), so extending the dependents traversal with a same-`pg_id` cross-label match from any physically-reached `Interface` to its co-keyed `IPAddress` is complete for the Device/Subnet cases at the SAME depth bound — no depth increase needed.

**Cypher shape (illustrative — validate against real Neo4j, adjust as needed):**

```cypher
MATCH (x:{target_label}) WHERE x.{key_prop} = $key
MATCH (x)-[:{phys_pattern}*0..{depth}]-(n)
WITH DISTINCT n
OPTIONAL MATCH (ip:IPAddress) WHERE n:Interface AND ip.pg_id = n.pg_id
WITH DISTINCT coalesce(ip, n) AS n2, n
// n2 is the IPAddress when n was its co-keyed Interface, else n unchanged
MATCH (app:Application)-[r:DEPENDS_ON]->(n2)
RETURN labels(app) AS app_labels, properties(app) AS app_props,
       labels(n2) AS target_labels, properties(n2) AS target_props,
       properties(r) AS rel_props
```

Do not treat this literally — Cypher's `coalesce` over node identities and multi-binding semantics need empirical validation (P2/P3 below is exactly that validation). An equally valid alternative shape is a second `OPTIONAL MATCH ... UNION`-style pass, or unwinding `n` and `n`'s co-keyed `IPAddress` into one candidate set before the `DEPENDS_ON` match. Pick whichever the live run proves correct; do not guess from prose alone.

**Known residual boundary (document, don't "fix"):** if the winning (lowest-`pg_id`) interface for a shared address belongs to a Device/Interface that is NOT itself within the queried target's neighborhood-at-depth (e.g., dedup picked a far-away device's interface for the same subnet address — an edge case, but real), the `IPAddress` is not reached by this join either. This mirrors the codebase's existing "unreconcilable" semantics (`app_derivation.py`'s `members_unreconciled` counter) — an absence that is a documented answer, not a bug. P5/P6 below name this boundary as a test, not a defect.

## Phases

### P1 — Live seed helper, reusing the established convention
Add a `# --- Integration: live compose Neo4j ---` section to `backend/tests/knowledge/test_topology_impact.py` (mirroring `test_projector.py` L739-800 exactly: `Neo4jClient(get_settings())`, `health_check()` skip-clean, `full_rebuild(client, nodes, edges, t1, applications=...)` to seed). Build the seed graph via REAL production functions: a `Device` with one `NormalizedInterfaceRow` (mgmt-reachable), an F5 VS/pool/member row set that `derive_applications`/`derive_application_dependencies` turns into an `Application --DEPENDS_ON--> IPAddress` edge, run through `derive_nodes`/edge builders + `full_rebuild`.
Depth tests: `test_live_seed_helper_produces_interface_and_ipaddress_sharing_pg_id` (query both nodes after seeding, assert `ip.pg_id == interface.pg_id` for the winning interface — proves the mechanism's premise empirically, not from prose) and `test_live_neo4j_integration_test_skips_cleanly_without_reachable_service` (temporarily point `NETOPS_NEO4J_URI` at an unreachable port, confirm `pytest.skip`, not error).

### P2 — Reproduce the gap, live, RED
Write `test_live_impact_device_target_reaches_f5_vip_dependent_through_shared_interface_key`: seed per P1, call the REAL `fetch_impact(client, target_label=LABEL_DEVICE, target_key=<device pg_id>, depth=2)` against the live client, assert the seeded Application appears in `result["dependents"]`. Run it against today's (unfixed) `_read_impact` — it MUST fail red (empty `dependents`). Paste the actual failure output in the transcript — this is the live reproduction of B3, not a repeat of the unit-level assertion from 63f465f.

### P3 — Implement the fix
Extend `_read_impact`'s dependents Cypher in `topology_read.py` per the mechanism above, validated empirically against the live service (iterate the Cypher shape until P2's test is green — do not stop at the first shape that merely doesn't error). P2's test goes GREEN. Re-run P1's premise test to confirm it's unaffected.

### P4 — Subnet-target parity
`test_live_impact_subnet_target_reaches_f5_vip_dependent_through_shared_interface_key`: same seed, query `target_label=LABEL_SUBNET` (the interface's subnet), assert the same Application surfaces via the `IN_SUBNET` direction. ADR-0052 §8 names Subnet as a valid impact target — this proves the fix generalizes, not just the Device case.

### P5 — Edge case: winner-interface reachable via a different path
`test_live_impact_shared_address_winner_interface_on_different_reachable_device_still_surfaces_dependent`: seed two devices/interfaces sharing one address where the LOWER-`pg_id` (winning) interface belongs to a device connected to the queried target within `depth` via `CONNECTED_TO`/`L3_ADJACENT` (not the directly-queried device) — assert the dependent still surfaces. Proves the join isn't accidentally scoped to only the directly-matched node.

### P6 — Edge case: winner-interface unreachable (documented boundary)
`test_live_impact_shared_address_winner_on_unreachable_device_yields_no_dependent_not_error`: seed the winning interface on a device with no path to the queried target within `depth`. Assert `dependents == []` (not an error, not a crash) — the residual boundary from the mechanism section, proven rather than assumed.

### P7 — Fast unit-level regression (no service)
In the existing fake-tx suite (`test_topology_impact.py`, non-integration tests), extend the Cypher-shape assertions (matching the existing style: `"*0..3" in dependents_cypher`, `"HAS_INTERFACE" in dependents_cypher`) with `test_dependents_cypher_includes_ipaddress_interface_pg_id_join` — asserts the new join clause is present in the emitted Cypher string, so a future edit gets a fast no-service signal too, not only the live gate.

### P8 — Full regression sweep
Re-run, all green: `pytest backend/tests/knowledge/ backend/tests/engines/topology/ backend/tests/api/test_impact.py backend/tests/agents/troubleshooting/test_impact_tool.py`. Confirm no existing depth-bound (`MAX_NEIGHBORHOOD_DEPTH`) or physical-family assertion regressed.

### P9 — Docstrings
Update `_read_impact`/`fetch_impact` docstrings in `topology_read.py` (the "known limitation" language added in 63f465f) to describe the new IPAddress-reach capability plus the P6 residual boundary, precisely — no overclaiming.

### P10 — Push + PR update
Push the branch. Post one comment on PR #119 citing the live-Neo4j proof (paste the P2→P3 red→green Cypher/output) as the resolution of the B3 note in summary comment #issuecomment-4906952265. Confirm `git diff --stat -- deploy/docker/docker-compose.yml` is empty (revert any local port-mapping edit made to reach the service).

### P11 — Docs (no depth test)
Update `docs/roadmap/p4-tasks/W2-T4-impact-analysis.md` exit criteria to note the transitive-IP-reach capability is now proven live. Confirm ADR-0052 §8 wording ("device → its interfaces → their IPs → applications") matches the shipped behavior — amend only if it doesn't. Note the CI-wiring follow-up (below) in the same doc.

## Out of scope (this round)

- Wiring a `neo4j:` service into the `pg-integration` (or a new) CI job so this test runs on every PR — tracked as a follow-up; this round proves correctness locally only.
- Extending the co-key mechanism to `Interface` as a direct impact TARGET kind (already supported today; not part of this gap).
- Any change to the derivation/tagging write paths, the projector's stale-sweep logic, or the Neo4j uniqueness constraints.
- Performance tuning of the new join (correctness first; the existing depth bound already caps blast radius).

## Dependencies

- Tier 1 (already present, no version change): `neo4j` async driver, `pytest`/`pytest-asyncio`.
- Tier 2/3: none. This round adds no new package to `backend/pyproject.toml` — the fix is a Cypher-string change plus tests using already-imported fixtures (`Neo4jClient`, `get_settings`, `full_rebuild`, `derive_applications`).

## Engineering invariants

- `knowledge/` stays the sole Neo4j reader; the projector stays the sole writer (lint-imports boundary) — untouched by this round.
- Every impact edge still carries `sources`/provenance/`projected_at` — the new join must not bypass `_impact_edge_provenance`/`_collect_stamp`.
- Depth bound (`MAX_NEIGHBORHOOD_DEPTH`) and JSON-safety (`GraphData = dict[str, Any]`, no driver types escaping) hold for the extended query exactly as before.

## Process invariants

- Depth tests written and shown red (P2, live) before the fix (P3) — do not implement first and backfill tests.
- One conventional commit per phase, body ending `(rider PN)`.
- Fresh-context review recommended (`/code-review`) once P10 is pushed, before the operator re-attempts merge.
