# network-infrastructure-ai-platform — P4-W2 Impact Rider (wave close: tagging UI + impact reads)

This rider holds the prescriptive constraints for the goal at
`D:/Multi-Agent workflow/network-infrastructure-ai-platform/docs/goals/2026-07-07-1004-netops-p4w2-impact-goal.md`
(`2026-07-07-1004-netops-p4w2-impact-goal.md`). It is the first goal+rider
pair in this repo, so it supersedes nothing — the repo's standing invariants
(CLAUDE.md, ADR-0052, `.claude/agents/README.md` discipline) still apply.
This rider adds the P4-W2 wave-close plan: the W2-T3 tagging UI and the whole
of W2-T4 (LAYER_APP, `fetch_impact`, impact endpoint, Troubleshooting-Agent
tool, app-dependency UI), plus the wave task ledger with per-task exit
criteria for W2-T1 through W2-T4.

**All paths relative to repo root** `D:/Multi-Agent workflow/network-infrastructure-ai-platform`
(branch `feat/p4-w2-app-dependency-topology`).

## Posture (decided — do not redesign)

- **This round is reads + UI.** No Alembic migration; no table or column
  change; no change to what the projector writes. The W2-T1 schema
  (migration 0018) and W2-T2 derivation are landed and reviewed — build on
  them, do not reopen them.
- **`knowledge/` is the only Neo4j reader; the projector the sole writer**
  (ADR-0005; enforced by lint-imports). `fetch_impact` lives in
  `backend/app/knowledge/topology_read.py` next to the existing reads.
- **No agent tagging tool ships in P4** (ADR-0052 §7; a future one is
  STATE_CHANGING and CR-gated). The only new agent tool this round is
  `get_application_impact`, classification READ_ONLY.
- **CR-gating for manual tagging stays declined** (user decision 2026-07-05).
  Direct write at `engineer`+ with full audit is the decided design — the UI
  implements it, it does not revisit it.
- **Derived applications stay undeletable** from API and UI; manual rows are
  user-owned and no derivation pass touches them (both already
  backend-enforced at 7d64a29 — the UI must not paper over either).
- **Bounded traversal only** — depth ≤ `MAX_NEIGHBORHOOD_DEPTH`; no
  full-graph fetch (G-SCA discipline).
- **No new dependencies**, backend or frontend.
- **No `git push`.** Phased local commits only; the wave PR to main is the
  operator's post-round step.
- **No V1 invention.** A major architectural decision surfaced mid-phase goes
  to `docs/roadmap/p4-tasks/` as a named-deferred note in the wave ledger
  section below — log and continue.

## Wave task ledger — P4-W2 exit criteria (all four tasks)

The wave is done when every box below is checked. P10 verifies each open box
with an in-transcript command.

### W2-T1 — schema + projector (COMMITTED `e0a9af5`; criteria met at commit)

- [x] Tables live behind one expand-only migration (0018), constraints per ADR-0052 §1.
- [x] `Application`/`DEPENDS_ON` project under existing mechanics; union-edge properties per §3.2; no phantom endpoints (MATCH-ed only).
- [x] Layer is part of EVERY production projection pass (sync + rebuild + auto-rebuild) — required positional component, no optional kwarg.
- [x] `ci/kind/selftest/neo4j-rebuild-bite.sh` extended with the new kinds; PARTIAL case still bites.
- [x] Projection-lag SLO rule + tests unregressed; `tests/pg/test_applications_pg.py` green.
- Evidence: commit `e0a9af5` (23 files); combined review returned zero must-fix.

### W2-T2 — derivation pipelines (COMMITTED `1e8d16f`; criteria met at commit)

- [x] All three automated sources (F5 VIP→pool→member, VMware VM→host, M5 DNS linkage) emit provenance-carrying rows per ADR-0052 §2.
- [x] Re-run ⇒ no-op asserted under real PG; no duplicate applications or edges (`origin_ref` MERGE stability).
- [x] Per-source row ownership + manual-untouched asserted under real PG (`tests/pg/test_app_derivation_pg.py`).
- [x] Post-discovery-run trigger wired; derivation never projects.
- Evidence: commit `1e8d16f`; combined review returned zero must-fix.

### W2-T3 — manual tagging (backend COMMITTED `7d64a29`; UI = this round P1–P3)

- [x] Direct-write tagging API live at `engineer`+ with full audit per mutation; reads at viewer+ (`backend/app/api/v1/applications.py`).
- [x] Derived-application delete refused; manual-row ownership asserted; hash-chain membership tested (`backend/tests/pg/test_application_tagging_pg.py`).
- [x] No agent tagging tool exposed; standard rate limiting covers the endpoints.
- [ ] UI tag/create/edit/remove flows working; frontend tests green. → P1–P3
- [ ] Write controls hidden below `engineer`; viewer sees a read-only surface. → P3

### W2-T4 — impact analysis (OPEN; this round P4–P9)

- [ ] `app` layer served by the existing graph/neighborhood surfaces; `LAYER_ALL` includes `DEPENDS_ON`. → P4
- [ ] `fetch_impact` answers both directions with per-edge provenance + `projected_at` watermark, depth-bounded. → P5–P6
- [ ] Impact endpoint live on the topology router at viewer+. → P7
- [ ] Troubleshooting Agent exposes the READ_ONLY impact tool; every claim cites source + evidence refs + watermark; failures return `{"error": ...}`. → P8
- [ ] UI app-dependency view renders with per-edge source badges; frontend tests green. → P9

### Wave close

- [ ] Full backend + frontend gate suites green at final HEAD. → P10
- [ ] Docs: API docs for tagging + impact; W2 task-spec Status lines flipped to Implemented. → P11
- [ ] PR to main opened by the operator after the round (not by the executor — no push).

## Data model (files, not fields)

No new persistent state this round. The W2-T1 tables and the W2-T2 rows are
the substrate; everything here reads them (via Neo4j projection) or writes
through the already-committed tagging API. New frontend state is in-memory
store state only (`frontend/src/stores/`), mirroring the DevicesPage pattern.

## Algorithms — `fetch_impact` (the rider is the spec)

```
fetch_impact(client, *, target_label, target_key, depth)
  # target_label ∈ {Device, IPAddress, Interface, Subnet, Application}
  # depth: validated/clamped exactly like the existing neighborhood read
  #        (mirror its handling; never exceed MAX_NEIGHBORHOOD_DEPTH)

  dependents direction ("what depends on X"):
    - direct: Application -[:DEPENDS_ON]-> target
    - indirect: expand the target's physical neighborhood (existing
      L2/L3/attachment edge types, ≤ depth hops), then collect every
      Application with a DEPENDS_ON edge into that neighborhood
  dependencies direction (Application targets only):
    - Application -[:DEPENDS_ON]-> * (≤ depth), i.e. what A depends on
  An Application target answers BOTH directions in one result.

  Mechanics: parameterized Cypher, one read session, scoped MATCH — no
  full-graph fetch. Every returned edge carries {sources, provenance
  summary (compact, refs-only), derived_at}. Result object:
  {target, dependents[], dependencies[], projected_at, depth_used} —
  JSON-safe (no Neo4j types leak).
  projected_at = the layer watermark the projector stamps (the "as of
  run X" the agent tool cites).
```

## Verb signatures

```
GET /api/v1/topology/impact          (viewer+)
    ?target_kind=<device|ip_address|interface|subnet|application>
    &target_ref=<key>                # the target's pg_id / natural key
    [&depth=<int>]                   # default + max mirror the neighborhood endpoint
```

| Refusal case | Response |
|---|---|
| unknown `target_kind` | 422, detail lists allowed kinds |
| `depth` outside the neighborhood endpoint's bounds | same 422 shape as that endpoint |
| unauthenticated | 401 (router floor) |
| target absent from graph | 200 with empty `dependents`/`dependencies` — absence is an answer, not an error |

```
get_application_impact(target: str)   # agents/troubleshooting/tools.py
    @netops_tool(classification=READ_ONLY)
```

| Failure | Return |
|---|---|
| graph unreachable / not projected | `{"error": "<house wording>"}` — never raises into the diagnosis loop |
| unresolvable target string | `{"error": ...}` naming the accepted target forms |
| empty result | normal payload with empty lists + watermark (not an error) |

Every dependency claim in the tool's payload cites: source name(s), evidence
refs (row ids / natural keys — never embedded content), and the
`projected_at` watermark.

## Phases (eleven)

Each phase: write the named depth tests **first** and watch them fail →
implement → gates green (backend: `pytest && ruff check . && ruff format
--check . && mypy && lint-imports` from `backend/` in `.venv`; frontend:
`npm run test && npm run lint && npm run typecheck` from `frontend/`) → one
conventional commit `feat(p4-w2): <slice> (rider PN)` (docs phases use
`docs(p4-w2): ...`).

### P1 — Frontend tagging API client + store

- `frontend/src/api/applications.ts`: typed client for the eight committed
  endpoints (list/get/dependencies reads; create/patch/delete app;
  add/remove dependency). Types mirror `backend/app/schemas/applications.py`.
- Store slice following the existing `frontend/src/stores/` house pattern.

Depth tests (frontend, vitest):
- `applications_client_calls_list_get_and_dependency_endpoints`
- `applications_client_create_sends_manual_origin_payload`
- `applications_client_surfaces_api_error_detail`

### P2 — ApplicationsPage: read surface

- `frontend/src/pages/ApplicationsPage.tsx` + route/nav wiring, mirroring
  DevicesPage/AdcPage conventions: list manual + derived applications with
  origin badge; detail view shows dependency rows with per-row `source`.

Depth tests:
- `applications_page_lists_manual_and_derived_applications`
- `application_detail_shows_dependency_rows_with_source`
- `derived_application_shows_origin_badge_and_no_delete_control`

### P3 — Tagging write flows + role gating

- Create/edit/delete manual application; tag-object-into-application flow
  (pick device/ip target → add `source='manual'` dependency row); manual-edge
  removal. Write controls render only for `engineer`+ (existing role-store
  pattern); viewer gets the same pages read-only.
- Backend contract is fixed — any UI-vs-API mismatch found here is a UI bug
  or a named finding for the operator, never an API edit.

Depth tests:
- `engineer_can_create_edit_delete_manual_application`
- `engineer_can_add_and_remove_manual_dependency_row`
- `viewer_sees_read_only_tagging_surface_without_write_controls`

### P4 — `LAYER_APP` in the topology read layer

- `backend/app/knowledge/topology_read.py`: `LAYER_APP = "app"`, added to
  `LAYERS`, `rel_types_for_layer(app) → (REL_DEPENDS_ON,)`, included in
  `LAYER_ALL`'s union. Existing graph/neighborhood surfaces serve it with no
  new endpoint work.

Depth tests (backend, pytest):
- `layer_app_maps_to_depends_on_rel_types`
- `layer_all_includes_depends_on_edges`
- `unknown_layer_still_rejected`

### P5 — `fetch_impact`: dependents direction

- Implement per the Algorithms section: direct dependents + indirect impact
  through the physical chain, depth handling mirroring the neighborhood read.

Depth tests:
- `fetch_impact_returns_direct_dependents_of_device_target`
- `fetch_impact_reaches_indirect_impact_through_physical_chain`
- `fetch_impact_depth_bounded_by_max_neighborhood_depth`
- `fetch_impact_empty_graph_returns_empty_result_not_error`

### P6 — `fetch_impact`: reverse direction + provenance contract

- Application-target entry point answering both directions; per-edge
  `sources` + compact provenance + `derived_at`; result carries
  `projected_at` and `depth_used`; JSON-safe throughout.

Depth tests:
- `fetch_impact_application_target_returns_both_directions`
- `fetch_impact_every_edge_carries_sources_and_provenance_summary`
- `fetch_impact_result_carries_projected_at_watermark`
- `fetch_impact_results_json_safe_for_api_serialization`

### P7 — Impact API endpoint

- `GET /api/v1/topology/impact` on the existing topology router at viewer+,
  schema in the topology schemas module, refusal cases per the table above;
  API docs entry alongside the other topology endpoints.

Depth tests:
- `impact_endpoint_allows_viewer_and_rejects_anonymous`
- `impact_endpoint_validates_target_kind_and_depth`
- `impact_endpoint_response_matches_schema_with_provenance`

### P8 — Troubleshooting-Agent tool

- `get_application_impact(target)` in `backend/app/agents/troubleshooting/tools.py`,
  house `@netops_tool(classification=READ_ONLY)` pattern; deterministic tests
  (no live LLM) for the citation and error contracts.

Depth tests:
- `get_application_impact_cites_source_refs_and_watermark_per_claim`
- `get_application_impact_returns_error_object_when_graph_missing`
- `get_application_impact_registered_read_only_classification`

### P9 — UI app layer + source badges

- TopologyPage: `app` layer selectable; DEPENDS_ON edges render per-edge
  source badges (`f5` / `vmware` / `dns` / `manual`); impact result shows the
  watermark and a sane empty state.

Depth tests (frontend):
- `topology_page_offers_app_layer_selection`
- `app_layer_edges_render_per_source_badges`
- `impact_view_shows_watermark_and_empty_state`

### P10 — Wave-close verification sweep (evidence phase; no new depth tests)

- Full backend gate suite + frontend gate suite at HEAD, output in
  transcript.
- Recording-rule tests (`slo-recording.rules.test.yaml`) unregressed — no
  projector changes were made this round.
- Walk the wave task ledger above: for every open checkbox, run the proving
  command in-transcript and check it off in this file (edit the rider — the
  ledger is the wave's exit-criteria record).
- `graphify update .` after the final code commit.

### P11 — Docs + status flips (doc only; no depth test)

- API documentation covers the tagging endpoints (7d64a29) and the impact
  endpoint (P7) — extend the repo's existing API-docs surface, matching its
  format.
- Flip `Status: Proposed` → `Status: Implemented` in
  `docs/roadmap/p4-tasks/W2-T1-app-schema-projector.md`, `W2-T2-derivation-pipelines.md`,
  `W2-T3-manual-application-tagging.md`, `W2-T4-impact-analysis.md`, each
  with its landing commit SHA.
- No CHANGELOG file exists in this repo; the per-phase conventional commits
  are the changelog.

## Integration matrix (role × surface)

| Surface | anonymous | viewer | operator | engineer | admin | agent session |
|---|---|---|---|---|---|---|
| List/read applications + dependencies (API/UI) | 401 / login | read | read | read | read | via READ_ONLY tools only |
| Tagging writes (API/UI) | 401 | refused / controls hidden | refused / hidden | full | full | no tool exists |
| Impact endpoint + app layer | 401 | read | read | read | read | `get_application_impact` |
| Delete `derived` application | 401 | refused | refused | refused (origin check) | refused (origin check) | n/a |

## Error-footer canonical pairs

| Error | `try:` |
|---|---|
| Impact endpoint 422 unknown `target_kind` | `try: target_kind=device\|ip_address\|interface\|subnet\|application` |
| Tool `{"error": "graph unavailable"}` | `try: run a discovery sync or POST the topology rebuild endpoint, then re-ask` |
| UI write refused (role below engineer) | UI shows the required role, not a raw 403 body |
| Delete refused on `origin='derived'` | UI explains derivation owns the row; offer manual-edge removal instead |

## Out of scope (explicitly not in this round)

- Derivation eval corpus + precision/recall + impact-correctness thresholds — W4-T2.
- CR-gated tagging or any agent-facing tagging tool — declined / future STATE_CHANGING work.
- `derived`-application suppress flag — named-deferred in ADR-0052.
- PG-side deep provenance drill-down UI beyond the compact summary — graph summary first.
- `DnsRecord` / app-to-app dependency targets — named-deferred.
- Flow telemetry as a derivation source — closed set of four sources stands.
- Role-floor changes (Consultant refinement item, later).

## Dependencies (Tier 1 / 2 / 3 policy)

Tier 1 (utility, free): none — the round uses only in-repo patterns.
Tier 2 (architectural): none expected; adding one violates Posture — stop and log.
Tier 3 (blocked): anything touching secret material or new external services.

## Engineering invariants (do not violate)

- **No schema changes; no projector-write changes.** The graph this round
  reads is exactly what W2-T1 projects.
- **`knowledge/` sole Neo4j reader; projector sole writer** — lint-imports
  must stay green without contract edits.
- **Depth-bounded, scoped queries only**; no unbounded traversal, ever.
- **Every impact edge cites provenance** — an edge in any answer (API, tool,
  UI) without `sources` + provenance summary breaks the explainability
  contract; asserted per edge in tests.
- **Provenance is refs-only** — row ids / natural keys, never embedded
  content (no secret path).
- **Tool failure ≠ diagnosis abort** — the agent tool returns the house
  error object; it never raises into the troubleshooting loop.
- **One depth test red before each phase's implementation.** A phase whose
  tests were never red is suspect.
- **No silent expansion** — anything beyond P1–P11 goes into the wave ledger
  as a named-deferred bullet.

## Process invariants

- Phased local commits only; no `git push`. One commit per phase, subject
  ending `(rider PN)`, so `git log --grep "rider P5"` finds P5.
- Both gate suites green before every commit that touches their tree
  (backend phases: backend gates; frontend phases: frontend gates; P10: both).
- The wave ledger in this rider is updated in place as criteria are verified
  (checkbox flips are part of P10's commit).
- After the round: operator opens the PR to main (prior-wave pattern:
  PR → CI → squash-merge) and runs the vault/memory sync.
- A fresh-context reviewer pass (`/code-review` or a second agent on the
  diff) reviews the round before the PR — the executor never self-certifies.
