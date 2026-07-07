# W2-T4 — Impact analysis: `fetch_impact` read + Troubleshooting-Agent tool + app-dependency UI view

| | |
|---|---|
| **Wave** | P4 W2 — Application-dependency topology |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | **W2-T1** (projection), **W2-T2** (derived edges) |
| **ADRs** | ADR-0052 §8 (binding), ADR-0005 (knowledge/ = sole Neo4j reader) |
| **PRODUCTION.md** | §2.4 ("impact-analysis query surface"), §11 G-OBS (explainability) |
| **Status** | Implemented — `e20a697`/`f2b0090`/`bf35868`/`0d6f8a4`/`c316fec` (P4 W2) |

## Objective

Implement the ADR-0052 §8 read surface: **the `app` topology layer, a bounded
`fetch_impact` read answering "what depends on X" / "what does application A
depend on", a read-only provenance-citing Troubleshooting-Agent tool, and the
app-dependency UI view with per-edge source badges.**

## Scope

**In** — `knowledge/topology_read.py`: `LAYER_APP` in `LAYERS` /
`rel_types_for_layer` → `(REL_DEPENDS_ON,)`, included in `LAYER_ALL`;
`fetch_impact(client, *, target_label, target_key, depth)` (name PROPOSED in
the ADR — this task binds it): applications reachable against `DEPENDS_ON`
direction for `Device`/`IPAddress`/`Interface`/`Subnet`/`Application` targets
incl. indirect impact through the physical chain, and the reverse direction
(an `Application` target is the entry point for both directions:
dependents-of-application-A and what-application-A-depends-on); depth bounded by
`MAX_NEIGHBORHOOD_DEPTH`; JSON-safe results carrying per edge `sources`,
compact provenance summary, and the `projected_at` watermark; `topology`
router impact endpoint at viewer+; Troubleshooting-Agent tool
`get_application_impact(target)` (`@netops_tool(classification=READ_ONLY)`,
`agents/troubleshooting/tools.py` house pattern) — every dependency claim
cites source + evidence refs + graph watermark; failures return the house
`{"error": ...}` object; frontend: app layer rendered with per-edge source
badges; deterministic tool tests.

**Out** — mutations of any kind (the tool is read-only by classification);
the full derivation eval corpus + impact-correctness thresholds (W4-T2);
PG-side deep provenance drill-down UI beyond the compact summary
(graph summary first; PG detail read only where the ADR names it).

## Requirements (grounded in ADR-0052 §8)

1. **`knowledge/` stays the only Neo4j reader**; the projector the sole writer
   (lint-imports boundary unchanged).
2. **Provenance-citing answers** — the explainability contract: every claim
   references source name + evidence-chain refs + watermark ("as of run X").
3. **Bounded traversal** — the existing depth discipline; no full-graph fetch.
4. **Tool failure ≠ diagnosis abort** — `{"error": ...}` on missing graph.
5. **Read floors match the topology surface** (viewer+).

## Contracts / artifacts

- `topology_read.py` extension; API endpoint + schema; agent tool; UI view;
  API docs; deterministic eval-style unit tests for the citation contract.

## Test & gate plan

- Full gate suite + frontend gates.
- Read tests: direct + indirect impact paths, reverse direction, depth bound,
  empty graph, provenance fields present on every edge.
- Tool tests: citation contract, error-object contract, READ_ONLY
  classification asserted.
- Recording-rule/SLO tests unregressed (no projector changes here).

## Exit criteria

- [ ] `app` layer served by existing graph/neighborhood surfaces; impact endpoint live at viewer+.
- [ ] `fetch_impact` answers both directions with provenance + watermark, depth-bounded.
- [ ] Troubleshooting Agent exposes the read-only impact tool; answers cite graph evidence.
- [ ] UI app-dependency view renders with per-edge source badges; frontend tests green.
- [ ] One atomic commit.
- [x] **Transitive IP-bound reach** (PR #119 B3 follow-up, rider
      2026-07-07-1540): a Device/Subnet/Interface impact target's dependents
      now include IP-bound Applications (the F5-VIP shape) reached through the
      physical chain, not only when the `IPAddress` is the direct target.
      `_read_impact`'s dependents Cypher co-key-joins every physically-reached
      `Interface` to its projected `IPAddress` (`ip.pg_id == n.pg_id` — both
      project from the same `normalized_interfaces` row for an address's
      winning interface); no new relationship type, no projector/migration
      change. Proven red→green against a real compose Neo4j. Residual
      boundary (documented, not a defect): if the winning interface for a
      shared address falls outside the queried target's `depth`-bounded
      neighborhood, that `IPAddress` is not reached either. **Follow-up
      (out of scope this round):** wire a `neo4j:` service into the
      `pg-integration` (or a new) CI job so the live-Neo4j proof
      (`TestLiveImpactIpReach` in `test_topology_impact.py`) runs on every PR
      instead of only locally.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Traversal explosion** on dense estates — depth bound + scoped queries;
  no full-graph fetch (G-SCA discipline).
- **Citation gaps** — an edge without provenance in the answer breaks the
  explainability contract; asserted per edge in tests.
