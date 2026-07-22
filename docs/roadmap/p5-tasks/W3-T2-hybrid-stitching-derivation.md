# W3-T2 — Hybrid stitching and Route53 DNS derivation

| Field | Contract |
|---|---|
| Owner | `wf-implementer` |
| Depends on | W3-T1, W2-T2, W2-T3, ADR-0058 |
| Review | sonnet spec + quality |
| Status | Proposed |

## Objective and scope

Derive explainable hybrid edges for AWS VPN/Direct Connect and Azure
VPN/ExpressRoute, and link private Route53 zones into the DNS graph. Out: CIDR-
only guessed links, telemetry enrichment, or Neo4j-only writes.

## Requirements and contracts

1. Match endpoint identity/circuit or peer evidence before route compatibility;
   overlap alone emits a candidate finding, never a connected edge.
2. Persist canonical derivation keys, mechanism, endpoint/source IDs, matched
   prefixes, confidence, algorithm version, and timestamps in PG.
3. Re-run is idempotent; changed evidence supersedes; source-scoped cleanup
   cannot erase another source; conflicts suppress an edge and remain visible.
4. Project confirmed/inferred edges and Route53 `DNS_SERVES` associations;
   full rebuild reproduces both from PG.

## Test and gate plan

Table-driven fixtures cover each mechanism, reciprocal and one-sided routes,
overlap-only, conflicting ownership, multi-source merge, stale source, IPv6,
rerun, and Route53 private/public association. PG concurrency/idempotency tests
and Neo4j rebuild comparison are blocking. Mutation proof removes endpoint
matching and must make the planted wrong-edge case fail.

## Exit criteria

- [ ] All four mechanisms derive only evidence-backed, provenance-rich edges.
- [ ] Wrong-edge, conflict, rerun, stale, and DNS association cases bite.
- [ ] PG remains authoritative and rebuild output is equivalent.
- [ ] D16, PG integration and rebuild bite pass; one atomic commit.
