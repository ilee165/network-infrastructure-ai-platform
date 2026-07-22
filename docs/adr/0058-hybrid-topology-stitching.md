# ADR-0058: Hybrid Cloud Topology Stitching

**Status:** Proposed | **Date:** 2026-07-21 | **Milestone:** P5 W0

## Context

Cloud inventory is useful only when joined to the authoritative on-premises L3
graph. D4/D5 require durable source state in PostgreSQL and a rebuildable Neo4j
projection. A CIDR overlap alone is not proof of connectivity.

## Decision

Add expand-only PostgreSQL tables for cloud networks, subnets, route tables,
routes, NICs, interconnect endpoints, DNS-zone associations, and derived hybrid
edges. Rows use canonical provider identity from ADR-0055, discovery-run/source
references, observed timestamps, and a normalized payload version. Unique keys
make collection and derivation idempotent. Stale observations are closed by the
existing inventory lifecycle; they are not immediately hard-deleted.

Project `CloudNetwork`, `CloudSubnet`, `CloudNic`, and `InterconnectEndpoint`
nodes plus `CONTAINS`, `ATTACHED_TO`, `ROUTES_TO`, `PEERS_WITH`, and
`HYBRID_CONNECTED_TO` edges. Every projected element carries only normalized,
non-secret properties and a PostgreSQL source identity. Neo4j stores no
authoritative cloud or stitching-only state.

### Stitching rules

A hybrid edge requires a matched endpoint pair and positive route evidence:

| Provider mechanism | Cloud endpoint evidence | On-prem endpoint evidence |
|---|---|---|
| AWS site-to-site VPN | VPN connection/gateway, customer-gateway address, advertised/static routes | device tunnel/interface peer plus reciprocal route |
| AWS Direct Connect | virtual interface/gateway association and prefixes | BGP neighbor/circuit metadata plus reciprocal route |
| Azure VPN | connection/local-network-gateway peer and prefixes | device tunnel/interface peer plus reciprocal route |
| Azure ExpressRoute | circuit/peering connection and prefixes | BGP neighbor/circuit metadata plus reciprocal route |

Provider endpoint ID, peer address/circuit key, and route compatibility are
evaluated in that order. CIDR overlap or route compatibility without endpoint
evidence creates a candidate finding, not an edge. Multiple valid sources
merge deterministically; contradictory endpoint ownership suppresses the edge
and emits a conflict finding. Confidence is `confirmed` only with both endpoint
and reciprocal route evidence, otherwise `inferred` when the provider contract
explicitly permits a one-sided route view.

Each edge stores a canonical derivation key, source observation IDs, mechanism,
endpoint IDs, matched prefixes, confidence, algorithm version, and `derived_at`.
Re-running the same inputs produces the same key and no duplicates. Changed
inputs supersede the old edge. Deletes are scoped to one derivation source and
cannot remove evidence owned by another source.

Private Route53 zone VPC associations create `DNS_SERVES` links from zones to
cloud networks. Existing DNS record dependency derivation then links names to
addresses/resources; zone association never itself asserts application reach.

Hybrid impact/reachability queries extend the existing topology read facade.
They accept source/target plus optional snapshot, traverse only active scoped
edges, and return path nodes, edges, confidence, and provenance references.
The Troubleshooting Agent uses this typed read-only tool. The UI distinguishes
confirmed, inferred, and candidate/conflict evidence.

The Neo4j rebuild job reads all active cloud and derived rows from PostgreSQL,
excluding lifecycle-closed observations, and recreates the identical live
graph. W3 must keep `neo4j-rebuild-bite.sh` green and prove idempotency under
real PostgreSQL.

## Consequences

Hybrid paths are explainable rather than guessed from address overlap. The
additional durable tables increase projection work, but preserve D5 recovery
and allow deterministic evaluation and conflict handling.
