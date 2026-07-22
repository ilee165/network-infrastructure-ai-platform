# W2-T3 — Azure network plugin

| Field | Contract |
|---|---|
| Owner | `wf-implementer` (strong) |
| Depends on | W2-T1, ADR-0057 |
| Review | strong credential-flow review |
| Status | Proposed |

## Objective and scope

Build the read-only `azure` SDK plugin for shared cloud inventory and firewall
policy across scoped subscriptions/resource groups. Include bounded
dependencies, docs, fixtures, and live script. Out: Azure mutations and DNS.

## Requirements and contracts

1. Vault-only `ClientSecretCredential`, subscription narrowing, typed partial
   results, `Retry-After` handling, bounded paging, and canonical resource-ID
   comparison follow ADR-0057.
2. Collect VNet/subnet/routes/peerings/VPN/ExpressRoute/NSG/NIC raw-first and
   normalize solely through ADR-0055 models.
3. NSG rules preserve priority/access/direction, inclusive ranges, service
   tags, and application-security-group references without broadening.
4. Entry point, conformance specs, secret-free recorded fixtures, plugin/API
   docs, and read-only live script ship.

## Test and gate plan

SDK fakes cover continuation pages, empty groups, 429 then success, forbidden
subscription, IPv6, prefix/port lists, service tags, ASGs, peerings, VPN, and
ExpressRoute. Run conformance, secret-leak, cross-provider equivalence, full
backend gates, an exported-method allowlist/static API-surface check, and a
planted attempted-mutation case that must be denied. Run lock drift and
coverage ≥80%. Sweep sibling bug classes across AWS before exit.

## Exit criteria

- [ ] Both capabilities pass conformance and normalized round trips.
- [ ] Partial subscriptions and retry/paging behavior are deterministic.
- [ ] Zero plaintext leakage; no write client method is exposed.
- [ ] Strong review, lockfile and D16 pass; one atomic commit.
