# W2-T2 — AWS network plugin including Route53

| Field | Contract |
|---|---|
| Owner | `wf-implementer` (strong) |
| Depends on | W2-T1, ADR-0056 |
| Review | strong credential-flow review |
| Status | Proposed |

## Objective and scope

Build the read-only `aws` boto3 plugin for network inventory, firewall policy,
and Route53 DDI using recorded responses. Include bounded dependencies, docs,
and a live-cloud script. Out: Resolver and every mutation API.

## Requirements and contracts

1. Vault-backed session/STS flow, region allowlist, partial-result semantics,
   adaptive bounded retries, and per-operation pagination match ADR-0056.
2. Collect VPC/subnet/routes/TGW/peering/VPN/DX/SG/ENI pages raw-first, then
   normalize field-for-field through ADR-0055.
3. Route53 zones, VPC associations, record sets, aliases, routing metadata,
   TTL/type/value flow through the existing `DDI_DNS` interface.
4. Fixtures are verbatim response bodies with no credential/request headers;
   entry point, conformance specs, plugin docs, API docs, and live script ship.

## Test and gate plan

Botocore stub cases cover multi-page, empty region, 429/5xx recovery, permanent
denial, expired STS, IPv6, SG references, TGW/VPN/DX, private/public zones,
aliases, and multi-page records. Run plugin conformance, DDI golden path,
secret-leak suite, full backend gates, lock drift, and coverage ≥80%. Sweep any
pagination/retry/fixture class fix across Azure before exit.

## Exit criteria

- [ ] All three capabilities pass conformance over recorded fixtures.
- [ ] Route53 completes the DDI triad without a parallel DNS model.
- [ ] Zero plaintext leakage; plugin is mechanically read-only.
- [ ] Strong review, lockfile and D16 pass; one atomic commit.
