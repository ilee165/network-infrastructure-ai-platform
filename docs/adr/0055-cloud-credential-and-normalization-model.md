# ADR-0055: Shared Cloud Credentials and Network Normalization

**Status:** Proposed | **Date:** 2026-07-21 | **Milestone:** P5 W0

## Context

P5 adds AWS and Azure without allowing either provider to define the platform
model. Both plugins need read-only credentials, a common inventory capability,
and security-policy output consumable by the existing Security Agent. D4 makes
PostgreSQL authoritative, D5 makes Neo4j rebuildable, D6 requires typed
capabilities, D7 selects cloud SDKs, and D11 requires encrypted credentials.

## Decision

Add `Capability.CLOUD_NETWORK_INVENTORY` and a `CloudNetworkInventoryCapability`
interface whose async `get_cloud_network_inventory()` returns a
`NormalizedCloudInventory`. The inventory contains virtual networks, subnets,
route tables/routes, peerings/interconnects, and network interfaces. Every
object carries `provider`, `account_id`, `region`, `external_id`, `name`, and
`raw_ref`; scoped objects also carry parent external IDs and CIDRs. Provider
extensions remain in raw artifacts, not an untyped attributes bag.

| Canonical model | AWS | Azure |
|---|---|---|
| `NormalizedCloudNetwork` | VPC | VNet |
| `NormalizedCloudSubnet` | subnet | subnet |
| `NormalizedCloudRouteTable` / `NormalizedCloudRoute` | route table / route | route table / route |
| `NormalizedCloudInterconnect` | peering, TGW attachment, VPN, Direct Connect | VNet peering, VPN, ExpressRoute |
| `NormalizedCloudNic` | ENI | NIC |

Identity is `(provider, account_id, region, external_id)`; global resources use
`region=None`. CIDRs use canonical `ip_network(..., strict=False)` text. Lists
are deterministically ordered by canonical identity. Missing provider fields
remain `None`; collectors must not invent values.

### Security-policy normalization

AWS security-group and Azure NSG rules map to `NormalizedFirewallRule`.
Ingress/egress map directly; allow/deny is preserved (AWS SG is allow-only).
Protocol and inclusive port constraints are encoded together in the existing
service strings (for example, `tcp/443-443`); only AWS `IpProtocol=-1` or the
Azure `*` protocol maps to `any`. ICMP type/code use the existing service
metadata. `from_port=None,to_port=None` means any port for the named protocol,
while a single port is an equal inclusive range. `0.0.0.0/0` and `::/0` remain
explicit any-source CIDRs. References to another SG/application security group
become named address references, never silently broadened to any. Provider
priority/order is stable, and the source raw reference is retained for
explanation. A provider rule whose protocol restriction cannot be represented
losslessly remains raw-only and emits a normalization finding; it is never
broadened into an unrestricted normalized rule.

### Credential contract

Add vault kinds `aws_access_key`, `aws_assume_role`, and
`azure_service_principal`. Their encrypted payloads are:

```json
{"access_key_id":"AKIA…","secret_access_key":"<secret>","session_token":"<optional>","role_arn":"<optional>","external_id":"<optional>"}
{"source_credential_id":"<uuid>","role_arn":"arn:aws:iam::123456789012:role/NetOpsReadOnly","external_id":"<optional>","session_name":"netops"}
{"tenant_id":"<uuid>","client_id":"<uuid>","client_secret":"<secret>","subscription_ids":["<uuid>"]}
```

Only non-secret metadata (kind, label, account/subscription scope, expiry,
disabled state) may leave the credential service. Secret values are decrypted
only inside the plugin credential-access boundary, are redacted from logs,
exceptions, `repr`, raw fixtures, and API responses, and are never topology
properties. Assume-role credentials reference a vault record rather than
embedding its source secret. Temporary STS expiry is checked before collection;
refresh uses the referenced source credential.

ADR-0040 rotation hooks apply: access keys and service-principal secrets use
stage→verify read-only probe→activate→disable-old; assume-role records rotate by
rotating their source or metadata. Failed verification preserves the active
credential. Every reveal, probe, rotation, and disable action is audited.

Operator docs ship an AWS least-privilege policy limited to the required EC2
network `Describe*`, `directconnect:Describe*`, and Route53 `List*`/`Get*`
actions, plus conditional `sts:AssumeRole` on only the configured role ARNs;
EC2 region discovery is included in that read inventory. The Azure template is
a custom Reader role limited to Microsoft.Network reads. Both rendered policy
templates must be strict subsets of their versioned read-action inventories;
mutation or provisioning actions fail validation. P5 plugins expose no write
method. A future cloud write capability requires a new ADR and an approved
ChangeRequest path.

## Validation

Round-trip and cross-provider equivalence tests prove the canonical shapes.
Credential-leak tests plant every secret in SDK failures and fixtures. Recorded
fixtures contain API responses only, never request authorization. Strong review
covers this entire ADR.

## Consequences

AWS and Azure can evolve independently at the client layer while topology,
security analysis, and APIs consume one stable contract. Provider-only details
remain explainable through immutable raw evidence without contaminating the
normalized schema.
