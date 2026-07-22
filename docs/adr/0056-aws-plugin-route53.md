# ADR-0056: AWS Network and Route53 Plugin

**Status:** Proposed | **Date:** 2026-07-21 | **Milestone:** P5 W0

## Context

AWS is the first P5 cloud provider and completes the required DDI triad through
Route53. It must implement ADR-0055 rather than create AWS-shaped platform
interfaces, and must remain read-only.

## Decision

Create vendor `aws` using boto3/botocore with `CLOUD_NETWORK_INVENTORY`,
`FIREWALL_POLICY`, and `DDI_DNS`. A session is created only from an ADR-0055
vault credential. Optional STS `AssumeRole` uses a fixed `netops` session name,
optional external ID, short-lived credentials, and expiry-aware refresh.
Credential material is never passed in URLs or recorded fixtures.

Account identity comes from STS. Enabled regions are enumerated once per run;
an explicit configured region allowlist narrows collection. One region failure
is a typed partial result and does not erase successful regions. EC2 paginators
collect VPCs, subnets, route tables, VPC peerings, transit gateways and
attachments, VPN connections/gateways, Direct Connect gateways/connections,
security groups, and ENIs. Raw pages are persisted verbatim before parsing.

SDK standard retries are configured in adaptive mode with bounded attempts.
`Throttling`, `RequestLimitExceeded`, and transient 5xx responses use jittered
exponential backoff; authentication/authorization and validation failures are
not retried. Pagination tokens are scoped to one operation/region and a replay
cannot duplicate normalized identities.

Mappings follow ADR-0055. VPC peering, TGW, VPN, and Direct Connect resources
become typed `NormalizedCloudInterconnect` records with endpoint IDs and route
evidence. Security groups map to `NormalizedFirewallRule`; SG references remain
named references. ENIs retain VPC/subnet IDs and all private IPs.

Route53 uses the existing `DDI_DNS` interface. `list_hosted_zones` is global;
private-zone VPC associations are retained. `list_resource_record_sets` is
paginated per zone. Alias targets, routing-policy metadata, TTL, record type,
and values map to existing normalized DNS zone/record models; unsupported
record details remain in the raw artifact. Route53 Resolver endpoints/rules are
out of P5.

Fixtures are verbatim botocore-shaped response JSON with deterministic account,
region, and timestamps. Stubbed tests cover pagination, empty regions,
throttling then success, permanent access denial, expired STS refresh, IPv6,
SG-to-SG rules, private/public zones, aliases, and multi-page record sets. A
ready-to-run live script performs read-only counts and redacted normalization;
execution is deferred until a cloud account is supplied.

## Consequences

The dependency lock gains bounded boto3/botocore versions. AWS collection is
explainable and replayable offline, while live credentials stay solely in the
D11 vault. No EC2, network, IAM, or Route53 mutation API is callable.
