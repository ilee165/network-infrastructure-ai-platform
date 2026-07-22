# ADR-0057: Azure Network Plugin

**Status:** Proposed | **Date:** 2026-07-21 | **Milestone:** P5 W0

## Context

Azure must be a sibling of the AWS plugin at the normalized boundary while
respecting Azure subscription/resource-group scoping and SDK paging behavior.

## Decision

Create vendor `azure` using `azure-identity` and `azure-mgmt-network`, exposing
`CLOUD_NETWORK_INVENTORY` and `FIREWALL_POLICY`. Authentication uses only the
ADR-0055 `azure_service_principal` vault kind through `ClientSecretCredential`.
Subscription IDs are credential scope; an optional operator allowlist may only
narrow that scope. Tenant, client, and subscription IDs are metadata; the
client secret is always redacted. The credential section inherits ADR-0055 and
does not redefine storage or rotation.

For every subscription, the plugin enumerates VNets/subnets, route tables and
routes, VNet peerings, VPN gateways/connections, ExpressRoute circuits and
connections, NSGs/rules, and NICs across resource groups. Azure resource IDs
are lower-cased for identity comparison but the source spelling is retained in
raw evidence. Azure locations map to `region`; subscription ID maps to
`account_id`. SDK `ItemPaged` sequences are exhausted page-by-page and each raw
page is recorded before normalization.

Azure retry policy uses bounded exponential backoff with jitter for 429 and
transient 5xx responses and honors `Retry-After`; authentication,
authorization, malformed-resource, and not-found scope errors are not retried.
A failed subscription yields a typed partial result without removing successful
subscriptions. Replays upsert canonical identities and never duplicate rows.

Mappings follow ADR-0055. VNet peerings, VPN, and ExpressRoute become typed
interconnects with both endpoint resource IDs and available route evidence.
NICs retain VNet/subnet and private addresses. NSG direction, access, protocol,
priority, source/destination prefixes or application-security-group references,
and inclusive port ranges map to `NormalizedFirewallRule`; service tags remain
named references rather than being expanded with stale address data.

Recorded fixtures are verbatim, secret-free Azure SDK response projections.
They cover continuation paging, empty resource groups, 429 then success,
forbidden subscription, IPv6, multiple address prefixes/ranges, service tags,
application security groups, peering, VPN, and ExpressRoute. A ready-to-run
read-only golden-path script is shipped; live execution is deferred until a
subscription is supplied.

## Consequences

Azure-specific scope and error semantics stay in the client while downstream
topology and Security Agent code sees the shared ADR-0055 models. The plugin
has no Azure write method and requests only Microsoft.Network read actions.
