# ADR-0022: Infoblox WAPI Plugin and DDI Capability Interfaces

**Status:** Accepted | **Date:** 2026-06-18 | **Milestone:** M5 (new vendor + new capability interfaces — `REPO-STRUCTURE.md` §6)

## Context

CLAUDE.md requires DDI support (BlueCat, Infoblox, Route53) and lists **Discovery → APIs** as a required discovery method. MVP.md §7 scopes **Infoblox only** for M5 (BlueCat/Route53 are PRODUCTION.md waves). ADR-0006 already declares the `DISCOVERY_API`, `DDI_DNS`, `DDI_DHCP`, `DDI_IPAM` capability enum members and reserves the in-repo `infoblox` vendor package; ADR-0007 (D7) fixes **httpx** as the HTTP client. The conformance suite (`backend/tests/plugins/conformance.py`) already anticipates this: capabilities whose typed interface "has not landed in `plugins/base.py` yet (e.g. `DISCOVERY_API` before its milestone)" currently get only the `implementation:<capability>` case; once the interface exists and is mapped in `_INTERFACE_SPECS`, the `fixtures:<capability>` contract attaches automatically.

This ADR fixes the httpx-based WAPI client design, the four DDI/discovery capability interface ABCs, and — critically — the rule that **DDI mutations never write directly; they produce ChangeRequests** (ADR-0020). It also makes `infoblox` the first **API-based discovery** plugin, satisfying the CLAUDE.md "Discovery → APIs" requirement.

## Decision

**An httpx-based Infoblox WAPI client backs one `infoblox` plugin implementing `DISCOVERY_API` + `DDI_DNS`/`DDI_DHCP`/`DDI_IPAM`. The capability interface ABCs split cleanly into read methods (return normalized models) and mutation methods (return a `ChangeRequestDraft`, never perform a write). The plugin satisfies the existing conformance suite by mapping its interfaces in `_INTERFACE_SPECS` and shipping recorded WAPI fixtures.**

### 1. httpx-based WAPI client (D7)

- A `WapiClient` (inside `app/plugins/vendors/infoblox/`, used only within the plugin per ADR-0006 §6) wraps **httpx** against the Infoblox WAPI REST endpoint (`/wapi/v2.x/<objtype>`). Synchronous httpx in the worker (capabilities run in Celery tasks); base URL + WAPI version configured per device; **credentials materialized in-process from the vault** (`device_credentials`, `credential_ref` on `ConnectionParams`, never a stored secret).
- TLS verification on by default; the appliance CA bundle / `verify` setting is part of device connection config. WAPI uses object `_ref` handles as stable identities — read methods carry `_ref` through so a later mutation targets the exact object.
- Raw WAPI JSON is stored verbatim to `raw_artifacts` before parsing (ADR-0006 §3 raw-first), so every normalized row is re-derivable and the audit trail holds even if parsing changes.

### 2. DDI capability interface ABCs (`plugins/base.py`)

Each ABC pairs read methods (typed normalized returns) with mutation methods that **produce a `ChangeRequestDraft`** carrying the intended WAPI calls — they do not call the appliance to write:

- `DiscoveryApiCapability.discover() -> list[NormalizedDiscoveredObject]` — read-only API discovery (networks, zones, members) feeding the discovery engine; first API-based discovery path.
- `DdiDnsCapability`: reads `get_zones()`, `get_records(zone)` → `list[NormalizedDnsRecord]` (the model already exists per ADR-0006 §3); mutations `add_record(...)`, `modify_record(_ref, ...)`, `delete_record(_ref)` → `ChangeRequestDraft`.
- `DdiDhcpCapability`: reads `get_ranges()`, `get_leases(...)`, scope utilization; mutations (range/fixed-address add/modify/delete) → `ChangeRequestDraft`.
- `DdiIpamCapability`: reads `get_networks()`, `get_next_available_ip(network)`; mutations (network/host-record allocation) → `ChangeRequestDraft`.

`NormalizedDnsRecord` / `NormalizedDhcpLease` / `NormalizedNetwork` (new where not already present) are added to `app/schemas/` and the normalized currency rule (ADR-0006 §3) holds.

### 3. Mutations produce ChangeRequests — never direct writes

- A DDI mutation method returns a `ChangeRequestDraft` (target object `_ref`, the exact WAPI verb+body to apply, and an inverse-change rollback spec — e.g. delete-the-added-record, or restore-the-prior-record-state). The DDI Agent (M5 task #10) hands this draft to the ChangeRequest service (ADR-0020), which persists a `change_requests` row of `kind = ddi_record`.
- The **Automation Agent** (ADR-0020 §1 `approved → executing`, ADR-0021 executor) is the only caller that turns a `ChangeRequestDraft` into an actual `WapiClient` write, and only for an `approved` CR. The capability's mutation method itself never opens a write to the appliance. This is exactly the E2E golden path of MVP.md §7 (DDI finds stale record → CR → different user approves → Automation executes via WAPI → verified → audited).
- Post-write verification re-reads the object by `_ref` to confirm the intended end-state (parity with ADR-0021 §verify-after); the inverse-change spec is the structured rollback if verify fails.

### 4. Satisfying the plugin conformance suite

- `infoblox` declares its `capabilities` frozenset and resolves each via `get_capability()` → concrete classes that subclass the new ABCs and override every abstract method — satisfying the `metadata:*` and `implementation:<capability>` case families already in `conformance.py`.
- The new interfaces are mapped in the suite's `_INTERFACE_SPECS`, so the `fixtures:<capability>` family attaches automatically: bundled **recorded WAPI JSON fixtures** replayed through a `FixtureReplayTransport`-style stub make read methods return non-empty results that re-validate against the normalized models and carry `source_vendor = "infoblox"`. A dedicated `test_infoblox_conformance.py` parametrizes over `make_conformance_cases(...)` exactly like the IOS/IOS-XE/EOS suites.
- Mutation methods are conformance-tested for **shape** — that they return a well-formed `ChangeRequestDraft` (correct `_ref`, verb, inverse spec) and perform no I/O — since "passes conformance" must not require a live appliance.

## Consequences

**Positive**
- One plugin delivers all of M5's Infoblox surface (API discovery + DNS/DHCP/IPAM) behind the registry, so the DDI Agent and discovery engine stay vendor-agnostic — BlueCat/Route53 later implement the same ABCs with zero engine changes (ADR-0006 extensibility realized).
- Mutations-as-drafts make "DDI record change requires human approval" structural: the capability layer cannot write, so there is no DDI write path that skips the CR spine.
- The conformance suite's pre-planned handling of not-yet-landed interfaces means `infoblox` plugs into existing test machinery (`_INTERFACE_SPECS` + recorded fixtures) rather than a bespoke harness.
- API-based discovery via WAPI satisfies the long-standing CLAUDE.md "Discovery → APIs" requirement and proves the `DISCOVERY_API` path the cloud plugins will later reuse.

**Negative**
- WAPI `_ref` handles can change across object edits on some Infoblox versions; the read-then-mutate flow must re-resolve by key when a `_ref` is rejected, adding a retry path (covered by the inverse-change verify).
- The normalized DDI models are lowest-common-denominator (ADR-0006 negative); Infoblox-specific richness (extensible attributes, network views) either extends the schema or rides an escape-hatch field invisible to engines.
- Recorded fixtures pin to a WAPI version; appliance upgrades may require refreshing fixtures (same template-maintenance tax ADR-0006 already accepts for CLI parsers).

## Alternatives considered

1. **`infoblox-client` (the official Python WAPI SDK) instead of raw httpx.** Rejected as the contract: ADR-0007 (D7) standardizes httpx as the HTTP client across API plugins (PAN-OS/FortiOS/F5 later); adding a vendor-specific SDK fragments the connectivity stack and its dependency/CVE surface. A thin `WapiClient` over httpx is small and keeps one HTTP posture.
2. **Capability mutation methods that write directly and the agent "remembers" to gate.** Rejected, security-critical: a write-capable capability is a write path that can be called outside the CR spine. Returning a `ChangeRequestDraft` makes direct writes impossible at the type level — only the Automation Agent executes, only for approved CRs (ADR-0020).
3. **Separate plugins per DDI function (one for DNS, one for DHCP).** Rejected: Infoblox is one appliance with one WAPI and one credential; ADR-0006 is "one package per vendor." Partial capability sets within a single plugin are the intended model.
4. **Skip API discovery; treat Infoblox as DDI-only.** Rejected: CLAUDE.md explicitly lists APIs as a discovery method and the `DISCOVERY_API` enum member exists for exactly this; Infoblox is the natural first proof and feeds the DNS-dependency topology layer (M5 task #13).
