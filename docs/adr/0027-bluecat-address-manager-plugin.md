# ADR-0027: BlueCat Address Manager DDI Plugin

**Status:** Accepted | **Date:** 2026-06-20 | **Milestone:** P1 W0 (Vendor Wave 1 — `bluecat`; `P1-PLAN.md` W0/W1, `PRODUCTION.md` §2.2)

## Context

CLAUDE.md requires DDI support across **BlueCat, Infoblox, Route53**. ADR-0022 landed the four DDI/discovery capability ABCs (`DISCOVERY_API`, `DDI_DNS`, `DDI_DHCP`, `DDI_IPAM`) against **Infoblox WAPI**, and ADR-0024 validated that the abstraction is genuinely vendor-neutral by mapping a second backend (**SpatiumDDI**) onto the same ABCs, including the mutators-as-`ChangeRequestDraft` write-path invariant and a resource-typed delete-inverse. `PRODUCTION.md` §2.2 schedules **BlueCat** in Vendor Wave 1 specifically because it "reuses the `DDI_*` capability interfaces and httpx client patterns proven on Infoblox in M5 — validates that the DDI abstraction is genuinely vendor-neutral." `P1-PLAN.md` W0 makes this ADR the design gate; W1 builds the plugin with `wf-implementer-light` mirroring the Infoblox/SpatiumDDI write-path, with **strong-tier credential-hygiene review** and live-lab golden-path **deferred-accepted** (no appliance hardware).

This ADR is **API recon for BlueCat Address Manager (BAM)**: it maps the BAM surface onto our ~16 DDI capability methods so the W1 plugin (client + capabilities + deterministic fixture mock + conformance) can be built without a running appliance. BlueCat exposes **two** API generations and the choice between them is a load-bearing decision:

- **RESTful v2 API** — JSON/HTTP, GA on Address Manager **9.5+**, self-documenting Swagger at `/api/docs`. Resources use **collection-name + numeric-id URIs** (e.g. a host record `1234` is `/api/v2/resourceRecords/1234`); reads use OData-style `filter`/`fields`/`offset`/`limit` query params. ([BAM RESTful v2 Guide 9.5](https://docs.bluecatnetworks.com/r/en-US/Address-Manager-RESTful-v2-API-Guide/9.5.0))
- **Legacy v1 API** — the older SOAP and REST-v1 entity model (generic `APIEntity{id, name, type, properties}` with `getEntities`/`addEntity`/`update`/`delete` verbs). BlueCat now flags v1 as legacy and points new integrations at v2. ([v1→v2 migration guide](https://docs.bluecatnetworks.com/r/Address-Manager-RESTful-v2-API-Guide/v1-REST-API-to-RESTful-v2-API-migration-guide/9.5.0))

Unlike Infoblox WAPI (appliance-only `_ref` handles, ADR-0022) and SpatiumDDI (self-hostable, UUID PKs, ADR-0024), BAM is an **appliance** keyed by a **stable numeric entity `id`**. This ADR extends ADR-0022/0024 (never contradicts them): same ABCs, same draft-only mutators, same vault `credential_ref` posture (ADR-0011 §1) — only the endpoint mapping, the entity hierarchy, the `object_ref` type, and the delete-inverse differ per BlueCat's semantics. **No BlueCat SDK or source is vendored**; this ADR is the durable extract and the fixture spec (§5) is derived from the v2 resource schemas.

## Decision

**A thin httpx-based `BamClient` (ADR-0007 D7, same posture as `WapiClient` / `SpatiumClient`) backs one `bluecat` plugin implementing all four ADR-0022 DDI capability ABCs against the BAM RESTful v2 API (9.5+). Reads return the normalized models; mutators return only a `ChangeRequestDraft` (never an HTTP write). The BlueCat numeric entity `id` is the `object_ref`. BAM `DELETE` is a hard delete, so the delete-inverse is a re-create from the captured prior body — matching Infoblox (ADR-0022 §3), not SpatiumDDI's RESTORE (ADR-0024 §3).**

### 1. Entity hierarchy mapping (BAM → normalized DDI models)

BAM's object tree is rooted at a **Configuration** (a top-level container that isolates an address space + DNS namespace). DNS and IPAM hang off it as parallel subtrees:

| Domain | BAM hierarchy | Normalized currency (ADR-0006 §3 / ADR-0022 §2) |
|---|---|---|
| DNS | **Configuration → View → Zone → ResourceRecord** | `NormalizedDnsRecord` (records); zones surfaced for `get_zones` |
| IPAM | **Configuration → IPv4Block → IPv4Network → IPv4Address** | `NormalizedNetwork` (= IPv4Network); blocks are aggregate containers |
| DHCP | **IPv4Network → DHCPv4Range**; **IPv4Address (state=DHCP_RESERVED, with a MAC)** = fixed reservation | `NormalizedNetwork`/range + `NormalizedDhcpLease` |

Mapping rules (parity with ADR-0024 §1's lowest-common-denominator stance):

- **`DDI_DNS.get_zones` → BAM Zones**, **`get_records`/`add_record`/`modify_record`/`delete_record` → BAM ResourceRecords.** A record's full addressing key is the pair `(view_id, record_id)` for mutation and `(zone_id …)` for listing; the draft pins `record_id` as `object_ref` and carries the parent `view_id`/`zone_id` so a re-create inverse can re-parent. `record_type` ∈ the BAM resource-record set normalized to `{A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, NAPTR, CAA, …}`; BAM models several of these as distinct v1 entity types (`HostRecord`, `AliasRecord`, `MXRecord`, `TXTRecord`, `SRVRecord`, `GenericRecord`) and as a unified `resourceRecords` collection in v2 — the plugin normalizes both onto one `record_type` discriminator.
- **`DDI_IPAM.get_networks`/`add_network`/`delete_network` → BAM IPv4Network** (a CIDR child of an IPv4Block). `DDI_IPAM.get_next_available_ip` → BAM's **`getNextAvailableIP4Address`** server function (BAM computes the next free address; we do **not** compute client-side — same rationale as ADR-0024 alt #1). Blocks (`/api/v2/blocks`) are surfaced read-only for discovery and for sizing an `add_network`.
- **`DDI_DHCP.get_ranges`/`add_range`/`delete_range` → BAM DHCPv4Range** (a child of an IPv4Network — the direct analogue of an Infoblox DHCP range; no pool/static split as in SpatiumDDI). **`get_leases` → BAM DHCP lease objects** (`DHCP_ALLOCATED`/`DHCP_RESERVED` address states + lease entities exposed by the appliance). Fixed reservations are `IPv4Address` rows whose state is `DHCP_RESERVED` carrying a MAC — surfaced for completeness, mutated via the address/reservation endpoints, not via `get_ranges`.

`DISCOVERY_API.discover()` is a **read-only fan-out** (no single discovery endpoint server-side): `GET /api/v2/configurations` → for each, `GET .../blocks`, `.../networks`, `.../views`, `.../views/{id}/zones`, `.../ranges` → emit `NormalizedDiscoveredObject`s feeding the discovery engine and the DNS-dependency topology layer (ADR-0022 §1, brief §6 `RESOLVES_TO`).

### 2. Endpoint ↔ capability mapping

Global prefix `/api/v2` is implicit on every path. `object_ref` is the field a draft pins for its inverse. Request bodies list load-bearing fields only. Reads accept BAM OData query params (`filter`, `fields`, `offset`, `limit`, `orderBy`).

#### DDI_DNS

| Method | Verb + path | Key request fields | Response shape | object_ref |
|---|---|---|---|---|
| `get_zones` | `GET /views/{view_id}/zones` (and nested `GET /zones/{zone_id}/zones` for sub-zones) | path `view_id`; query `filter?, fields?, limit?, offset?` | `ZoneCollection{count, data[Zone]}` (`id, name, absoluteName, type, deployable, …`) | `Zone.id` |
| `get_records` | `GET /zones/{zone_id}/resourceRecords` | path `zone_id`; query `filter?, type?, limit?, offset?` | `ResourceRecordCollection{count, data[ResourceRecord]}` (`id, name, absoluteName, type, rdata/{…}, ttl`) | `ResourceRecord.id` |
| `add_record` | `POST /zones/{zone_id}/resourceRecords` → `201` | body `{type, name, ttl?, …rdata}` (per-type rdata: `A→addresses[]`, `CNAME→linkedRecord/alias`, `MX→priority+linkedRecord`, `TXT→text`, `SRV→priority+weight+port+linkedRecord`) | `ResourceRecord` | new `ResourceRecord.id` |
| `modify_record` | `PUT /resourceRecords/{record_id}` (full replace) or `PATCH /resourceRecords/{record_id}` (partial) | body changed fields; `type` is **immutable** on update | `ResourceRecord` | `record_id` |
| `delete_record` | `DELETE /resourceRecords/{record_id}` → `204` (**hard delete**) | path `record_id` | empty | `record_id` |

`MX`/`SRV` carry `priority` (SRV also `weight`+`port`); `CNAME`/`MX`/`SRV` reference a target via `linkedRecord`/rdata. The record's full key for mutation is `record_id` alone (BAM ids are globally unique across the appliance), but the draft also captures parent `(view_id, zone_id)` for the re-create inverse (§3).

#### DDI_IPAM

| Method | Verb + path | Key request fields | Response shape | object_ref |
|---|---|---|---|---|
| `get_networks` | `GET /blocks/{block_id}/networks` (or `GET /networks?filter=…`) | path `block_id`; query `filter?, fields?, limit?, offset?` | `NetworkCollection{count, data[IPv4Network]}` (`id, name, range (CIDR), gateway, definedRanges?, utilization?, …`) | `IPv4Network.id` |
| `get_next_available_ip` | `GET /networks/{network_id}/addresses/next?…` (server-side `getNextAvailableIP4Address`) | path `network_id`; query `offset?` (start hint) | `{address: str}` (BAM-selected; no client-side free-space math) | n/a (read-only peek) |
| `add_network` | `POST /blocks/{block_id}/networks` → `201` | body `{range (CIDR), name?, gateway?}` | `IPv4Network` | new `IPv4Network.id` |
| `delete_network` | `DELETE /networks/{network_id}` → `204` (**hard delete**) | path `network_id` | empty | `network_id` |

Block-level read helpers back `add_network` sizing: `GET /blocks/{block_id}` (free/allocated counts) and `GET /blocks/{block_id}/networks` (siblings). An actual address allocation (`POST /networks/{network_id}/addresses`) is a **`ChangeRequestDraft`** executed only by the Automation Agent — the read-only capability uses the **`/next`** peek form (parity with ADR-0024 §1 `next-ip-preview` vs. committing `next`).

#### DDI_DHCP

| Method | Verb + path | Key request fields | Response shape | object_ref |
|---|---|---|---|---|
| `get_ranges` | `GET /networks/{network_id}/ranges` | path `network_id`; query `filter?, limit?, offset?` | `RangeCollection{count, data[DHCPv4Range]}` (`id, range/start+end, name, definedProperties?`) | `DHCPv4Range.id` |
| `get_leases` | `GET /networks/{network_id}/addresses?filter=state:in('DHCP_ALLOCATED','DHCP_RESERVED')` (and lease entities where exposed) | path `network_id`; query `filter?, limit?, offset?` | `AddressCollection{count, data[IPv4Address]}` (`id, address, state, macAddress?, leaseTime?, expiryTime?`) | n/a (read-only) |
| `add_range` | `POST /networks/{network_id}/ranges` → `201` | body `{start, end, name?, …}` | `DHCPv4Range` | new `DHCPv4Range.id` |
| `delete_range` | `DELETE /ranges/{range_id}` → `204` (**hard delete**) | path `range_id` | empty | `range_id` |

Reservations (fixed addresses) ride the address endpoints: `POST /networks/{network_id}/addresses` with `state=DHCP_RESERVED` + `macAddress`, `DELETE /addresses/{address_id}`; surfaced for the golden path, not as `get_ranges` (parity with ADR-0024 §1 statics-vs-pools).

### 3. Object identity, hard-delete, and the delete-inverse spec

- **`object_ref` = BlueCat numeric entity `id`.** Every BAM resource carries a server-assigned **immutable** integer `id`, globally unique across the appliance. Unlike Infoblox `_ref` (an opaque, edit-mutable handle that can rotate across object edits — ADR-0022 §Negative), a BAM `id` is a stable PK like a SpatiumDDI UUID (ADR-0024 §Context): **read-then-mutate has no `_ref`-rotation retry path** — a draft pins a stable target.
- **BAM `DELETE` is a hard delete.** There is **no 30-day trash / soft-delete** subsystem as in SpatiumDDI (ADR-0024 §3). A deleted ResourceRecord / IPv4Network / DHCPv4Range is gone from the entity tree; its `id` is not reusable as a restore target. **The delete-inverse is therefore a re-create from the captured prior body — exactly the Infoblox posture (ADR-0022 §3), explicitly NOT the SpatiumDDI RESTORE-by-`(type,id)`.**

**Inverse-change spec per resource (what a `ChangeRequestDraft` carries for rollback):**

| Resource | Mutation | Rollback inverse |
|---|---|---|
| ResourceRecord | create | `DELETE /resourceRecords/{new_id}` |
| ResourceRecord | update | `PUT /resourceRecords/{record_id}` with the **captured prior field values** (re-applied) |
| ResourceRecord | delete (hard) | **re-create** `POST /zones/{zone_id}/resourceRecords` with the captured prior body (new `id` results) |
| IPv4Network | create | `DELETE /networks/{new_id}` |
| IPv4Network | delete (hard) | **re-create** `POST /blocks/{block_id}/networks` with the captured prior `{range, name, gateway}` |
| DHCPv4Range | create | `DELETE /ranges/{new_id}` |
| DHCPv4Range | delete (hard) | **re-create** `POST /networks/{network_id}/ranges` with the captured prior `{start, end, name}` |
| IP allocation (address) | create | `DELETE /addresses/{new_id}` |

Because the re-create inverse mints a **new `id`**, any downstream reference that pinned the old `id` (another draft, a topology edge) is re-resolved by **key** (`absoluteName`+`type` for records; `range` CIDR for networks) on rollback — the same caveat ADR-0022 §3 carries for Infoblox re-create. This **contrasts explicitly with ADR-0024 §3** (SpatiumDDI), where re-creating a soft-deleted row would orphan its trash entry; BlueCat has no trash, so re-create is the **only** correct inverse and there is no orphan hazard. The plugin therefore selects inverse **uniformly by mutation verb** (create→delete-new, update→re-apply-prior, delete→re-create-prior) — simpler than the SpatiumDDI per-resource-type branch (ADR-0024 §3), and it never emits a RESTORE.

### 4. Client semantics (`BamClient`)

- **Base URL** — `https://<appliance>/api/v2` (the global prefix is baked in). Per-device connection config; **TLS verify on by default** (ADR-0007 / ADR-0011 §7), appliance CA bundle / `verify` settable — same as `WapiClient` (ADR-0022 §1).
- **Auth** — BAM v2 mints a **session API token** via `POST /api/v2/sessions` (the login body carries the API-user's username + password materialized in-process from the vault). The exact header form used to present the resulting token on subsequent requests — whether RFC 7617 `Authorization: Basic <base64(token:)>` (token as username, empty password) or the proprietary `BAMAuthToken <token>` header — and the precise encoding rules differ between BAM versions and are **deferred to §7** pending live-appliance verification; the W1 implementer **must not guess the form** from the name alone. **The API user's password is materialized in-process from the vault** (`device_credentials`, `credential_ref` on `ConnectionParams`, ADR-0011 §1) — **never a stored secret, never logged, never returned by any API** (parity with ADR-0022 §1 and ADR-0024 §2). The minted session token is held only in process memory and is redacted from logs/traces like every credential (ADR-0011 §1). **Session TTL and re-authentication:** BAM session tokens have a configurable server-side TTL. A long-running operation such as a multi-configuration discovery fan-out (`DISCOVERY_API.discover()`) may exhaust the token TTL mid-loop and receive an auth failure with no recovery path unless `BamClient` implements re-auth. The W1 implementation **must** either (a) issue a fresh `POST /api/v2/sessions` on 401/session-expired responses (retry-once re-auth pattern) or (b) verify via live-appliance testing that the BAM TTL exceeds the maximum expected task duration and document that bound explicitly. The chosen strategy and verified TTL bounds are **listed in §7** as a required open item to resolve during W1 build. The integration uses a **least-privilege API user** scoped (via BAM access rights / UDF) to the DDI objects it manages.
- **Pagination** — BAM v2 list endpoints are **offset/limit paged** and return `{count, data[...]}` envelopes. The client loops `offset`/`limit` (server default page size, bounded) until `count` is exhausted, accumulating `data`. This differs from Infoblox (`_max_results`/`_page_id` paging, ADR-0022) and SpatiumDDI (mostly unpaginated bare lists, ADR-0024 §2) — the client carries BAM's `offset`/`limit` on every list call.
- **Raw-first recording** — every executed HTTP call records its verbatim JSON via the capability's `PluginCapability._record_raw(command, output) -> str` (ADR-0006 §3, raw-first) **before** parsing into normalized models, so `raw_artifacts` holds authoritative bytes and every normalized row is re-derivable (parity with ADR-0022 §1 / ADR-0024 §2). `command` = `"<VERB> <path>"`; `output` = the raw response body.

### 5. Write-path invariant (restated)

`bluecat` mutators (`add_record`/`modify_record`/`delete_record`, `add_range`/`delete_range`, `add_network`/`delete_network`, and any IP/address allocation) **return only a `ChangeRequestDraft`** — they perform **no HTTP write** (ADR-0022 §3, ADR-0024 §4). The draft carries the target `object_ref` (the BlueCat `id` + parent ids: `view_id`/`zone_id` for records, `block_id` for networks, `network_id` for ranges), the exact verb+path+body to apply, and the inverse-change spec from §3. The **Automation Agent** (ADR-0020 `approved → executing`, ADR-0021 executor) is the **sole** caller that turns a draft into a real `BamClient` write, and only for an `approved` ChangeRequest of `kind = ddi_record` (ADR-0022 §3). Four-eyes (ADR-0020, brief §7) is preserved structurally: the capability layer is write-incapable by type, so no DDI write path can skip the CR spine. Post-write verification re-reads the object by `id` (parity with ADR-0021 verify-after); on verify failure the §3 inverse-change spec is the structured rollback. Because the API user is least-privilege, a leaked or misused token bounds blast radius to the managed DDI objects (PRODUCTION.md §5 per-credential scoping).

### 6. Conformance and fixture plan (source-derived)

`bluecat` declares its `capabilities` frozenset `{DISCOVERY_API, DDI_DNS, DDI_DHCP, DDI_IPAM}` and resolves each via `get_capability()` → concrete classes subclassing the ADR-0022 ABCs and overriding every abstract method — satisfying the `metadata:*` and `implementation:<capability>` case families in `backend/tests/plugins/conformance.py`. The interfaces are already mapped in `_INTERFACE_SPECS` (landed with ADR-0022), so the `fixtures:<capability>` family attaches automatically. A dedicated `test_bluecat_conformance.py` parametrizes over `make_conformance_cases(...)` exactly like the IOS/EOS/Infoblox/SpatiumDDI suites; mutators are conformance-tested for **shape** (well-formed `ChangeRequestDraft` — correct `object_ref`, verb, inverse spec — and **no I/O**), so "passes conformance" requires no live appliance.

To drive the **deterministic mock**, the plugin ships JSON fixtures **derived from the BAM v2 resource schemas** (each file header labeled `"source-derived, not live-recorded"`), replayed through the `FixtureReplayTransport` stub; they re-validate against our normalized models and carry `source_vendor = "bluecat"`. Minimum set:

- `configurations.json` — `{count, data[Configuration]}` (≥1).
- `views.json` / `zones.json` — `{count, data[View]}`; `{count, data[Zone]}` (≥2 zones incl. a reverse `in-addr.arpa`).
- `resource_records.json` — `{count, data[ResourceRecord]}` covering `A`, `AAAA`, `CNAME`, `MX` (priority), `SRV` (priority+weight+port), `TXT`, `PTR` — exercising the per-type rdata normalization.
- `blocks.json` / `networks.json` / `next_ip.json` — `{count, data[IPv4Block]}`; `{count, data[IPv4Network]}` (with utilization/gateway); a `getNextAvailableIP4Address` `{address}` peek.
- `ranges.json` / `leases.json` — `{count, data[DHCPv4Range]}` (one v4 range); `{count, data[IPv4Address]}` with `state=DHCP_ALLOCATED`/`DHCP_RESERVED` (one MAC reservation, `expiryTime`).
- `paged_zones.json` — a two-page `{count, data}` pair to exercise the §4 `offset`/`limit` accumulation loop.

Coverage gate **≥80%** on the plugin package (D16 / PRODUCTION.md §2.6); raw artifacts stored verbatim; normalized models round-trip; write paths via ChangeRequest covered by shape tests.

### 7. Live-lab posture (deferred-accepted)

Per `P1-PLAN.md` §6 and W1, the **opt-in live golden-path run against a real BAM appliance is deferred-accepted** — no BlueCat hardware is available, matching the M4/M5 and SpatiumDDI-T6 posture (ADR-0024 §6 was resolved only when an instance existed). The source-derived fixture set (§6) is sufficient for the mock-backed conformance + unit tests in the interim. Open items requiring a live appliance (to be resolved like ADR-0024 §6.1 when hardware exists): exact v2 paging defaults/caps; precise per-`record_type` rdata field names (`addresses[]` vs. `rdata`) across BAM 9.5/9.6; the **auth-token header form** — whether to use RFC 7617 `Authorization: Basic <base64(token:)>` (token as username, empty password, base64-encoded) or the proprietary `BAMAuthToken <token>` header, and the exact encoding rule for each form; **session token TTL and re-authentication strategy** — the BAM-configured TTL must be measured against the maximum expected task duration (particularly multi-configuration discovery fan-outs), and `BamClient` must implement either a retry-once re-auth on 401 or document a verified TTL bound that covers the worst-case task; the exact `getNextAvailableIP4Address` query contract; and the minimum BAM **access-right** set for a true least-privilege API user.

## Consequences

**Positive**
- BlueCat becomes a **third `DDI_*` implementation** reusing the ADR-0022 ABCs + conformance machinery with **zero engine changes**, completing the on-prem DDI pair (Infoblox + BlueCat) CLAUDE.md requires and proving the abstraction across appliance (`_ref`), self-hosted-UUID (SpatiumDDI), and appliance-numeric-`id` (BlueCat) identity models — directly satisfying the PRODUCTION.md §2.2 "validates the DDI abstraction is vendor-neutral" rationale.
- The BlueCat `id` is an **immutable PK** (unlike Infoblox `_ref`), so the read-then-mutate flow has **no `_ref`-rotation retry path** — drafts pin a stable target, simpler than ADR-0022.
- The delete-inverse is the **uniform re-create posture** (no per-resource-type branch like SpatiumDDI ADR-0024 §3, no trash/RESTORE), and the W1 implementer mirrors the Infoblox write-path almost 1:1 — lowest marginal build cost (P1-PLAN §2 `wf-implementer-light`).
- Mutators-as-drafts make "DDI record change requires human approval" **structural** (ADR-0022 §3): the capability layer cannot write, so no BlueCat write path skips the CR spine; least-privilege API user bounds blast radius (PRODUCTION.md §5).

**Negative**
- The re-create delete-inverse **mints a new `id`**, so rollback must re-resolve downstream references by key (`absoluteName`/CIDR) — the same caveat ADR-0022 §3 carries for Infoblox; a draft that pinned the pre-delete `id` elsewhere needs the key-based re-resolution path.
- BlueCat's **two API generations** (v2 REST on 9.5+ vs. legacy v1 SOAP/REST) mean appliances below 9.5 are unreachable by this plugin; supporting them would require a second client against the v1 `APIEntity` model — explicitly out of scope (we target 9.5+ only).
- The normalized DDI models stay **lowest-common-denominator** (ADR-0006/0022 negative): BlueCat richness (Configurations, Views, UDFs/access-rights, deployment roles) either extends the schema or rides an escape-hatch field invisible to engines; per-type rdata shapes are normalized onto one `record_type` discriminator, losing BAM's distinct record entity types.
- **Source-derived fixtures pin to the BAM 9.5/9.6 schema**; an appliance upgrade may require refreshing them (same maintenance tax ADR-0022/0024 accept), and several behaviors (§7) stay unverified until a live appliance exists (live-lab deferred-accepted).

## Alternatives considered

1. **Use the BlueCat legacy v1 API (SOAP / REST-v1 `APIEntity` model) instead of RESTful v2.** **Rejected.** BlueCat itself flags v1 as legacy and directs new integrations to v2; the v1 generic `APIEntity{id, type, properties}` model with string-blob `properties` is harder to normalize cleanly than v2's typed JSON resources, and SOAP fragments the D7 httpx posture. v2 is JSON/HTTP over httpx, self-documenting, and the path of record on supported (9.5+) appliances. **Chosen:** RESTful v2.
2. **Treat the BlueCat delete-inverse as a RESTORE (mirror SpatiumDDI ADR-0024 §3).** **Rejected as impossible:** BAM has **no soft-delete / trash subsystem** — a deleted entity is hard-gone and its `id` is not a restore target. Re-create from the captured prior body is the only correct inverse (the Infoblox posture, ADR-0022 §3). This is the **deliberate deviation noted against ADR-0024**: BlueCat's inverse is re-create, not RESTORE, because the trash that makes RESTORE correct for SpatiumDDI does not exist here. **Chosen:** uniform re-create inverse (§3).
3. **Map `get_ranges` to BlueCat fixed-address reservations instead of DHCPv4Range.** **Rejected:** an Infoblox/normalized "range" is a dynamic DHCP range; BAM **DHCPv4Range** is the semantic match (parity with ADR-0024 alt #3, where pools — not statics — back `get_ranges`). Reservations (`DHCP_RESERVED` addresses) are surfaced separately for the golden path, not as `get_ranges`. **Chosen:** `get_ranges` → DHCPv4Range.
4. **Compute `get_next_available_ip` client-side from network utilization.** **Rejected:** BAM ships a server-side `getNextAvailableIP4Address` that honors the appliance's allocation policy, reservations, and exclusions; reimplementing it client-side would diverge from the appliance's selection and risk proposing an address BAM would refuse (identical rationale to ADR-0024 alt #1). The read-only capability uses the `/next` peek; actual allocation is a `ChangeRequestDraft`. **Chosen:** server-side next-IP peek.
5. **Separate plugins per DDI function (one for DNS, one for IPAM/DHCP).** **Rejected:** BlueCat Address Manager is one appliance with one API and one credential; ADR-0006 is "one package per vendor" and partial capability sets within a single plugin are the intended model (parity with ADR-0022 alt #3). **Chosen:** one `bluecat` plugin implementing all four ABCs.
6. **Use the `bluecat-libraries` Python SDK instead of a thin httpx `BamClient`.** **Rejected as the contract:** ADR-0007 (D7) standardizes httpx across API plugins (Infoblox WAPI, SpatiumDDI, PAN-OS/F5 later); a vendor SDK fragments the connectivity stack and its dependency/CVE surface (identical rationale to ADR-0022 alt #1). A thin `BamClient` over httpx keeps one HTTP posture. **Chosen:** httpx `BamClient`.
