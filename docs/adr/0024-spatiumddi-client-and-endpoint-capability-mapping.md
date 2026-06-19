# ADR-0024: SpatiumDDI Client and Endpoint↔Capability Mapping

**Status:** Accepted | **Date:** 2026-06-19 | **Milestone:** M-DDI golden-path (SpatiumDDI plugin — `ROADMAP` PR #27 plan)

## Context

CLAUDE.md requires DDI support and a working DDI golden-path lab item. ADR-0022 landed the DDI capability interface ABCs (`DISCOVERY_API`, `DDI_DNS`, `DDI_DHCP`, `DDI_IPAM`) against **Infoblox WAPI**, but Infoblox is appliance-only — we cannot stand it up self-hosted for an end-to-end lab. **SpatiumDDI** (an open-source FastAPI DDI backend, `github.com/spatiumddi/spatiumddi`) is our chosen self-hostable instance to prove the DDI golden path.

This ADR is **API recon**: it maps the live SpatiumDDI REST surface to our ~16 DDI capability methods so the later tasks (client + plugin + deterministic mock + opt-in live run) can be built without a running instance. All paths/fields below are read from the SpatiumDDI `main` backend source (`backend/app/api/v1/**`, `backend/app/main.py`, `backend/app/services/soft_delete.py`, `backend/app/tasks/trash_purge.py`). **No SpatiumDDI source is vendored into our repo** — this ADR is the durable extract.

Decisions of record from the source:

- **Global prefix** — `backend/app/main.py` mounts the v1 router with `app.include_router(api_v1_router, prefix="/api/v1")`. Every path below carries `/api/v1`.
- **Sub-mounts** — `dns/` → `/api/v1/dns`, `dhcp/` → `/api/v1/dhcp`, `ipam/` → `/api/v1/ipam`, `api_tokens/` → `/api/v1/api-tokens`, `admin/trash` → `/api/v1/admin`.
- **Hierarchy** — DNS is **group → view → zone → record**; records live under a zone, which lives under a DNS server group. DHCP is **server-group → scope → {pool, static}**; leases hang off a **server**. IPAM is **space → block → subnet → address**.
- **Object id** — every resource carries a server-assigned `id: uuid.UUID` (Pydantic response field), which is the stable `object_ref` our drafts target. Unlike Infoblox `_ref` (an opaque, edit-mutable handle), SpatiumDDI ids are immutable PKs.

## Decision

**A thin httpx-based `SpatiumClient` (ADR-0007 D7, same posture as `WapiClient`) backs one `spatiumddi` plugin implementing the four ADR-0022 DDI capability ABCs. Reads return the normalized models; mutators return only a `ChangeRequestDraft`. The delete-inverse is an UNDELETE/RESTORE against the SpatiumDDI trash — not a re-create — for soft-deleted resource types.**

### 1. Endpoint ↔ capability mapping

Global prefix `/api/v1` is implicit on every path. "object_ref" is the field a draft pins for its inverse. Request bodies are the load-bearing fields only.

#### DISCOVERY_API — `discover()`

Read-only fan-out over the read endpoints below (spaces+blocks+subnets, zones+records, scopes) to emit `NormalizedDiscoveredObject`s. No single discovery endpoint exists server-side; `discover()` composes `GET /ipam/spaces`, `GET /ipam/blocks`, `GET /ipam/subnets`, `GET /dns/groups/{group_id}/zones`, and `GET /dhcp/server-groups/{group_id}/scopes`.

#### DDI_DNS

| Method | Verb + path | Key request fields | Response shape | object_ref |
|---|---|---|---|---|
| `get_zones` | `GET /dns/groups/{group_id}/zones` | path `group_id`; query `customer_id?`, `tag[]?` | `list[ZoneResponse]` (`id, group_id, view_id, name, zone_type, kind, ttl, primary_ns, admin_email, dnssec_enabled, last_serial, …`) | `ZoneResponse.id` |
| `get_records` | `GET /dns/groups/{group_id}/zones/{zone_id}/records` | path `group_id, zone_id`; query `tag[]?` | `list[RecordResponse]` (`id, zone_id, view_id, name, fqdn, record_type, value, ttl, priority, weight, port`) | `RecordResponse.id` |
| `add_record` | `POST /dns/groups/{group_id}/zones/{zone_id}/records` → `201` | body `RecordCreate`: `name, record_type, value, ttl?, priority?, weight?, port?, view_id?, tags?` | `RecordResponse` | new `RecordResponse.id` |
| `modify_record` | `PUT /dns/groups/{group_id}/zones/{zone_id}/records/{record_id}` | body `RecordUpdate` (all-optional: `name?, value?, ttl?, priority?, weight?, port?, view_id?, tags?`; `record_type` is **immutable** on update) | `RecordResponse` | `record_id` |
| `delete_record` | `DELETE /dns/groups/{group_id}/zones/{zone_id}/records/{record_id}` → `204` | query `permanent: bool = false` (default = **soft-delete**) | empty | `record_id` |

`record_type` ∈ `{A, AAAA, ALIAS, CNAME, MX, TXT, NS, PTR, SRV, CAA, TLSA, SSHFP, NAPTR, LOC, LUA, SVCB, HTTPS, DNAME}` (RFC 9460 `SVCB`/`HTTPS` and RFC 6672 `DNAME` are present; `SVCB`/`HTTPS`/`DNAME`/`ALIAS`/`LUA` are driver-gated to bind9/powerdns). `SRV` requires `priority+weight+port`; `MX` uses `priority` (server defaults to 10); others carry none of the three. A record's full key for mutation is the triple `(group_id, zone_id, record_id)` — the draft must carry all three, with `record_id` as the `object_ref`.

#### DDI_DHCP

SpatiumDDI splits the Infoblox "range" concept into **pools** (dynamic ranges, child of a scope) and **statics** (fixed-address reservations, child of a scope). We map `DDI_DHCP.get_ranges`/`add_range`/`delete_range` onto **pools** (the closest analogue to an Infoblox DHCP range); reservations and leases are surfaced too.

| Method | Verb + path | Key request fields | Response shape | object_ref |
|---|---|---|---|---|
| `get_ranges` | `GET /dhcp/scopes/{scope_id}/pools` | path `scope_id` | `list[PoolResponse]` (`id, scope_id, name, start_ip, end_ip, pool_type, …`) | `PoolResponse.id` |
| `get_leases` | `GET /dhcp/{server_id}/leases` (live) and/or `GET /dhcp/{server_id}/lease-history` (historical, paginated) | path `server_id`; history query `since?, until?, mac?, ip?, hostname?, lease_state?, page, per_page` | `list[LeaseResponse]` (`id, server_id, scope_id, ip_address, mac_address, hostname, state, starts_at, ends_at, expires_at`) / `LeaseHistoryPage{total, page, per_page, items[LeaseHistoryRow]}` | n/a (read-only) |
| `add_range` | `POST /dhcp/scopes/{scope_id}/pools` → `201` | body `PoolCreate`: `name, start_ip?, end_ip?, pool_type="dynamic", lease_time_override?, options_override?` (+ DHCPv6-PD `pd_prefix?, delegated_length?`) | `PoolResponse` | new `PoolResponse.id` |
| `delete_range` | `DELETE /dhcp/pools/{pool_id}` → `204` | path `pool_id` | empty | `pool_id` |

Adjacent (for completeness / the discovery+golden-path): scopes `GET/POST /dhcp/server-groups/{group_id}/scopes`, `GET/PUT/DELETE /dhcp/scopes/{scope_id}`; statics (reservations) `GET /dhcp/scopes/{scope_id}/statics`, `POST` same, `PUT/DELETE /dhcp/statics/{static_id}` (`StaticCreate`: `ip_address, mac_address, hostname?, client_id?, duid?`).

#### DDI_IPAM

SpatiumDDI's "network" = **subnet** (a CIDR with addresses); a **block** is an aggregate container and a **space** is the top container. We map `DDI_IPAM.get_networks`/`add_network`/`delete_network` onto **subnets**.

| Method | Verb + path | Key request fields | Response shape | object_ref |
|---|---|---|---|---|
| `get_networks` | `GET /ipam/subnets` | query filters (space/block/etc.) | `list[SubnetResponse]` (`id, space_id, block_id, network, name, gateway, status, utilization_percent, total_ips, allocated_ips, …`) | `SubnetResponse.id` |
| `get_next_available_ip` | **`GET /ipam/subnets/{subnet_id}/next-ip-preview`** (read-only, no write) | path `subnet_id`; query `strategy="sequential"\|"random"\|"eui64"`, `mac_address?` | `NextIPPreview{address: str\|None, strategy}` (`address=None` ⇒ full / IPv6-unsupported) | n/a (read-only peek) |
| `add_network` | `POST /ipam/subnets` → `201` | body `SubnetCreate`: `space_id, block_id, network, name?, gateway?` (None ⇒ auto-first-usable), `status="active"`, `skip_auto_addresses?` | `SubnetResponse` | new `SubnetResponse.id` |
| `delete_network` | `DELETE /ipam/subnets/{subnet_id}` → `204` | path `subnet_id` (**soft-delete**) | empty | `subnet_id` |

**`get_next_available_ip` has a real server endpoint** (`next-ip-preview`) — we do **not** compute free-space client-side. There is a separate committing allocator `POST /ipam/subnets/{subnet_id}/next` (`NextIPRequest`, writes an `IPAddress`); our read-only capability uses the **preview** form, and any actual allocation is a `ChangeRequestDraft` against `POST .../next` executed only by the Automation Agent. Subnet free-space helpers also exist read-only (`GET /ipam/blocks/{block_id}/free-space` → `list[FreeCidrRange]`, `GET /ipam/blocks/{block_id}/available-subnets` → `list[str]`) and back `add_network` size planning.

### 2. Client semantics (`SpatiumClient`)

- **Base URL** — `https://<host>/api/v1` (the global prefix is baked in). Per-device connection config; TLS verify on by default (ADR-0007), CA bundle settable.
- **Auth** — bearer token. Header `Authorization: Bearer sddi_<token>`; SpatiumDDI mints user-scoped API tokens via `POST /api/v1/api-tokens` (`ApiTokenCreate`: `name, expires_at?\|expires_in_days?, scopes[], resource_grants[]`) and returns the **raw token exactly once** in `ApiTokenCreateResponse.token` (only `token_hash` (sha256) + a `sddi_…` prefix are stored). The server enforces token `scopes` *before* RBAC, so a **read-only token can never reach a write handler** — we provision a least-privilege token and materialize it in-process from the vault (`credential_ref`, never a stored secret; never logged — parity with the token endpoint's "never logged" rule).
- **Pagination** — **no global cursor scheme.** Most list endpoints (`/dns/.../zones`, `/dns/.../records`, `/dhcp/scopes/{id}/pools`, `/ipam/subnets`, …) are **unpaginated** and return a bare `list[...]`, filtered by query params (`tag[]`, `customer_id`, …). Two exceptions: **lease-history** uses **page-number** paging (`page`, `per_page` ≤ 500, `LeaseHistoryPage{total,page,per_page,items}`) and **trash** uses **limit/offset** (`limit` ≤ 1000, `offset`). The client carries page/limit/offset only on those two; everything else is single-shot.
- **Raw-first recording** — every executed HTTP call records its verbatim JSON via the capability's `PluginCapability._record_raw(command, output) -> str` (ADR-0006 §3, `backend/app/plugins/base.py`) **before** parsing into normalized models, so `raw_artifacts` holds the authoritative bytes and every normalized row is re-derivable. `command` = `"<VERB> <path>"`; `output` = the raw response body.

### 3. Soft-delete & rollback semantics

SpatiumDDI `DELETE` is a **soft-delete** for the resource types in `SOFT_DELETE_RESOURCE_TYPES` = `{ip_space, ip_block, subnet, dns_zone, dns_record, dhcp_scope}`: the row is stamped `deleted_at` + `deleted_by_user_id` + a `deletion_batch_id` (descendants share the batch), hidden from queries but recoverable from a **30-day trash** (`backend/app/tasks/trash_purge.py`: daily Celery sweep hard-deletes rows with `deleted_at < now − soft_delete_purge_days`; default **30**, `0` disables).

- **Trash list** — `GET /api/v1/admin/trash` (`type?, since?, until?, q?, limit, offset`) → `TrashListResponse{items[TrashEntry], total}`.
- **Restore (the delete-inverse)** — `POST /api/v1/admin/trash/{type}/{row_id}/restore` → `RestoreResponse{batch_id, restored}`; restores the whole `deletion_batch_id` atomically; `409` if a restore would clash with an active row. `{type}` ∈ `SOFT_DELETE_RESOURCE_TYPES`.
- **Permanent delete** — `DELETE /api/v1/admin/trash/{type}/{row_id}` → `204` (hard); also `DELETE /dns/.../records/{record_id}?permanent=true`.

**Inverse-change spec per resource (what a `ChangeRequestDraft` carries for rollback):**

| Resource | Mutation | Rollback inverse |
|---|---|---|
| dns_record (soft) | create | `DELETE .../records/{new_id}` (soft) → then restore-able |
| dns_record (soft) | update | `PUT .../records/{record_id}` with the captured prior field values |
| dns_record (soft) | delete (soft) | **`POST /admin/trash/dns_record/{record_id}/restore`** — UNDELETE, not re-create |
| subnet / ip_block / ip_space / dhcp_scope (soft) | delete | `POST /admin/trash/{type}/{row_id}/restore` |
| subnet (soft) | create | `DELETE /ipam/subnets/{new_id}` (soft) |
| **dhcp_pool / dhcp_static (HARD)** | delete | **re-create** via `POST /dhcp/scopes/{scope_id}/{pools\|statics}` with the captured prior body — pools and statics are `db.delete(...)` **hard** deletes (NOT in `SOFT_DELETE_RESOURCE_TYPES`); their delete has no trash row to restore |

This **contrasts explicitly with Infoblox (ADR-0022 §3)**, where delete is a hard delete and its rollback is a *re-create* of the captured object. For SpatiumDDI, the rollback of a soft-delete must be a **RESTORE by `(type, row_id)`**; re-creating would orphan the trash row, double the resource on the next purge edge, and lose the original `id`/batch identity. The plugin therefore selects inverse by resource type: **restore for the six soft-delete types; re-create only for hard-delete pools/statics.**

### 4. Write-path invariant (restated)

`spatiumddi` mutators (`add_record`/`modify_record`/`delete_record`, `add_range`/`delete_range`, `add_network`/`delete_network`, and any IP allocation) **return only a `ChangeRequestDraft`** — they perform no HTTP write. The draft carries the target `object_ref` (the SpatiumDDI `id` + parent ids), the exact verb+path+body to apply, and the inverse-change spec from §3. The **Automation Agent** (ADR-0020 `approved → executing`, ADR-0021 executor) is the **sole** caller that turns a draft into a real `SpatiumClient` write, and only for an `approved` ChangeRequest. Four-eyes (ADR-0020) is preserved: the capability layer is write-incapable by type, so no DDI write path can skip the CR spine. Post-write verification re-reads the object by `id` (parity with ADR-0021 verify-after); on verify failure the inverse-change spec is the structured rollback.

### 5. Fixture plan (source-derived)

To drive a **deterministic mock** without a live instance, the plugin ships JSON fixtures **derived from the SpatiumDDI Pydantic response schemas** (clearly labeled `"source-derived, not live-recorded"` in each file header). These re-validate against our normalized models and carry `source_vendor = "spatiumddi"`, satisfying the ADR-0022 `fixtures:<capability>` conformance family via the `FixtureReplayTransport` stub. Minimum set:

- `zones.json` — `list[ZoneResponse]` (≥2 zones incl. a reverse `in-addr.arpa`).
- `records.json` — `list[RecordResponse]` covering `A`, `AAAA`, `CNAME`, `MX` (priority=10), `SRV` (priority+weight+port), `TXT`, and one `HTTPS`/`SVCB` to exercise the RFC-9460 path.
- `pools.json` / `statics.json` — `list[PoolResponse]` (one v4 dynamic range), `list[StaticResponse]` (one MAC reservation).
- `leases.json` — `list[LeaseResponse]` (state=`active`, with `expires_at`).
- `subnets.json` / `next_ip_preview.json` — `list[SubnetResponse]` (+`utilization_percent`/`total_ips`/`allocated_ips`) and a `NextIPPreview{address, strategy:"sequential"}`.
- `trash_restore.json` — a `RestoreResponse{batch_id, restored:1}` to exercise the delete-inverse path.

**Live-recorded fixtures are deferred to the opt-in live run (T6)** against a self-hosted SpatiumDDI; the source-derived set is sufficient for the mock-backed conformance + unit tests in the interim.

### 6. Open questions (require a running instance)

1. **Default `group_id`/`space_id` bootstrapping** — how a fresh SpatiumDDI exposes the default DNS server-group and default IP space (auto-seeded ids vs. operator-created) is needed before the plugin can address zones/subnets without a hard-coded group; resolve against a live instance in T6.
2. **`view_id` requiredness** — DNS zones/records carry an optional `view_id`; whether a default view is auto-created (so we can omit it) or required on multi-view installs needs live confirmation.
3. **Live lease endpoint shape** — `GET /dhcp/{server_id}/leases` returns live Kea/Windows leases whose population depends on a running DHCP agent; the exact freshness/empty behavior (and whether `sync-leases` must run first) is only observable live.
4. **Restore `409` conflict surface** — the precise conflict payload from `default_conflict_check` (which fields collide) needs a live restore-after-recreate to pin the retry/abort branch in the Automation executor.
5. **Token scope vocabulary** — the exact `scopes` strings accepted by `validate_scopes` (e.g. a `dns:read`/`ipam:write` taxonomy) needed to mint a true least-privilege token are best confirmed against `GET`/`POST /api/v1/api-tokens` on a live build.

## Consequences

**Positive**
- One self-hostable instance unblocks the DDI golden-path lab item end-to-end (discover → CR → four-eyes approve → Automation executes → verify → audit) with no appliance.
- The SpatiumDDI `id` is an immutable PK (unlike Infoblox `_ref`), so the read-then-mutate flow has no `_ref`-rotation retry path — drafts pin a stable target.
- Reusing the ADR-0022 ABCs + conformance machinery means `spatiumddi` is a second `DDI_*` implementation with zero engine changes; restore-as-inverse is captured structurally in the draft.

**Negative**
- The DNS path requires the full `(group_id, zone_id, record_id)` triple and SpatiumDDI's pool/static split doesn't line up 1:1 with the Infoblox "range" — the normalized DDI models stay lowest-common-denominator (ADR-0006 negative) and pool↔range is an approximation noted in code.
- Mixed delete semantics (soft for 6 types, hard for pools/statics) force the plugin to branch its inverse-change selection by resource type — a foot-gun if a future SpatiumDDI version flips a type's deletion mode; the inverse-selection table here is the guard.
- Source-derived fixtures pin to the current SpatiumDDI schema; a SpatiumDDI upgrade may require refreshing them (same maintenance tax ADR-0022 accepts), and several behaviors (§6) stay unverified until the opt-in live run.

## Alternatives considered

1. **Compute `get_next_available_ip` client-side from subnet free-space.** Rejected: SpatiumDDI ships a read-only `GET .../next-ip-preview` (and a committing `POST .../next`) — reimplementing allocation client-side would diverge from the server's `_pick_next_available_ip` strategy logic (sequential/random/eui64, pool/reservation exclusions) and risk handing out an IP the server would refuse.
2. **Treat SpatiumDDI delete-inverse as a re-create (mirror Infoblox).** Rejected as incorrect for the six soft-delete types: re-create orphans the trash row, loses the original `id`/`deletion_batch_id`, and collides on the next restore; RESTORE is the server's intended inverse and is atomic across the deletion batch.
3. **Map `get_ranges` to statics (reservations) instead of pools.** Rejected: an Infoblox "range" is a dynamic address range; SpatiumDDI **pools** are the semantic match. Statics are reservations and are surfaced separately for the golden path, not as `get_ranges`.
4. **Use the SpatiumDDI session-cookie/user auth instead of API tokens.** Rejected: bearer API tokens (`sddi_*`) are headless, scope-restrictable (read-only tokens are blocked from write handlers server-side), and vault-storable as a `credential_ref` — the correct posture for a machine integration.
