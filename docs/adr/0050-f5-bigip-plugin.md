# ADR-0050: F5 BIG-IP Vendor Plugin (iControl REST) — `ADC_SERVICES` Capability, Normalized ADC Models, UCS Backup

**Status:** Proposed | **Date:** 2026-07-05 | **Milestone:** P4 W0

## Context

F5 BIG-IP (`f5_bigip`) is the platform's **first ADC vendor** and the lead vendor
of **Wave 3 (P4)**. `PRODUCTION.md` §2.4 assigns it: "ADC layer: VIPs, pools,
members, monitors via iControl REST per D7 — the primary source of
service-to-server mappings, a direct input to application-dependency topology",
with the capability set `DISCOVERY_API`, interfaces, routes (self-IPs),
virtual-server/pool inventory, `HA_STATUS`, and config backup (UCS). This ADR is
the **design gate**; the build is **W1-T1** (`P4-PLAN.md` §3), which binds
field-for-field to the tables below. No code in this ADR.

The decision is bounded by ADR-0006 (plugin contract: typed capability ABCs over
the enum, normalized models as the only engine-visible currency, raw payloads
stored verbatim first), ADR-0007 §D7 (**httpx is the named REST transport for
F5 iControl**), ADR-0011 §D11 (credential vault `credential_ref`, append-only
audit, ChangeRequest for every state change), ADR-0020/0021 (four-eyes CR gating
and the never-silent rollback contract for device writes), and ADR-0034 (the
precedent for ratifying a new capability + normalized models as a W0 design
gate).

Three things make this ADR bigger than a Wave-1/Wave-2 "mirror the reference
plugin" record:

1. **A new capability surface.** Unlike `FIREWALL_POLICY` (already in the enum
   when ADR-0034 ratified its interface), there is **no ADC member in
   `Capability` today** (`backend/app/plugins/base.py:106-124`) and no normalized
   virtual-server/pool models. This ADR adds the enum member, the typed ABC, and
   the models — the primary input contract for the W2 application-dependency
   derivation (ADR-0052), which walks VIP→pool→member chains to emit
   `DEPENDS_ON` edges.
2. **A secret-bearing backup artifact.** F5's full-fidelity backup is the **UCS
   archive** — a binary tar that contains device credentials, password hashes,
   SSL/TLS **private keys**, and the device master key material. It cannot be
   redacted (opaque binary) and it cannot ride the text-shaped
   `ConfigBackupCapability.fetch_running_config() -> str` contract
   (`base.py:520-527`). Handling it is a secret-surface decision (P4-PLAN §0a:
   strong-bar review).
3. **A single-vendor normalization.** The two-vendor rule that validated
   `FIREWALL_POLICY` (PAN-OS + FortiOS, ADR-0034 alt 4) has no counterpart here:
   F5 is the only ADC in the CLAUDE.md vendor set. The second validator for the
   ADC models is the **W2 derivation engine** consuming every field, not a second
   vendor — a named deviation, decided in §4.6.

The platform already runs four httpx-client API plugins — `bluecat`
(`BamClient`), `infoblox`, `panos` (`PanosClient`), `fortios` — with a proven
client discipline (vendor-private `client.py`, credentials in headers never
URLs, name-mangled key attributes, per-instance log-redaction filters, TLS
verify on by default, synchronous calls in Celery workers, raw text returned
verbatim for `_record_raw`). ADR-0035 §1–2 is the closest exemplar and this ADR
mirrors it.

## Decision

**Ship `f5_bigip` as a plain-httpx iControl REST plugin (D7; no third-party F5
client library), authenticating with vault-referenced credentials exchanged for
an `X-F5-Auth-Token` session token, declaring `DISCOVERY_API`, `INTERFACES`,
`ROUTES` (self-IPs + static routes, route domains mapped to `vrf`), the NEW
`ADC_SERVICES` capability returning `NormalizedVirtualServer` /
`NormalizedPool` (with nested `NormalizedPoolMember`) — final names — plus
`HA_STATUS`, and UCS config backup via a NEW additive archive-backup capability
pair. UCS archives are treated as opaque secret material end-to-end:
passphrase-encrypted on-box before download, envelope-encrypted at rest,
metadata-only on every API/log surface, no download endpoint in P4, and restore
strictly as the execution step of an approved ChangeRequest with a
pre-captured baseline archive as the rollback artifact.**

### 1. Client — plain httpx; no F5 client library

**Decision: the plugin uses a thin, synchronous `F5Client`
(`backend/app/plugins/vendors/f5_bigip/client.py`) wrapping `httpx` against
`https://<host>/mgmt/`, mirroring `PanosClient`/`BamClient` one-for-one. No
third-party F5 library is adopted.** Candidates evaluated:

| Candidate | Verdict | Why |
|---|---|---|
| `f5-common-python` (`f5-sdk`, the classic iControl REST SDK) | **Rejected** | Archived/unmaintained upstream; `requests`-based (second HTTP stack beside our pinned httpx); untyped; object wrappers hide the raw response text our raw-first contract (`_record_raw`, ADR-0006 §3) must store verbatim |
| `bigrest` | **Rejected** | Community single-maintainer `requests` wrapper — net-new supply-chain surface and lockfile entry for a convenience layer four sibling plugins already prove we do not need; response objects again obscure raw-first |
| `bigsuds` | **Rejected** | Legacy SOAP iControl (pre-REST generation); wrong API entirely |
| F5 ATC SDKs (AS3/DO-oriented tooling) | **Rejected** | Target declarative-onboarding/AS3 document workflows, not tmos resource reads; wrong shape for capability collection |
| **Plain `httpx`** | **Chosen** | D7 names it for F5 iControl; the discipline is proven in `bluecat`/`infoblox`/`panos`/`fortios`; raw-first needs verbatim response bodies anyway; full control of auth/redaction/token lifecycle; **zero new runtime dependencies** |

The httpx choice is maximally **air-gap friendly** and satisfies the lockfile
rule (P4-PLAN §0a) trivially: `httpx` is already pinned in the dependency
lockfile, so `f5_bigip` adds **no** new backend dependency (unlike `vmware`,
which adds `pyvmomi` — ADR-0051). Nothing new to mirror into an offline package
index.

Client discipline (inherited verbatim from ADR-0035 §1–2 / `PanosClient`):

- **Vendor-private** — `F5Client` is used only inside the `f5_bigip` plugin
  (ADR-0006 §6); engines and agents never see it.
- **Synchronous by design** — capability methods run inside Celery workers,
  never on the FastAPI event loop (ADR-0007 §3).
- **Secrets in headers, never URLs** — the auth token travels in the
  `X-F5-Auth-Token` request header; the login password travels only in the
  login POST body. httpx logs request URLs at INFO; nothing secret may appear
  in a URL in literal or percent-encoded form.
- **Name-mangled secret attributes, no custom `repr`/`str`** (ADR-0011 §1),
  plus a per-instance logging filter on the `httpx` logger that drops any
  record containing the password **or token** in literal or
  URL-percent-encoded form — the `_ApiKeyRedactFilter` pattern, extended to
  cover both secrets.
- **TLS verification on by default**; `verify` rides device connection config.
- **Raw-first** — read methods return the verbatim JSON response text so the
  capability layer records it via `PluginCapability._record_raw` *before*
  parsing (ADR-0006 §3).
- **Paged collection reads** — iControl REST collections (`/mgmt/tm/ltm/pool`
  on a large estate can be thousands of objects) are read with `$top`/`$skip`
  paging at a fixed page size, following the returned paging metadata until
  exhausted; every page's raw body is recorded. Pagination is a named
  sibling-shared bug class (P4-PLAN §0a) — the fixture set includes a
  multi-page collection (§8).

### 2. Credential flow — vault-referenced, token-based (D11)

**Decision: token-based auth is the only steady-state auth mode.** The flow:

1. The device row's `ConnectionParams.credential_ref` names a vault credential
   (ADR-0011); the credentials service materializes the username/password
   **in-process only**. The plugin never receives, stores, or logs a plaintext
   secret of its own — same contract as every existing plugin.
2. `F5Client` POSTs `/mgmt/shared/authn/login` with the credentials and a
   `loginProviderName` (default `"tmos"`; configurable in connection params so
   estates using remote auth — RADIUS/TACACS+/LDAP providers — work unchanged).
   The login request/response bodies are **never** recorded via `_record_raw`
   and never logged: the request carries the password, the response carries the
   token.
3. All subsequent requests carry the returned token in the `X-F5-Auth-Token`
   header. **Token lifecycle:** BIG-IP tokens default to a 1200 s timeout. The
   client treats an authentication-expired response (401 on a tokened request)
   as a signal to re-authenticate once and retry; it does not pre-emptively
   PATCH the token timeout upward (least privilege — no long-lived tokens).
   On session close the client best-effort **revokes** the token
   (`DELETE /mgmt/shared/authz/tokens/<token>`); revocation failure is logged
   (without the token) and non-fatal — the 1200 s expiry bounds the exposure.
4. Both the password and the live token are held in name-mangled attributes
   with no custom `repr`; the redaction filter (§1) covers both, in literal and
   percent-encoded forms. Neither may appear in a normalized record, a raw
   artifact `command` field, an exception message, an API response, or any log
   line — the W1-T1 escalated quality review verifies this (P4-PLAN §2
   escalation set).

**Least-privilege note (named, not hidden):** the read capabilities (§3) work
with a low-privilege F5 role, but **UCS create/download/load require an
administrator-role account** — an F5 RBAC constraint, not our choice. The
recommended deployment is a dedicated service account; rotation rides the
existing ADR-0040 credential-rotation machinery unchanged. A device
provisioned with a lower-privilege credential still serves every read
capability; the archive capabilities then fail with a typed `PluginError`
(plugin-level capability declaration, device-level partial coverage — the
ADR-0025 §4 philosophy).

### 3. Capability map (one row per declared capability)

| Capability | iControl REST source | Normalized return |
|---|---|---|
| `DISCOVERY_API` | `GET /mgmt/tm/sys/version`, `GET /mgmt/tm/sys/global-settings` | one `NormalizedDiscoveredObject` (`kind=OTHER`) representing the device — identity/facts, mirroring `panos` (`plugin.py:199`) |
| `INTERFACES` | `GET /mgmt/tm/net/interface` (+ interface stats subcollection for oper state) | `list[NormalizedInterface]` |
| `ROUTES` | `GET /mgmt/tm/net/route` + `GET /mgmt/tm/net/self` | `list[NormalizedRoute]` — static routes plus connected routes synthesized from self-IPs; route domains → `vrf` (§5) |
| `ADC_SERVICES` **(new)** | `GET /mgmt/tm/ltm/virtual`, `GET /mgmt/tm/ltm/pool?expandSubcollections=true` (+ `/stats` for availability) | `list[NormalizedVirtualServer]` / `list[NormalizedPool]` (§4) |
| `HA_STATUS` | `GET /mgmt/tm/cm/failover-status`, `GET /mgmt/tm/cm/sync-status` | `list[NormalizedHaStatus]` (§6) |
| `CONFIG_BACKUP_ARCHIVE` **(new)** | `POST /mgmt/tm/sys/ucs` (save, passphrase) + download via `/mgmt/shared/file-transfer/ucs-downloads/` | `ConfigArchive` (§7) |
| `CONFIG_RESTORE_ARCHIVE` **(new)** | upload + `POST /mgmt/tm/sys/ucs` (load, passphrase) | `ChangeResult`, **CR-gated only** (§7.4) |

`f5_bigip` declares **no** `CONFIG_BACKUP`/`CONFIG_RESTORE`/`CONFIG_DEPLOY`
(the text-shaped contracts) and no `ACL`/`FIREWALL_POLICY` (AFM is out of
scope; not in the §2.4 row). Text-config drift/compliance for F5 is a **named
deferral** (§7.6).

### 4. NEW `ADC_SERVICES` capability + normalized ADC models

#### 4.1 Enum + typed interface (ratified signature — implemented in W1-T1)

Unlike ADR-0034, this ADR **adds an enum member**: `Capability.ADC_SERVICES =
"adc_services"` (`backend/app/plugins/base.py`, alongside the existing
members). Adding one member + one typed ABC is additive with zero edits to
existing plugins (ADR-0006 §6; ADR-0025 §8 precedent).

```python
# backend/app/plugins/base.py — mirrors FirewallPolicyCapability (ADR-0034 §1)
class AdcServicesCapability(PluginCapability):
    """``Capability.ADC_SERVICES`` — virtual-server/pool/member (VIP) inventory."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.ADC_SERVICES})

    @abstractmethod
    def get_virtual_servers(self) -> list[NormalizedVirtualServer]:
        """Return virtual servers (VIPs) as normalized records."""

    @abstractmethod
    def get_pools(self) -> list[NormalizedPool]:
        """Return pools with nested members as normalized records."""
```

Both methods return normalized models, never dicts/raw (ADR-0006 §3).

#### 4.2 Final model names

**`NormalizedVirtualServer`, `NormalizedPool`, and `NormalizedPoolMember` are
the final names** — the PROPOSED names from `P4-PLAN.md` §3 W0-T1 are adopted
unchanged. `NormalizedVirtualServer` and `NormalizedPool` subclass
`NormalizedRecord` (`normalized.py:280` — provenance triple `device_id` /
`collected_at` / `source_vendor`; `frozen=True`, `extra="forbid"`).
`NormalizedPoolMember` is a **nested frozen sub-model** (plain `BaseModel`,
`frozen=True`, `extra="forbid"`), not a `NormalizedRecord`: members inherit
their pool's provenance triple, and membership is intrinsically hierarchical —
see §4.5.

All name fields carry the F5 **full-path, partition-qualified** form
(`/Common/vs_web`) verbatim; there is no separate partition field. Names are
opaque identifiers to consumers; the derivation joins on them exactly as
collected.

#### 4.3 Field tables (W1-T1 binds field-for-field)

**`NormalizedVirtualServer`** — the fields are exactly what the W2 derivation
(ADR-0052) and the W1-T3 inventory UI need: VIP address, port, protocol, and
the pool link.

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Full-path virtual-server name |
| `vip_address` | `IPv4Address \| IPv6Address \| None` | Destination address, route-domain suffix stripped (§5); `None` when the destination is non-literal (e.g. an address list) |
| `port` | `int \| None` (ge=0, le=65535) | `None` = any (F5 `0`/`any` maps to `None`) |
| `protocol` | `AdcProtocol` | `tcp` / `udp` / `sctp` / `any` / `other` (new StrEnum, §4.4) |
| `vrf` | `str \| None` | F5 route domain (§5); reuses the house `vrf` vocabulary (`NormalizedRoute.vrf`) |
| `enabled` | `bool` | Disabled virtual servers are collected, not dropped (impact analysis needs them) |
| `availability` | `AdcAvailability` | `available` / `offline` / `disabled` / `unknown` (new StrEnum, §4.4) |
| `pool_name` | `str \| None` | Full-path default-pool name — **the VIP→pool join key**; `None` when the VS has no default pool (iRule/policy-only) |
| `description` | `str \| None` | Free text |

**`NormalizedPool`**

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Full-path pool name — the join target of `pool_name` |
| `monitors` | `tuple[str, ...]` | Health-monitor names; `()` = none (monitors are named in `PRODUCTION.md` §2.4) |
| `availability` | `AdcAvailability` | Pool-level availability |
| `members` | `tuple[NormalizedPoolMember, ...]` | Nested members (§4.5); `()` = empty pool |
| `description` | `str \| None` | Free text |

**`NormalizedPoolMember`** (nested sub-model)

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Full-path member name (e.g. `/Common/web01:80`) |
| `address` | `IPv4Address \| IPv6Address \| None` | Member address, route-domain suffix stripped (§5); `None` **only** for unresolved FQDN nodes |
| `fqdn` | `str \| None` | FQDN for FQDN-type nodes — joins to the M5 DNS-dependency layer in W2 derivation |
| `port` | `int` (ge=0, le=65535) | `0` = any |
| `vrf` | `str \| None` | Route domain of the member address (§5) |
| `admin_state` | `AdcAdminState` | `enabled` / `disabled` / `forced_offline` (new StrEnum, §4.4) |
| `availability` | `AdcAvailability` | Monitor-reported member health |

Together these carry every field the W2 derivation spec requires (VIP, port,
protocol, pool membership, member address/port/state) plus the `fqdn` bridge to
DNS dependencies. Deliberately **excluded** (LCD discipline, ADR-0034 §6):
load-balancing method, persistence profiles, SSL profiles, iRules,
connection/session statistics — vendor richness rides the verbatim raw
artifact only (**no `vendor_attributes` escape hatch**, same decision and
rationale as ADR-0034 §6). All fields are config/state metadata; **no field can
carry a secret** (profiles and certificates — where key material lives — are
not collected into the normalized surface).

#### 4.4 New enums (in `normalized.py`, alongside `AclAction`/`HaPeerRole`)

- `AdcProtocol(StrEnum)`: `TCP = "tcp"`, `UDP = "udp"`, `SCTP = "sctp"`,
  `ANY = "any"`, `OTHER = "other"`. F5 `ipProtocol` values map directly;
  `OTHER` covers the long tail so an exotic protocol never breaks
  normalization (the `DiscoveredObjectKind.OTHER` pattern).
- `AdcAvailability(StrEnum)`: `AVAILABLE = "available"`, `OFFLINE = "offline"`,
  `DISABLED = "disabled"`, `UNKNOWN = "unknown"`. Maps F5
  `status.availabilityState` (+ `enabledState` for `disabled`); `UNKNOWN` is
  the safe default (e.g. unmonitored objects report "unknown" — the blue
  state).
- `AdcAdminState(StrEnum)`: `ENABLED = "enabled"`, `DISABLED = "disabled"`,
  `FORCED_OFFLINE = "forced_offline"`. F5's three member session states map
  1:1; future ADC-style sources without a forced-offline concept use the first
  two.

Availability and admin state are **separate dimensions on purpose**: a member
can be admin-enabled yet monitor-down, or admin-disabled yet monitor-up. The
derivation (ADR-0052) needs both to decide whether an edge represents live
traffic; collapsing them into one field would lose exactly the distinction
impact analysis needs.

#### 4.5 Members nest inside pools — decided

F5 returns members as a subcollection of the pool, and the W2 derivation walks
VIP→pool→member as one chain. Nesting `members` inside `NormalizedPool` keeps
the chain traversable in a single record with no string re-join, and avoids
duplicating the provenance triple onto every member row. The alternative (flat
top-level `NormalizedPoolMember` records carrying a `pool_name` back-reference)
is rejected in Alternatives (#4).

#### 4.6 Single-vendor validation — named deviation from the two-vendor rule

`FIREWALL_POLICY` required two independent vendors before being declared
stable (`PRODUCTION.md` §2.3, ADR-0034 alt 4). No second ADC vendor exists in
the CLAUDE.md vendor set, so that rule is unsatisfiable here. **Decision: the
ADC interface is validated by (a) the F5 conformance fixtures (round-trip over
recorded payloads, §8) and (b) the W2 derivation engine consuming every field
as the second, independent consumer.** The interface is declared
**provisionally stable**: if a second ADC-shaped source ever lands (e.g. cloud
load balancers in Wave 4), its ADR must re-run the ADR-0034-style
realizability cross-check against these models before extending them. Named,
not silent.

#### 4.7 Conformance-suite wiring — the three-file lesson (ADR-0025 §8)

The new capability is enforceable only when **all three** land together in
W1-T1: (1) the `AdcServicesCapability` ABC + `Capability.ADC_SERVICES` member
in `base.py`; (2) the three models + three enums in `normalized.py`; (3) an
`_INTERFACE_SPECS` entry in `backend/tests/plugins/conformance.py` mapping
`ADC_SERVICES` → (`AdcServicesCapability`, both method names, both record
models). Without (3) the `fixtures:adc_services` conformance case is
**silently skipped** — the exact failure mode ADR-0025 §8 documented. The same
wiring applies to the archive capabilities (§7).

### 5. Routes via self-IPs; route domains map to `vrf`

`ROUTES` returns the union of:

- **Static/configured routes** from `/mgmt/tm/net/route`, mapped 1:1 to
  `NormalizedRoute` (`protocol="static"`).
- **Connected routes synthesized from self-IPs** (`/mgmt/tm/net/self`): each
  self-IP's network is emitted as a connected route — exactly how a router's
  routing table reports directly-connected networks. This is what
  `PRODUCTION.md` §2.4 means by "routes (self-IPs)": on most BIG-IPs the
  self-IP networks *are* the L3 adjacency picture the topology layer needs.

**Route domains** (F5's VRF analog, the `%<id>` suffix on addresses, e.g.
`10.1.1.1%2`) map to the existing `NormalizedRoute.vrf` field: the parser
strips the `%<id>` suffix before IP parsing and carries the route-domain id as
the `vrf` string (`"0"` — the default route domain — normalizes to `None`).
The same stripping applies to `vip_address` and member `address` in §4.3, with
the id carried in those models' `vrf` fields, because two identical addresses
in different route domains are **different endpoints** — collapsing them would
corrupt the W2 derivation joins. A route-domain-suffixed fixture is mandatory
(§8).

### 6. `HA_STATUS` — DSC failover state onto the existing model

`f5_bigip` implements the existing `HaStatusCapability` (`base.py:765`,
ADR-0025 §8) — the interface ADR-0025 explicitly anticipated F5 would reuse;
**no schema change is needed**. Mapping from `/mgmt/tm/cm/failover-status` +
`/mgmt/tm/cm/sync-status`:

| `NormalizedHaStatus` field | F5 source |
|---|---|
| `ha_domain` | Device-group / sync-group name |
| `peer_role` | failover status `ACTIVE` → `HaPeerRole.ACTIVE`, `STANDBY` → `HaPeerRole.STANDBY` (the enum already carries both — `normalized.py:247-248`) |
| `peer_link_state` / `keepalive_state` | Failover/ConfigSync connection status → `up`/`down`/`unknown` |
| `consistency_check_ok` | sync-status "In Sync" → `True`; "Changes Pending"/"Not All Devices Synced" → `False`; standalone → `None` |
| `peer_address` | Peer device's ConfigSync/failover address when reported |

A standalone (non-DSC) BIG-IP returns a single record with
`peer_role=UNKNOWN` — empty-not-error, consistent with the ADR-0025 §4
read-capability philosophy.

### 7. UCS backup — secret-bearing archive handling (secret surface)

This section is written to the strong bar (P4-PLAN §0a): a UCS archive
contains **device credentials, local-user password hashes, SSL/TLS private
keys, certificates, license, and device master-key material**. It is the
restore artifact precisely *because* it is total — which makes it the most
sensitive artifact this platform stores for any vendor to date. The governing
posture: **the archive is opaque secret material end-to-end; no platform
surface ever parses, renders, logs, or serves its contents.**

#### 7.1 Why not the existing text contracts — new additive capability pair

`ConfigBackupCapability.fetch_running_config() -> str` (`base.py:520`) is a
**text** contract feeding the M4 drift/compliance engines; a UCS is a binary
tar. Base64-smuggling binary through the text contract would poison the drift
engine's diff surface and misrepresent semantics. The supported iControl paths
to a *textual* running config all route through shell-escape endpoints
(`/mgmt/tm/util/bash`) — handing our device credential an arbitrary
remote-shell primitive, which the security posture rejects outright (see §7.6
and Alternatives #6/#7).

**Decision: add two enum members + one ABC pair, additive (ADR-0006 §6):**

```python
# backend/app/plugins/base.py
class ConfigArchiveBackupCapability(PluginCapability):
    """``Capability.CONFIG_BACKUP_ARCHIVE`` — full-fidelity binary config archive (UCS)."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.CONFIG_BACKUP_ARCHIVE}
    )

    @abstractmethod
    def fetch_config_archive(self) -> ConfigArchive:
        """Create, download, and return the device's config archive (secret-bearing)."""


class ConfigArchiveRestoreCapability(PluginCapability):
    """``Capability.CONFIG_RESTORE_ARCHIVE`` — CR-gated full-device archive restore."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.CONFIG_RESTORE_ARCHIVE}
    )

    @abstractmethod
    def restore_archive(self, archive: ConfigArchiveRef, *, plan: ChangePlan) -> ChangeResult:
        """Restore the device from *archive* under the approved-CR *plan* (ADR-0021 contract)."""
```

`ConfigArchive` is a frozen model: `format` (`"ucs"`), `content:
SecretBytes` (Pydantic secret type — masked in `repr`/serialization so the
bytes cannot leak through a stray log/trace/response), `sha256: str` (digest of
the passphrase-encrypted archive as downloaded — safe to log, used for
integrity verification at restore), `size_bytes: int`, and `passphrase_ref:
str` (a vault credential **reference**, never the passphrase itself).
`ConfigArchiveRef` is the persisted-archive handle (id + device), mirroring
`ConfigSnapshotRef`. Names are final. Vendor-neutral by design: a future
vendor with an archive-shaped backup (e.g. a vCenter profile bundle) reuses
the pair unchanged.

#### 7.2 Archive creation — always passphrase-encrypted, on-box residue cleaned

`fetch_config_archive()`:

1. Generates a fresh high-entropy passphrase **per backup** and stores it in
   the credential vault (AES-256-GCM envelope under the ADR-0032 KMS-backed
   master key, D11) as a vault row referenced by `passphrase_ref`. Per-backup
   passphrases mean one compromised passphrase exposes one archive.
2. `POST /mgmt/tm/sys/ucs` with `command=save` **and the `passphrase`
   option** — the archive is encrypted *on the device before it ever crosses
   the wire or rests on the box*. An unencrypted UCS never exists in the
   pipeline. The request body carries the passphrase; that exchange is never
   raw-recorded and never logged (§7.3).
3. Downloads the archive via the ranged file-transfer worker
   (`/mgmt/shared/file-transfer/ucs-downloads/<name>`). The **binary body is
   not a raw artifact** — only the JSON control-plane exchanges (save status,
   delete status) are `_record_raw`-recorded.
4. Best-effort **deletes the on-box UCS file** (`DELETE /mgmt/tm/sys/ucs/…`)
   so no residue accumulates on the device; deletion failure is surfaced in
   the job result (named, non-fatal — the on-box copy is passphrase-encrypted).
5. Computes `sha256` over the downloaded ciphertext and returns the
   `ConfigArchive`.

The archive **includes SSL private keys** (F5's `no-private-key` save option
is deliberately NOT used): an archive without keys cannot actually restore an
ADC that terminates TLS, which would make the backup a false safety net. The
compensating control is the encryption posture, not content stripping.

#### 7.3 Storage, access, and redaction rules

- **At rest:** archives persist in a new `config_archives` Postgres table
  (expand-only migration, W1-T1): metadata columns (device, created_at,
  format, `size_bytes`, `sha256`, `passphrase_ref`) + the ciphertext bytes
  **envelope-encrypted a second time** with the platform's D11/ADR-0032
  machinery (per-archive DEK wrapped by the KEK). Defense in depth: reading
  the DB alone yields double-encrypted bytes; the vault row (passphrase) and
  the KEK are both required to reconstruct a usable UCS.
- **API surface:** metadata only — name, device, timestamps, size, sha256.
  **No download endpoint ships in P4** (named deferral): the only consumer of
  archive bytes is the CR-gated restore path, which minimizes the
  exfiltration surface to zero HTTP endpoints. If an operator-download need is
  proven, a follow-up ADR adds it behind admin RBAC + step-up audit.
- **Redaction rules:** archive bytes never appear in any log line, `repr`
  (`SecretBytes`), exception message, Celery task result, WebSocket event,
  API response, or report artifact (the W3 report redaction contract inherits
  this class). The passphrase never appears anywhere outside the vault row —
  it is materialized in-process at save/restore time only, held name-mangled,
  covered by the §1 redaction filter, and never raw-recorded. Log-safe
  identifiers: archive id, device id, size, sha256.
- **Retention:** archives follow the config-snapshot retention policy
  (ADR-0017), deletion audited. Vault passphrase rows are deleted with their
  archive (a passphrase without its archive is dead weight; an archive
  without its passphrase is unrestorable — the pair is atomic).
- **DR note (named):** restoring an archive requires the platform vault
  (passphrase + KEK). The P1-W5 backup/DR baseline already covers Postgres +
  KMS material; a platform-DR scenario therefore restores archives too. An
  estate that loses the vault loses archive restorability — accepted, because
  the alternative (weaker archive encryption) is strictly worse.

#### 7.4 Restore — strictly via ChangeRequest, baseline-first, never-silent rollback

`restore_archive()` follows the ADR-0021 contract adapted to archives. It
**never self-authorizes**: it refuses (typed `PluginError`) unless the
`ChangePlan` attests an `executing`, four-eyes-approved CR — identical gating
to `ConfigRestoreCapability` (`base.py:545`).

Sequence: **capture a fresh pre-change baseline UCS** (via §7.2 — this is the
rollback artifact) → upload the target archive
(`/mgmt/shared/file-transfer/ucs-uploads/`) → `POST /mgmt/tm/sys/ucs` with
`command=load` + the vault-materialized passphrase → **verify-after**: the
management API returns reachable within the restore window, `sys/version` and
hostname match the archive's recorded metadata, and failover status is not
degraded → on verify failure, **load the baseline UCS** (rollback) and verify
that; `rollback_failed` is surfaced, never reported as `rolled_back`
(ADR-0021 never-silent contract). Byte-equality verify-after is impossible
for archives (UCS saves are not byte-stable), so the verify predicate is the
reachability + identity + HA-health triple — recorded in the `ChangeResult`.

`ChangeResult` for archive operations carries **metadata only** (archive ids,
sha256s, verify outcomes) — never contents, never a diff (there is no
meaningful text diff of a UCS; `applied_diff` semantics are "archive loaded",
with the baseline archive id as the rollback pointer).

**Blast radius (must surface in the CR approval UI):** a UCS load restarts
BIG-IP services (traffic interruption; on an HA pair it can force a failover
and can overwrite device-trust/ConfigSync state). The CR description generated
for an archive restore names this explicitly so the human approver approves
the outage, not just the change. HA-pair restore ordering (standby-first) is
an open question for the live lab (§9).

#### 7.5 Why backup is a read, not a CR

Creating a UCS mutates no device configuration; the on-box temp file +
deletion are recorded in the audit trail via the raw-recorded control-plane
exchanges and the job audit entry. Backup therefore rides the scheduled/manual
read path like every other vendor's `CONFIG_BACKUP`; **restore** is the write
and is CR-gated (§7.4). This matches the platform-wide split (ADR-0017 backup
vs ADR-0021 restore).

#### 7.6 Named deferral — F5 text-config drift/compliance

Because P4 rejects the shell-escape endpoints (§7.1), `f5_bigip` produces no
text snapshot, so the M4 drift-detection and compliance engines have **no F5
surface in P4** — the W3 compliance-posture report will show F5 devices as
out-of-scope, not passing. This is a deliberate, named gap, not an oversight.
The follow-up path (a future ADR, earliest P5): a supported non-shell text
export — SCF generation via `/mgmt/tm/sys/config` if a whitelisted download
path can be validated on a live device, or tmsh-over-SSH as a secondary
transport (F5 supports SSH; D7 keeps netmiko available) — with the PAN-OS
secret-bearing-text posture (ADR-0035 §1) applied to the result.

### 8. Conformance, fixtures, coverage, live golden path

`f5_bigip` ships against the reusable conformance suite
(`backend/tests/plugins/conformance.py`) exactly as the four existing API
plugins do — `test_f5_bigip_conformance.py` parametrizing
`make_conformance_cases(F5BigipPlugin(), …)` over fixture-replay transport,
with the three case families (`metadata:*`, `implementation:<capability>`,
`fixtures:<capability>`) attaching automatically once the §4.7
`_INTERFACE_SPECS` entries exist.

- **Fixtures are recorded raw iControl REST JSON payloads stored verbatim**
  (P4-PLAN §0), sanitized (no real credentials/addresses/keys) and clearly
  labeled with the BIG-IP version they were captured from — the ADR-0024 §5
  "source-derived, clearly labeled" posture. The normalized round-trip runs
  over these real payload shapes, not hand-authored dicts.
- **Mandatory fixture cases beyond the happy path:** a multi-page collection
  (pagination, §1); a route-domain-suffixed address set (§5); an FQDN-node
  pool member (§4.3); a VS with no default pool; an empty pool; a member in
  `forced_offline`; a standalone (non-DSC) `HA_STATUS` response; a UCS
  save/download/delete control-plane JSON sequence (the binary body itself is
  a small synthetic blob — its bytes are opaque to every assertion except
  size/sha256 handling).
- **Secret-leak assertions:** the W1-T1 test set must assert that the login
  password, the auth token, and the UCS passphrase appear in no log record,
  no raw artifact, no exception message, and no `repr` — the existing
  credential-leak test pattern extended to the two new secrets (P4-PLAN §5
  W1 exit criterion: "zero plaintext leakage"). The leak check additionally
  covers the **archive content surface, not just the secret strings**: the
  UCS archive payload bytes (asserted via the synthetic blob's content) must
  appear in no log record, no API response, and no task result — the §7.4
  metadata-only `ChangeResult` contract, negatively controlled.
- **Restore-gating negative control:** a `ChangeRequest`/`ChangePlan` that is
  unapproved or not in `executing` state is REJECTED by the UCS restore path
  with the typed `PluginError` **before any device call** (the fixture-replay
  transport records zero requests) — the §7.4 never-self-authorizes contract,
  asserted in tests.
- **Coverage ≥80%** on the plugin module (D16), enforced in CI; plugin + API
  docs published (CLAUDE.md Development Standards).
- **Live golden path** (discover → ADC inventory → UCS backup → CR-approved
  restore against a real/virtual BIG-IP) is **named deferred-accepted → live
  lab** — the same posture every prior wave recorded
  (P3-RELEASE-READINESS §4 item 6); the script ships ready-to-run in W1.

### 9. Open questions (require a live BIG-IP / lab)

1. **File-transfer chunking behavior** across BIG-IP versions (ranged
   download/upload sizes for large UCS files) — pin the client's chunk logic
   against ≥2 TMOS releases.
2. **UCS load on an HA pair** — standby-first restore ordering, device-trust
   re-establishment, and ConfigSync behavior after load (§7.4 blast-radius
   note); needed before the restore golden path is certified.
3. **`$top`/`$skip` paging metadata stability** across TMOS releases (§1) —
   confirm the pagination termination condition against real large
   collections.
4. **SCF text-export viability** for the §7.6 drift deferral — whether a
   supported, non-shell whitelisted download path exists on current TMOS.
5. **Remote-auth token providers** — confirm `loginProviderName` handling for
   TACACS+/LDAP-backed service accounts (§2) against a lab AAA setup.

## Consequences

**Positive**

- Zero new backend dependencies: the D7-named httpx path reuses the discipline
  four sibling API plugins already prove, keeping the plugin air-gap-friendly
  and the lockfile untouched — W1-T1 is a template-following build plus the
  new capability surface.
- The ADC models carry exactly the fields the W2 application-dependency
  derivation needs (VIP/port/protocol/pool/member address/port/state, plus the
  `fqdn` bridge to DNS dependencies and `vrf` disambiguation), so ADR-0052 can
  bind to a stable contract with no mid-wave model churn.
- The archive-capability pair gives secret-bearing binary backups a typed,
  vendor-neutral home with honest semantics — no base64 smuggling through the
  text contract, no shell-escape endpoints, restore CR-gated with a baseline
  rollback artifact and the ADR-0021 never-silent contract intact.
- Defense-in-depth on the most sensitive artifact yet stored: on-box
  passphrase encryption before transfer + platform envelope encryption at
  rest + vault-held per-backup passphrases + `SecretBytes` + no download
  endpoint + metadata-only surfaces.
- `HA_STATUS` and `NormalizedRoute.vrf` reuse existing surfaces unchanged —
  the ADR-0025 §8 investment pays out exactly as designed.

**Negative**

- **No F5 text-config drift/compliance in P4** (§7.6) — the M4 engines skip F5
  until a supported text export is validated; named-deferred, visible in the
  W3 posture report as out-of-scope.
- The ADC interface is single-vendor-validated (§4.6); a second ADC-shaped
  source may expose LCD misjudgments — mitigated by the derivation-as-second-
  consumer check and the named re-validation rule.
- Per-backup vault passphrases couple archive restorability to the platform
  vault (§7.3 DR note): losing the vault means losing restorability — accepted
  over weaker encryption.
- Nested members (§4.5) mean a very large pool makes a large single record;
  acceptable at ADC scale (pools are hundreds of members, not millions), and
  pagination happens at the HTTP layer, not the model layer.
- Three new enum members + two ABCs + three models is the largest additive
  contract surface since ADR-0034 — the ADR-0006 interface-proliferation risk
  is mitigated by keeping every addition LCD and vendor-neutral.

## Alternatives considered

1. **`f5-common-python` / `bigrest` / `bigsuds` client libraries.** Rejected
   (§1 table): archived or single-maintainer supply-chain surface, a second
   HTTP stack, object wrappers that obscure the raw-first verbatim contract —
   all for convenience the existing httpx discipline already provides. D7
   names httpx for F5 iControl.
2. **HTTP Basic auth on every request instead of token auth.** Rejected (§2):
   resends the long-lived credential on every request (maximum exposure
   window), and does not serve remote-auth (TACACS+/LDAP) service accounts;
   token auth bounds exposure to a revocable 1200 s token and is the
   vendor-recommended path.
3. **A `vendor_attributes` escape hatch on the ADC models.** Rejected —
   identical rationale to ADR-0034 §6: bloats every future source, drifts, and
   leaks non-portable data into engine-visible surfaces; the verbatim raw
   artifact already preserves the richness.
4. **Flat top-level `NormalizedPoolMember` records (a third getter) instead of
   nesting.** Rejected (§4.5): forces a string re-join the derivation would
   have to re-verify, duplicates the provenance triple per member, and
   mismatches the vendor's own pool→member subcollection shape.
5. **Base64-encode the UCS through the existing
   `fetch_running_config() -> str` contract.** Rejected (§7.1): poisons the
   M4 drift diff surface with binary noise, misrepresents semantics, and would
   put megabytes of secret-bearing ciphertext through a code path designed for
   loggable-adjacent text handling.
6. **Use `/mgmt/tm/util/bash` to pull `tmsh show running-config` text.**
   Rejected (§7.1/§7.6): grants the platform's device credential an arbitrary
   remote-shell primitive on the ADC — a standing lateral-movement gift that
   violates least privilege; hardened estates disable it. The text surface is
   named-deferred instead.
7. **Skip UCS; assemble a "config backup" from iControl resource GETs.**
   Rejected: a resource-scrape is lossy (no certs/keys/licensing/base config),
   cannot restore a device, and would masquerade as a backup while being a
   false safety net — worse than an honest named deferral.
8. **Store archives unencrypted (rely on DB access controls) or strip private
   keys (`no-private-key`).** Rejected (§7.2/§7.3): the archive is the
   highest-value secret artifact the platform holds — double encryption with
   vault-held per-backup passphrases is the floor; key-stripped archives
   cannot actually restore a TLS-terminating ADC, defeating the capability's
   purpose.
9. **CR-gate the backup (not just the restore).** Rejected (§7.5): backup
   mutates no configuration; forcing four-eyes approval on every scheduled
   backup would train approvers to rubber-stamp. The write path (restore) is
   where the CR spine bites, matching the platform-wide ADR-0017/0021 split.
