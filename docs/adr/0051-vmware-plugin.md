# ADR-0051: VMware vSphere Vendor Plugin (pyVmomi) — `VIRTUALIZATION_INVENTORY` Capability, Normalized Virtualization Models, Read-Only vCenter Role

**Status:** Proposed | **Date:** 2026-07-05 | **Milestone:** P4 W0

## Context

VMware (`vmware`) is the platform's **first virtualization vendor** and the
second vendor of **Wave 3 (P4)**. `PRODUCTION.md` §2.4 assigns it: "pyVmomi per
D7: vSwitch/dvSwitch, port groups, VM-to-port and VM-to-host mappings — bridges
physical L2 topology to workloads; prerequisite for `Application`/`DEPENDS_ON`
graph data", with the capability set `DISCOVERY_API`, virtual interfaces/port
groups, VM inventory, host/cluster topology. This ADR is the **design gate**;
the build is **W1-T2** (`P4-PLAN.md` §3), which binds field-for-field to the
tables below. No code in this ADR.

The decision is bounded by ADR-0006 (plugin contract: typed capability ABCs
over the enum, normalized models as the only engine-visible currency, raw
payloads recorded first), ADR-0007 §D7 (**pyVmomi is the named VMware
transport** — the plugin contract already anticipates it:
`ConnectionProtocol.API` is documented as "cloud / virtualization SDKs (boto3,
azure SDK, pyVmomi)", `backend/app/plugins/base.py:134`), ADR-0011 §D11
(credential vault `credential_ref`, append-only audit), and ADR-0034/0050 (the
precedent for ratifying a new capability + normalized models as a W0 design
gate).

Four things distinguish this ADR from its Wave-3 sibling (ADR-0050):

1. **A new capability surface with four models.** There is no virtualization
   member in `Capability` today (`base.py:106-124`) and no normalized
   VM/host/cluster/port-group models. This ADR adds the enum member, the typed
   ABC, and the models. VM-to-host/cluster **placement** is the field set that
   bridges physical L2 to workloads and is a direct input to the W2
   application-dependency derivation (ADR-0052) — alongside the F5 VIP→pool→
   member chains, whose member addresses/FQDNs join **onto these VM records**.
2. **The first SDK-transport plugin.** Every existing plugin speaks netmiko
   (CLI text) or httpx (REST/XML bodies); both hand the capability layer
   verbatim wire text for `_record_raw`. pyVmomi is a SOAP SDK whose transport
   deserializes responses into Python objects — the raw-first contract needs a
   named adaptation (§7).
3. **The first new runtime dependency since the lockfile landed** (P3-W0-T8;
   P4-PLAN §0a "new deps go through it"). ADR-0050 added zero dependencies;
   `pyvmomi` is a real supply-chain and air-gap decision (§1).
4. **The platform's first read-only-only vendor plugin.** Every prior vendor
   ships at least one write surface (config restore/deploy, DDI record writes,
   archive restore). `vmware` declares **no write path at all** (§3) — the
   least-privilege story is the vCenter role, not CR gating.

## Decision

**Ship `vmware` as a pyVmomi (SOAP) plugin against vCenter Server — one
inventory `device` row per vCenter, authenticating with vault-referenced
credentials under a least-privilege read-only vCenter role, with short-lived
per-collection sessions. It declares `DISCOVERY_API` plus the NEW
`VIRTUALIZATION_INVENTORY` capability returning `NormalizedVirtualMachine`,
`NormalizedHypervisorHost`, `NormalizedComputeCluster`, and
`NormalizedPortGroup` — final names — with nested `NormalizedVirtualNic` /
`NormalizedPhysicalNic` sub-models carrying the placement and port-group
fields the W2 derivation joins on. Collection uses the PropertyCollector with
explicit continuation-token paging; raw-first is satisfied by recording the
retrieved property-set documents as deterministic JSON (named deviation from
verbatim wire bytes). There is no write path in this plugin — no CR-gated
write exists for `vmware` in P4 — and the required vCenter service account
holds read-only privileges only.**

### 1. Client & dependency — pyVmomi confirmed (D7); lockfile + pin posture

**Decision: pyVmomi (`pyvmomi` on PyPI) is the transport, per D7 —
confirmed.** Candidates evaluated:

| Candidate | Verdict | Why |
|---|---|---|
| **pyVmomi** (SOAP SDK) | **Chosen** | D7 names it; actively maintained by Broadcom/VMware; complete coverage of the inventory surface this plugin needs (PropertyCollector bulk reads, standard *and* distributed vSwitch/port-group config, per-vNIC backing detail); pure-Python wheels on PyPI (lockfile- and air-gap-friendly) |
| vSphere Automation SDK for Python (REST) | **Rejected** | Not distributed on PyPI (GitHub-only install) — breaks the lockfile discipline and offline mirroring outright; its REST surface lacks the depth this plugin needs (standard-vSwitch/port-group config and bulk property collection remain SOAP-first) |
| Raw httpx against the vSphere REST API | **Rejected** | Same coverage gaps as the Automation SDK, minus the SDK; would end in hand-rolled SOAP for the missing surfaces — reinventing pyVmomi badly |
| `govc`/PowerCLI subprocess wrappers | **Rejected** | Shelling out to a non-Python toolchain from Celery workers; no typed surface; a packaging/air-gap burden with none of the SDK's benefits |

**Lockfile + version-pin posture (P4-PLAN §0a — the lockfile bit twice in
P1/P2 before it existed):** `pyvmomi` is added to `backend/pyproject.toml`
with a **floor + major-cap constraint** (the current stable major at W1-T2
land time), and the **exact version is resolved into the dependency lockfile**
in the same commit; the blocking lockfile/drift CI gate covers it from day
one, and pip-audit/Trivy supply-chain scanning applies as to every dependency.
The pin tracks **client-side currency, not the estate's vCenter version**:
pyVmomi maintains backward compatibility with supported vCenter API levels, so
one pinned client serves mixed vCenter 7/8 estates. pyVmomi ships pure-Python
wheels, so an air-gapped index mirrors one artifact with no build toolchain.

Client discipline (adapted from the `PanosClient`/`BamClient`/ADR-0050 §1
house pattern):

- **Vendor-private** — a thin `VsphereClient`
  (`backend/app/plugins/vendors/vmware/client.py`) wraps pyVmomi; engines and
  agents never see pyVmomi types (ADR-0006 §6). The client exposes typed
  `fetch_*` methods that return **property-set documents** (plain
  JSON-serializable dicts, §7) — this seam is what conformance fixtures replay
  (§8).
- **Synchronous by design** — collection runs inside Celery workers, never on
  the FastAPI event loop (ADR-0007 §3).
- **TLS verification on by default** — `ssl.create_default_context()`; a CA
  bundle / verify flag rides device connection config exactly like httpx
  `verify` on the REST plugins. pyVmomi's `disableSslCertValidation` is never
  a default; disabling verification is an explicit per-device connection
  setting, visible in config review.
- **No debug transports** — the client never enables pyVmomi/`http.client`
  debug output (which prints raw headers, including the session cookie,
  outside the logging framework where no redaction filter can catch it).

### 2. Credential flow & session lifecycle (D11 — secret surface)

This section is written to the strong bar (P4-PLAN §0a: plugin credential
flows are on the P4 escalation set). Two secrets exist in this plugin: the
vCenter **password** and the **SOAP session cookie** (`vmware_soap_session`).

1. The device row's `ConnectionParams.credential_ref` names a vault credential
   (ADR-0011); the credentials service materializes the username/password
   **in-process only**. The plugin never persists, returns, or logs a
   plaintext secret — the same contract as every existing plugin. Rotation
   rides the ADR-0040 machinery unchanged.
2. `VsphereClient` authenticates via pyVmomi `SmartConnect` (SOAP
   `SessionManager.Login`). The password crosses process boundaries only
   inside that TLS-protected login call; the login exchange is **never**
   raw-recorded and never logged.
3. **Session lifecycle — short-lived, per collection run.** The client
   connects lazily on first use; the owning job context disconnects in a
   `finally` block (`Disconnect` → SOAP `Logout`, terminating the session
   server-side). Sessions never outlive the Celery task, are never cached
   across tasks or workers, and the cookie is never persisted anywhere. If
   vCenter expires the session mid-run (`vim.fault.NotAuthenticated` — default
   idle timeout is 30 minutes), the client re-authenticates **once** and
   retries, mirroring the F5 401-retry-once posture (ADR-0050 §2); a second
   failure is a typed `PluginError`.
4. **Zero plaintext leakage.** Both the password and the live session cookie
   are held in name-mangled attributes with no custom `repr`/`str`
   (ADR-0011 §1); a per-instance logging filter on the plugin's logger drops
   any record containing either secret in literal or percent-encoded form
   (the `_ApiKeyRedactFilter` pattern). Typed error mapping guarantees
   exception messages carry host/port and fault type only —
   `vim.fault.InvalidLogin` is re-raised as a credential-free `PluginError`.
   Neither secret may appear in a normalized record, a raw artifact, an
   exception message, an API response, or any log line — the W1-T2 escalated
   quality review verifies this, and the test set asserts it (§8).

### 3. Read-only vCenter role — least privilege; no write path (stated)

**Decision: the platform requires a dedicated vCenter service account holding
read-only privileges only.** The documented least-privilege role the platform
requires:

- A **dedicated service account** (local SSO or directory-backed) used by the
  platform alone — never `administrator@vsphere.local`, never a shared human
  account.
- Granted the built-in **Read-Only** role — or an equivalent custom role
  containing exactly the `System.Anonymous`, `System.Read`, `System.View`
  privileges — on the **root vCenter Server object with "Propagate to
  children"**. That is the entire privilege surface: every read this plugin
  performs (inventory traversal, config/runtime/guest property reads via the
  PropertyCollector) works under it.
- The account holds **no** modify privileges of any kind — no
  `VirtualMachine.*`, `Host.*`, `Network.*`, `Datastore.*` mutation, no guest
  operations, no console access, no datastore browse. Compromise of the
  platform credential yields visibility into the virtualization estate, never
  control of it.

**No write path exists in this plugin — stated explicitly.** `vmware` declares
no `CONFIG_BACKUP`/`CONFIG_RESTORE`/`CONFIG_DEPLOY`, no DDI writes, no archive
capabilities: **no CR-gated write exists for `vmware` in P4.** Host-config or
vCenter-profile backup is a **named deferral**, not an oversight — the W3
compliance-posture report shows VMware as out-of-scope for config drift, the
same honest posture as ADR-0050 §7.6 for F5 text config. Any future write
surface (VM tagging, snapshots, power operations) requires a new ADR and the
full ADR-0020/0021 CR gating; nothing here pre-authorizes it.

### 4. Capability map — vCenter is the device; what is and is not declared

The inventory `device` row is **the vCenter Server** (`ConnectionParams` →
vCenter host, `protocol=API`), matching the DDI-grid pattern (`infoblox`/
`bluecat`: one API endpoint manages many downstream objects). ESXi hosts, VMs,
clusters, and port groups are **discovered objects carried in normalized
records** whose provenance triple points at the vCenter device.

| Capability | vSphere source (via PropertyCollector unless noted) | Normalized return |
|---|---|---|
| `DISCOVERY_API` | `ServiceInstance.content.about` | one `NormalizedDiscoveredObject` (`kind=OTHER`) — vCenter identity/facts (product, version, build, instance UUID), mirroring `panos` (`plugin.py:199`) and ADR-0050 §3 |
| `VIRTUALIZATION_INVENTORY` **(new)** | `VirtualMachine`, `HostSystem`, `ClusterComputeResource`, `Network`/`DistributedVirtualPortgroup` + host `config.network` property sets | `list[NormalizedVirtualMachine]` / `list[NormalizedHypervisorHost]` / `list[NormalizedComputeCluster]` / `list[NormalizedPortGroup]` (§5) |

The `PRODUCTION.md` §2.4 phrase "virtual interfaces/port groups" is delivered
**inside the virtualization models**: port groups are first-class records; VM
virtual NICs and host physical NICs are nested sub-models (§5.3). The plugin
deliberately does **not** declare `INTERFACES`: that capability's semantics
are "the interfaces of *this device*", and the device row here is the vCenter
— emitting thousands of per-host/per-VM interfaces as if they belonged to the
vCenter would corrupt device-scoped interface semantics for every consumer
(rejected in Alternatives #4). `HA_STATUS` is likewise not declared — vSphere
cluster HA is a cluster property (`ha_enabled`, §5.3), not a device-pair
failover status in the `NormalizedHaStatus` sense; the §2.4 row does not
assign it.

### 5. NEW `VIRTUALIZATION_INVENTORY` capability + normalized models

#### 5.1 Enum + typed interface (ratified signature — implemented in W1-T2)

This ADR adds one enum member — `Capability.VIRTUALIZATION_INVENTORY =
"virtualization_inventory"` (`backend/app/plugins/base.py`) — and one typed
ABC. Adding one member + one ABC is additive with zero edits to existing
plugins (ADR-0006 §6; ADR-0025 §8 and ADR-0050 §4.1 precedents).

```python
# backend/app/plugins/base.py — mirrors AdcServicesCapability (ADR-0050 §4.1)
class VirtualizationInventoryCapability(PluginCapability):
    """``Capability.VIRTUALIZATION_INVENTORY`` — VM/host/cluster/port-group inventory."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.VIRTUALIZATION_INVENTORY}
    )

    @abstractmethod
    def get_virtual_machines(self) -> list[NormalizedVirtualMachine]:
        """Return virtual machines (with placement + vNICs) as normalized records."""

    @abstractmethod
    def get_hypervisor_hosts(self) -> list[NormalizedHypervisorHost]:
        """Return hypervisor hosts (with cluster membership + pNICs) as normalized records."""

    @abstractmethod
    def get_compute_clusters(self) -> list[NormalizedComputeCluster]:
        """Return compute clusters as normalized records."""

    @abstractmethod
    def get_port_groups(self) -> list[NormalizedPortGroup]:
        """Return standard and distributed port groups as normalized records."""
```

All four methods return normalized models, never dicts/raw (ADR-0006 §3).

#### 5.2 Final model names

**`NormalizedVirtualMachine`, `NormalizedHypervisorHost`,
`NormalizedComputeCluster`, and `NormalizedPortGroup` are the final names.**
The `P4-PLAN.md` §3 W0-T2 PROPOSED shorthand (`NormalizedVM` / host / cluster
/ port-group) is adopted with two deliberate renames: `NormalizedVM` is
spelled out as `NormalizedVirtualMachine` (house style avoids multi-capital
acronym runs — cf. `NormalizedBgpPeer`, `NormalizedHaStatus` — and mirrors the
sibling `NormalizedVirtualServer`), and the host/cluster models take
vendor-neutral names (`Hypervisor`/`Compute`, not `Esxi`/`Vsphere`) so a
future virtualization source reuses them without a rename.

All four subclass `NormalizedRecord` (`normalized.py:280` — provenance triple
`device_id` / `collected_at` / `source_vendor`, where `device_id` is the
**vCenter** device; `frozen=True`, `extra="forbid"`). `NormalizedVirtualNic`
and `NormalizedPhysicalNic` are **nested frozen sub-models** (plain
`BaseModel`, `frozen=True`, `extra="forbid"`), not `NormalizedRecord`s — NICs
inherit their parent record's provenance and are intrinsically hierarchical,
the `NormalizedPoolMember` precedent (ADR-0050 §4.2/§4.5).

#### 5.3 Field tables (W1-T2 binds field-for-field)

**`NormalizedVirtualMachine`**

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | VM display name — **not unique** per vCenter; identity is `moref` |
| `moref` | `str` (min_length=1) | vCenter managed-object id (e.g. `vm-1042`) — unique per vCenter; the derivation's VM node key is `(device_id, moref)` |
| `instance_uuid` | `str \| None` | vCenter `instanceUuid` — survives vMotion; cross-collection identity |
| `is_template` | `bool` | Templates are collected, not dropped; derivation excludes them (never traffic endpoints) |
| `power_state` | `VmPowerState` | `powered_on` / `powered_off` / `suspended` / `unknown` (new StrEnum, §5.4) |
| `guest_hostname` | `str \| None` | VMware-Tools-reported hostname — joins the M5 DNS-dependency layer |
| `guest_ip_addresses` | `tuple[IPv4Address \| IPv6Address, ...]` | Union of Tools-reported IPs (incl. the primary), deduplicated and sorted for determinism; `()` when Tools absent — **the F5 bridge**: ADR-0050 pool-member `address`/`fqdn` joins onto these |
| `host_name` | `str \| None` | **Placement**: name of the host the VM runs on — joins `NormalizedHypervisorHost.name`; `None` only for unplaced (e.g. orphaned) VMs |
| `cluster_name` | `str \| None` | **Placement**: cluster of that host; `None` for standalone hosts. Deliberately denormalized onto the VM (also derivable via host→cluster) so derivation survives a partial collection |
| `datacenter` | `str \| None` | Disambiguation scope for name joins (§5.5) |
| `nics` | `tuple[NormalizedVirtualNic, ...]` | Nested vNICs; `()` = none |
| `description` | `str \| None` | vSphere annotation, free text |

**`NormalizedVirtualNic`** (nested sub-model)

| Field | Type | Notes |
|---|---|---|
| `label` | `str` (min_length=1) | Device label (e.g. `Network adapter 1`) |
| `mac_address` | `MacAddress` | House canonical MAC (`normalized.py:91`) — the **physical-L2 join key** (switch MAC/forwarding tables) |
| `port_group_name` | `str \| None` | Join to `NormalizedPortGroup.name`; distributed-portgroup **keys are resolved to names at collection time** (the plugin holds all port groups in the same pass) so consumers join on one field; `None` when the backing is unresolvable |
| `switch_type` | `VirtualSwitchType \| None` | Disambiguates the join: `standard` → scope by the VM's host; `distributed` → vCenter-wide (§5.5) |
| `connected` | `bool` | vNIC link state |
| `ip_addresses` | `tuple[IPv4Address \| IPv6Address, ...]` | Per-NIC Tools-reported IPs; `()` when unreported |

**`NormalizedHypervisorHost`**

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Host name as inventoried (typically FQDN) — join target of `NormalizedVirtualMachine.host_name`; also the LLDP/CDP system-name bridge to physical-switch neighbor tables |
| `moref` | `str` (min_length=1) | e.g. `host-123` |
| `cluster_name` | `str \| None` | `None` = standalone host |
| `datacenter` | `str \| None` | |
| `vendor` / `model` | `str \| None` | Hardware identity |
| `hypervisor_version` | `str \| None` | e.g. `VMware ESXi 8.0.2 build-…` |
| `connection_state` | `HostConnectionState` | `connected` / `disconnected` / `not_responding` / `unknown` (new StrEnum, §5.4) |
| `in_maintenance_mode` | `bool` | Impact analysis needs it (drained host ≠ failed host) |
| `management_ip` | `IPv4Address \| IPv6Address \| None` | Management vmkernel address |
| `pnics` | `tuple[NormalizedPhysicalNic, ...]` | Nested physical adapters |

**`NormalizedPhysicalNic`** (nested sub-model)

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | e.g. `vmnic0` — join target of `NormalizedPortGroup.uplink_pnic_names` |
| `mac_address` | `MacAddress` | Physical-L2 join key (the MAC physical switches see) |
| `link_speed_mbps` | `int \| None` (ge=0) | `None` = link down or unreported |

**`NormalizedComputeCluster`**

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Join target of `cluster_name` fields |
| `moref` | `str` (min_length=1) | e.g. `domain-c8` |
| `datacenter` | `str \| None` | Cluster names are unique per datacenter, not per vCenter (§5.5) |
| `drs_enabled` | `bool \| None` | Placement volatility signal — DRS moves VMs between hosts |
| `ha_enabled` | `bool \| None` | Impact analysis: HA cluster ⇒ VM restarts elsewhere on host failure |

**`NormalizedPortGroup`**

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Join target of `NormalizedVirtualNic.port_group_name` |
| `switch_name` | `str` (min_length=1) | Parent vSwitch / distributed vSwitch name |
| `switch_type` | `VirtualSwitchType` | `standard` / `distributed` (new StrEnum, §5.4) |
| `datacenter` | `str \| None` | |
| `host_name` | `str \| None` | **Scope**: standard port groups exist per host (same name may repeat across hosts, §5.5); `None` for distributed |
| `vlan_id` | `int \| None` (ge=0, le=4094) | Access VLAN — joins topology `Vlan` nodes; `None` for trunk/private-VLAN port groups (richness rides the raw artifact — named LCD limit) |
| `moref` | `str \| None` | Distributed portgroup key (e.g. `dvportgroup-123`); `None` for standard port groups (they have no moref) |
| `uplink_pnic_names` | `tuple[str, ...]` | Effective uplink pNICs (per-portgroup teaming override respected, else the parent switch's uplinks) — completes the vNIC → port group → pNIC → physical-switchport chain; `()` = none reported |

Deliberately **excluded** (LCD discipline, ADR-0034 §6): resource
allocations (CPU/memory shares, reservations), datastore/storage topology,
snapshots, vApp/folder hierarchy, DRS rules, vmkernel adapters beyond
`management_ip`, NIC teaming policy detail — vendor richness rides the
verbatim raw artifact only (**no `vendor_attributes` escape hatch**, same
decision and rationale as ADR-0034 §6 / ADR-0050 §4.3). All fields are
inventory/state metadata; **no field can carry a secret** (guest credentials,
host root credentials, and certificate material are never collected).

#### 5.4 New enums (in `normalized.py`, alongside `AclAction`/`AdcProtocol`)

- `VmPowerState(StrEnum)`: `POWERED_ON = "powered_on"`, `POWERED_OFF =
  "powered_off"`, `SUSPENDED = "suspended"`, `UNKNOWN = "unknown"`. vSphere's
  three runtime power states map 1:1; `UNKNOWN` is the safe default for
  unreachable/inconsistent state (the `DiscoveredObjectKind.OTHER` pattern).
- `HostConnectionState(StrEnum)`: `CONNECTED = "connected"`, `DISCONNECTED =
  "disconnected"`, `NOT_RESPONDING = "not_responding"`, `UNKNOWN = "unknown"`.
- `VirtualSwitchType(StrEnum)`: `STANDARD = "standard"`, `DISTRIBUTED =
  "distributed"`.

`power_state` and `is_template` are separate dimensions on purpose (a template
is always powered off, but a powered-off VM is usually not a template);
`connection_state` and `in_maintenance_mode` likewise — the derivation
(ADR-0052) needs each distinction to decide whether an edge represents a live
workload path (the ADR-0050 §4.4 availability/admin-state rationale).

#### 5.5 Join keys — the derivation contract (what W2 consumes)

The W2 derivation (ADR-0052) and physical-L2 bridging join on exactly these
fields — this is the placement/port-group contract this ADR exists to pin:

| Edge derived | Join |
|---|---|
| VM → host (placement) | `NormalizedVirtualMachine.host_name` (scoped by `datacenter`) → `NormalizedHypervisorHost.name` |
| VM / host → cluster (placement) | `cluster_name` (scoped by `datacenter`) → `NormalizedComputeCluster.name` |
| VM → DNS / application layer | `guest_hostname`, `guest_ip_addresses` ↔ M5 DNS-dependency records; ADR-0050 `NormalizedPoolMember.address`/`fqdn` ↔ `guest_ip_addresses`/`guest_hostname` (the F5 VIP→pool→member→**VM** chain) |
| vNIC → port group | `NormalizedVirtualNic.port_group_name` + `switch_type`: `standard` scopes to the VM's `host_name`; `distributed` is vCenter-wide (dv keys pre-resolved to names, §5.3) |
| Port group → VLAN / physical L2 | `vlan_id` ↔ topology `Vlan` nodes; `uplink_pnic_names` → host `pnics[].mac_address` ↔ physical-switch MAC/LLDP/CDP tables; `NormalizedHypervisorHost.name` ↔ LLDP/CDP neighbor system names |

Identity keys for graph nodes: VMs key on `(device_id, moref)` (names
collide across folders); hosts and clusters key on `(device_id, moref)` with
`name` as the human join field; distributed port groups key on
`(device_id, moref)`, standard port groups on
`(device_id, datacenter, host_name, name)`. Name-based joins are scoped by
`datacenter` because vSphere names are only unique within one (clusters,
standard port groups per host).

#### 5.6 NICs nest; the four collections are flat — decided

vNICs/pNICs nest inside their parent (single-traversal chains, no provenance
duplication — ADR-0050 §4.5 rationale). VMs, hosts, clusters, and port groups
are **flat top-level collections** joined by the §5.5 keys rather than one
deep vCenter→datacenter→cluster→host→VM tree: the consumers are different
(derivation walks VM→host→cluster; the inventory UI lists each collection;
L2 bridging reads port groups alone), and a monolithic tree record would
force every consumer to traverse everything (rejected in Alternatives #6).

#### 5.7 Single-vendor validation — same named deviation as ADR-0050 §4.6

VMware is the only virtualization vendor in the CLAUDE.md set, so the
two-vendor rule (`PRODUCTION.md` §2.3 precedent) is unsatisfiable, exactly as
for ADC. **Decision: the virtualization interface is validated by (a) the
conformance fixtures (round-trip over recorded property sets, §8) and (b) the
W2 derivation engine consuming the §5.5 contract as the second, independent
consumer.** The interface is declared **provisionally stable**; a future
virtualization-shaped source (Hyper-V, KVM/Proxmox, cloud hypervisor
inventories in Wave 4) must re-run the ADR-0034-style realizability
cross-check against these models before extending them. Named, not silent.

#### 5.8 Conformance-suite wiring — the three-file lesson (ADR-0025 §8)

The capability is enforceable only when **all three** land together in W1-T2:
(1) the `VirtualizationInventoryCapability` ABC + `Capability.
VIRTUALIZATION_INVENTORY` member in `base.py`; (2) the four models, two nested
sub-models, and three enums in `normalized.py`; (3) an `_INTERFACE_SPECS`
entry in `backend/tests/plugins/conformance.py` mapping
`VIRTUALIZATION_INVENTORY` → (`VirtualizationInventoryCapability`, all four
method names, all four record models). Without (3) the
`fixtures:virtualization_inventory` case is **silently skipped** — the exact
failure mode ADR-0025 §8 documented and ADR-0050 §4.7 re-applied.

### 6. Collection — PropertyCollector with explicit continuation paging

Inventory is collected with the vSphere **PropertyCollector** over
container views: one `RetrievePropertiesEx` call per managed-object type
(`VirtualMachine`, `HostSystem`, `ClusterComputeResource`, network entities +
host `config.network`), each requesting the **named property paths** the §5.3
tables need and nothing more — no `RetrieveEntireContents`-style full-object
pulls (bandwidth, vCenter load, and it drags unneeded data into raw
artifacts).

`RetrievePropertiesEx` returns at most a server-chosen batch and a
**continuation `token`**; the client MUST loop `ContinueRetrievePropertiesEx`
until the token is exhausted, recording every batch (§7). Pagination is the
named sibling-shared bug class (P4-PLAN §0a; ADR-0050 §1 pays the same
attention to `$top`/`$skip`) — a multi-batch fixture is mandatory (§8).
Missing/unset optional properties (e.g. no VMware Tools ⇒ no guest IPs) are
normal device state, normalized to `None`/`()` — the ADR-0025 §4
empty-not-error philosophy — never a `PluginError`.

### 7. Raw-first adaptation — property-set JSON, a named deviation

ADR-0006 §3 requires the raw payload be recorded verbatim before parsing.
For netmiko/httpx plugins "verbatim" means wire text; pyVmomi's transport
deserializes SOAP envelopes into Python objects before the plugin ever sees
them, and intercepting the XML would mean monkeypatching pyVmomi transport
internals — fragile across releases (rejected in Alternatives #7).

**Decision: the raw artifact for `vmware` is a deterministic JSON rendering
of each retrieved property-set batch** — object type, moref, and the exact
property paths + values as returned, serialized with sorted keys — recorded
via `PluginCapability._record_raw` per `RetrievePropertiesEx` batch **before**
normalization. This preserves what raw-first exists for: an audit-grade,
pre-normalization record of **what vCenter reported**, re-parseable if
normalization bugs are found. The deviation (post-deserialization content
rather than wire bytes) is **named here and in the plugin docs**, not silent.
The login exchange and session cookie are never part of any recorded batch
(§2). Conformance fixtures replay these same JSON documents through the
`VsphereClient` seam (§1), so fixtures and raw artifacts share one format.

### 8. Conformance, fixtures, coverage, live golden path

`vmware` ships against the reusable conformance suite
(`backend/tests/plugins/conformance.py`) — `test_vmware_conformance.py`
parametrizing `make_conformance_cases(VmwarePlugin(), …)` over fixture replay,
with the three case families attaching once the §5.8 `_INTERFACE_SPECS` entry
exists.

- **Fixtures are recorded property-set JSON documents** (§7) stored verbatim,
  sanitized (no real hostnames/addresses/UUIDs) and labeled with the
  vCenter/ESXi version they were captured from — the ADR-0024 §5
  "source-derived, clearly labeled" posture. The normalized round-trip runs
  over real payload shapes, not hand-authored dicts (P4-PLAN §0).
- **Mandatory fixture cases beyond the happy path:** a multi-batch
  continuation-token collection (§6); a Tools-less VM (`guest_hostname=None`,
  `guest_ip_addresses=()`); a template VM; a powered-off VM; two VMs with the
  same `name` in different folders (moref disambiguation); a standalone host
  (no cluster); a host in maintenance mode; a standard and a distributed port
  group; a trunked distributed port group (`vlan_id=None`, richness in raw); a
  disconnected vNIC; a dv-portgroup key→name resolution case; a per-portgroup
  teaming override (uplink resolution).
- **Secret-leak assertions:** the W1-T2 test set must assert that the vCenter
  password and the session cookie appear in no log record, no raw artifact,
  no exception message, and no `repr` — the existing credential-leak pattern
  extended to the session cookie (P4-PLAN §5 W1: "zero plaintext leakage").
- **Coverage ≥80%** on the plugin module (D16), enforced in CI; plugin + API
  docs published (CLAUDE.md Development Standards). The lockfile/drift gate
  must be green with `pyvmomi` resolved (§1).
- **Live golden path** (discover vCenter → VM/host/cluster/port-group
  inventory → W2 derivation smoke) is **named deferred-accepted → live lab**,
  the same posture every prior wave recorded (P3-RELEASE-READINESS §4 item 6);
  the script ships ready-to-run in W1. The **`vcsim` simulator** (from the
  govmomi project; speaks the vSphere SOAP API pyVmomi targets) is the
  documented preferred substitute — the ADR-0025 §9 `n9000v` pattern — with
  its fixture fidelity listed as an open question (§9).

### 9. Open questions (require a live vCenter / lab)

1. **Guest-info fidelity** — how stale `guest_hostname`/`guest_ip_addresses`
   are across VMware Tools / open-vm-tools versions, and how often IPs are
   reported without NIC attribution (affects vNIC vs VM-level IP placement).
2. **PropertyCollector batching behavior** across vCenter 7/8 releases —
   server-chosen batch sizes and token semantics at 10k+-VM scale; pin the
   client's paging loop against ≥2 releases.
3. **Teaming-override resolution** (§5.3 `uplink_pnic_names`) — confirm the
   per-portgroup override vs switch-default precedence across standard and
   distributed switches on real configs.
4. **Session idle-timeout interplay** with very long collection runs on large
   estates — whether re-auth-once (§2) suffices or a keep-alive read is
   needed.
5. **`vcsim` fidelity** — which mandatory fixture cases (§8) can be captured
   from `vcsim` versus which require a real VCSA capture.
6. **Standard-portgroup name collisions** — same port-group name with
   *different* VLAN ids across hosts: confirm the
   `(datacenter, host_name, name)` key holds and the derivation's
   host-scoped join never crosses hosts.

## Consequences

**Positive**

- The placement + port-group contract (§5.5) gives the W2 derivation
  (ADR-0052) exactly the fields it joins on — VM→host/cluster placement, guest
  hostname/IPs bridging to DNS and to F5 pool members, and the vNIC→port
  group→pNIC chain bridging workloads to physical L2 — with no mid-wave model
  churn, mirroring what ADR-0050 does for the VIP→pool→member side.
- Least privilege by construction: a read-only vCenter role plus a plugin with
  **no write path at all** means the platform credential can never mutate the
  virtualization estate; there is no CR surface to get wrong.
- pyVmomi per D7 with a lockfile-resolved exact pin keeps the first new
  vendor-SDK dependency governed from day one (drift gate, supply-chain
  scanning, pure-Python wheel mirrorable into air-gapped indexes).
- The property-set-JSON raw/fixture format (§7) makes fixtures and raw
  artifacts one format, so conformance replays are exactly what production
  records — no translation layer to drift.
- Vendor-neutral model names and enums leave room for a second virtualization
  source without renames; the provisional-stability rule (§5.7) names the
  re-validation duty instead of hiding it.

**Negative**

- **First new runtime dependency since the lockfile landed** — `pyvmomi`
  widens the supply-chain surface and adds one artifact to air-gap mirrors;
  accepted as governed cost (lockfile + drift gate + pip-audit/Trivy).
- **Raw artifacts are post-deserialization JSON, not wire bytes** (§7) — the
  audit record is what pyVmomi decoded, not the SOAP envelope; a pyVmomi
  deserialization bug is invisible to re-parsing. Named deviation, accepted
  over monkeypatching the SDK transport.
- Single-vendor validation (§5.7): LCD misjudgments may only surface when a
  second virtualization source lands — mitigated by the
  derivation-as-second-consumer check and the named re-validation rule.
- Guest-derived fields depend on VMware Tools presence; Tools-less VMs join
  the application layer only via MAC/port-group paths — consumers must
  tolerate `()` (empty-not-error), and derivation precision on such VMs is
  structurally lower.
- Trunk/private-VLAN port groups carry `vlan_id=None` (§5.3) — VLAN-based L2
  joins skip them; the richness is raw-only until a named enrichment.
- No VMware config backup/drift surface in P4 (§3) — the M4 engines and the
  W3 posture report show VMware as out-of-scope; named deferral.

## Alternatives considered

1. **vSphere Automation SDK for Python (REST) instead of pyVmomi.** Rejected
   (§1): not on PyPI (GitHub-only install) — incompatible with the lockfile
   discipline and air-gapped mirrors; its REST surface lacks the
   standard-vSwitch/port-group and bulk-PropertyCollector depth this plugin
   is assigned; D7 names pyVmomi.
2. **Raw httpx against the vSphere REST API.** Rejected (§1): same coverage
   gaps, and closing them means hand-rolling SOAP — reimplementing pyVmomi.
3. **Model each ESXi host as its own inventory `device`** (the ADR-0025 §6
   VDC-per-device analogy). Rejected: unlike VDCs, hosts are not independent
   management endpoints in a vCenter estate — collection would multiply
   credentials by N hosts, bypass the central RBAC/session audit point, and
   still miss vCenter-only constructs (clusters, distributed switches,
   placement). The vCenter-as-device pattern matches the DDI grids
   (`infoblox`/`bluecat`). Direct-to-ESXi collection for unmanaged hosts is a
   possible future enrichment, named here.
4. **Declare `INTERFACES` for host/VM interfaces.** Rejected (§4): the device
   row is the vCenter; per-host/per-VM interfaces emitted as the vCenter's own
   would corrupt device-scoped interface semantics for every existing
   consumer. Interfaces ride the virtualization models where their parentage
   is explicit.
5. **A `vendor_attributes` escape hatch on the models.** Rejected — identical
   rationale to ADR-0034 §6 / ADR-0050 alt 3: bloat, drift, and non-portable
   data leaking into engine-visible surfaces; the raw artifact preserves the
   richness.
6. **One deep tree record (vCenter→cluster→host→VM) instead of four flat
   collections.** Rejected (§5.6): forces every consumer to traverse the whole
   estate for any read, makes partial collection all-or-nothing, and produces
   one giant record per vCenter; flat collections + typed join keys match how
   the derivation and the inventory UI actually consume the data.
7. **Intercept and record verbatim SOAP XML for raw-first.** Rejected (§7):
   requires monkeypatching pyVmomi transport internals that are not a stable
   public surface — a fragility tax on every pyVmomi upgrade, for wire bytes
   whose audit value over the property-set JSON is marginal. The deviation is
   named instead.
8. **Cache vCenter sessions across Celery tasks.** Rejected (§2): a live
   session cookie held beyond the task is a standing secret with no owner;
   per-run connect/disconnect bounds exposure to the task lifetime and keeps
   session count predictable against vCenter session limits.
9. **Ship a write surface now (VM tags, snapshots) behind CR gating.**
   Rejected (§3): no P4 requirement consumes it (`PRODUCTION.md` §2.4 assigns
   inventory only), and every write capability widens the required vCenter
   role beyond read-only — the least-privilege posture is worth more than a
   speculative capability. A future ADR adds writes with full ADR-0020/0021
   gating if a requirement lands.
