# VMware vSphere plugin (`vmware`)

The platform's first **virtualization** vendor plugin: a vendor-private
[pyVmomi](https://github.com/vmware/pyvmomi) (SOAP) client against **vCenter
Server** that discovers the vCenter identity and the virtualization inventory —
VMs, hypervisor hosts, compute clusters, and standard/distributed port groups,
with the placement and vNIC → port group → pNIC join keys the W2
application-dependency derivation consumes. Design gate: **ADR-0051**. Build:
**P4 W1-T2**. **No write path** (ADR-0051 §3).

## Capabilities

The inventory `device` row is the **vCenter Server** (one API endpoint managing
many downstream objects — the DDI-grid pattern of `infoblox`/`bluecat`). ESXi
hosts, VMs, clusters, and port groups are discovered objects carried in
normalized records whose provenance points at the vCenter device (ADR-0051 §4).

| Capability | vSphere source (via PropertyCollector unless noted) | Normalized return |
|---|---|---|
| `DISCOVERY_API` | `ServiceInstance.content.about` | one `NormalizedDiscoveredObject` (`kind=OTHER`) / `DeviceFacts` — vCenter identity (product, version, build, instance UUID) |
| `VIRTUALIZATION_INVENTORY` **(new)** | `VirtualMachine`, `HostSystem`, `ClusterComputeResource`, `DistributedVirtualSwitch`/`DistributedVirtualPortgroup` + host `config.network` | `list[NormalizedVirtualMachine]` / `list[NormalizedHypervisorHost]` / `list[NormalizedComputeCluster]` / `list[NormalizedPortGroup]` (with nested `NormalizedVirtualNic` / `NormalizedPhysicalNic`) |

The plugin deliberately does **not** declare `INTERFACES` (the device row is the
vCenter; per-host/per-VM interfaces ride the virtualization models where their
parentage is explicit) or `HA_STATUS` (vSphere cluster HA is a cluster property,
`ha_enabled`, not a device-pair failover status) — ADR-0051 §4.

## Connection, credentials & session lifecycle (secret surface)

The device's vault `credential_ref` materializes a username/password in-process;
`VsphereClient` authenticates via pyVmomi `SmartConnect` (SOAP
`SessionManager.Login`). Two secrets exist: the vCenter **password** and the
SOAP **session cookie** (`vmware_soap_session`).

- **Short-lived, per-collection sessions** (ADR-0051 §2): the client connects
  lazily on first use; the owning job context calls `disconnect()` (SOAP
  `Logout`) in a `finally` block. Sessions never outlive the task and are never
  cached across tasks/workers; the cookie is never persisted.
- **Re-auth once** on a mid-run `vim.fault.NotAuthenticated` (idle-timeout
  expiry), then retry; a second failure is a typed `PluginError`.
- **TLS verification on by default** (`ssl.create_default_context()`); a
  CA-bundle path is honored. Disabling verification is an explicit per-device
  connection setting, visible in config review — never a default.
- **Zero plaintext leakage:** the password and live cookie are held in
  name-mangled slots with no leaking `repr`; a redaction filter on the pyVmomi /
  `http.client` loggers drops any record containing either secret in literal or
  percent-encoded form. Typed error mapping strips credentials —
  `vim.fault.InvalidLogin` becomes a credential-free `PluginError` carrying
  host/port only. The login exchange is never raw-recorded and never logged, and
  the client never enables pyVmomi / `http.client` debug transports (which would
  print the cookie outside the logging framework).

### Least-privilege vCenter role (ADR-0051 §3)

The platform requires a **dedicated service account** holding the built-in
**Read-Only** role on the root vCenter object with "Propagate to children" — no
modify privileges of any kind. Compromise of the platform credential yields
visibility into the virtualization estate, never control of it. There is **no
write path in this plugin** — no VM tagging, snapshots, or power operations. Any
future write surface requires a new ADR and the full ADR-0020/0021 CR gating.
Host-config / vCenter-profile backup is a **named deferral** (ADR-0051 §3).

## Raw-first: property-set JSON — a named deviation (ADR-0051 §7)

ADR-0006 §3 requires the raw payload be recorded verbatim before parsing. For
netmiko/httpx plugins "verbatim" means wire text; pyVmomi is a SOAP SDK whose
transport **deserializes** SOAP envelopes into Python objects before the plugin
ever sees them, and intercepting the XML would mean monkeypatching pyVmomi
transport internals (fragile across releases).

**The raw artifact for `vmware` is therefore a deterministic JSON rendering of
each retrieved property-set batch** — object type, moref, and the exact property
paths + values as returned, serialized with sorted keys — recorded via
`_record_raw` per `RetrievePropertiesEx` batch **before** normalization. This is
a **named deviation** from verbatim wire bytes (post-deserialization content
rather than the SOAP envelope): a pyVmomi deserialization bug is invisible to
re-parsing, accepted over monkeypatching the SDK. Each document additionally
carries the `datacenter` its container view was rooted at — a collection-context
attribute that scopes the name joins (§5.5), alongside the pyVmomi property
paths. The login exchange and session cookie are never part of any recorded
batch. Conformance fixtures replay these same JSON documents through the
`VsphereClient.fetch_*` seam, so fixtures and raw artifacts share one format.

## Collection — PropertyCollector with continuation paging (ADR-0051 §6)

Inventory is collected with the vSphere **PropertyCollector** over container
views (one per managed-object type), requesting only the named property paths
the normalized models need — never a full-object pull. `RetrievePropertiesEx`
returns at most a server-chosen batch plus a continuation **token**; the client
loops `ContinueRetrievePropertiesEx` until the token is exhausted, recording
every batch. Missing/unset optional properties (no VMware Tools ⇒ no guest IPs)
are normal device state, normalized to `None`/`()` — empty-not-error, never a
`PluginError`.

## Join keys — the W2 derivation contract (ADR-0051 §5.5)

- **VM → host / cluster (placement):** `NormalizedVirtualMachine.host_name` /
  `cluster_name` (scoped by `datacenter`) join `NormalizedHypervisorHost.name` /
  `NormalizedComputeCluster.name`. Identity keys are morefs (`(device_id,
  moref)`) — names collide across folders.
- **VM → DNS / F5:** `guest_hostname` / `guest_ip_addresses` bridge the DNS
  layer and join F5 `NormalizedPoolMember.address`/`fqdn` (the VIP → pool →
  member → **VM** chain).
- **vNIC → port group:** `port_group_name` + `switch_type` — a `standard` name
  scopes to the VM's host, a `distributed` name is vCenter-wide (dv keys are
  pre-resolved to names at collection time so consumers join on one field).
- **Port group → VLAN / physical L2:** `vlan_id` joins topology VLANs;
  `uplink_pnic_names` join host `pnics[].mac_address` ↔ physical-switch
  MAC/LLDP/CDP tables.

Trunk / private-VLAN port groups carry `vlan_id=None` (the richness rides the
raw artifact — a named LCD limit). There is **no `vendor_attributes` escape
hatch**; vendor-unique richness lives only in the verbatim raw artifact.

## Dependency & lockfile

`pyvmomi` is added to `backend/pyproject.toml` with a floor + major cap
(`>=8.0,<9`) and the exact version is resolved into `requirements.lock.txt` in
the same commit, so the blocking drift gate + pip-audit/Trivy supply-chain
scanning cover it from day one. The pin tracks client-side currency, not the
estate's vCenter version (pyVmomi is backward-compatible with supported vCenter
API levels, so one pinned client serves mixed vCenter 7/8 estates).

**Upstream publishes the 8.x line as an sdist only** (no wheel exists for any
`8.x` release; the first wheel is `9.0`). The major cap `<9` is retained
deliberately — the plugin is written and fixture-tested against 8.x SOAP
semantics, and bumping to the 9.0 major is a compatibility change gated by
ADR-0051, not a lockfile tweak. This is safe: pyVmomi is **pure Python**, so the
sdist install needs only `setuptools` (no C toolchain), and `8.0.3.0.1` builds
cleanly on the CI interpreter (Python 3.12, setuptools ≥79 — well past the
setuptools-71 `canonicalize_version` regression that affected some older
sdists). The lockfile hash-pins the sdist, so an air-gapped index mirrors one
artifact and the build is reproducible; pip-audit/Trivy scan it like any other
pinned dependency. When upstream ships an 8.x wheel, the drift gate will pick it
up on the next re-lock with no code change.

## Fixtures, tests, live path

- Conformance runs over recorded **property-set JSON** fixtures
  (`tests/plugins/test_vmware_conformance.py`), covering every mandatory case
  (ADR-0051 §8): multi-batch continuation paging; a Tools-less VM; a template
  VM; a powered-off VM; duplicate names across folders; a standalone host; a
  maintenance-mode host; standard + distributed + trunked port groups; a
  disconnected vNIC; dv key→name resolution; and a teaming-override uplink
  resolution. Zero-plaintext-leakage is asserted for the password **and** the
  session cookie.
- Client **contract tests** pin the real pyVmomi call shape
  (`RetrievePropertiesEx` / `ContinueRetrievePropertiesEx` /
  `CreateContainerView` / `Destroy` / `Disconnect`) and the generic vmodl→JSON
  serialization over constructed pyVmomi objects — the surface a live vCenter
  would exercise, pinned without one. The deep guest-nic / device-backing /
  host-network shapes are validated live (ADR-0051 §9).
- The live golden path (discover → virtualization inventory → W2 join smoke)
  ships ready-to-run in `tests/agents/eval/test_vmware_live_golden_path.py` —
  **deferred-accepted → live lab**, collected-but-skipped in CI (env-var gated).
  The **`vcsim`** simulator (govmomi) is the documented preferred substitute
  (the ADR-0025 §9 `n9000v` pattern); its fixture fidelity is a named open
  question (ADR-0051 §9.5).
