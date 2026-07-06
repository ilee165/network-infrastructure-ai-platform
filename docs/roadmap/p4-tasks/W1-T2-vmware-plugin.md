# W1-T2 — VMware plugin: `VIRTUALIZATION_INVENTORY` + normalized models + `vmware` (pyVmomi) + conformance fixtures + lockfile

| | |
|---|---|
| **Wave** | P4 W1 — Vendor Wave 3 plugins |
| **Owner** | `wf-implementer` (strong) |
| **Review tier** | **strong** spec + quality (escalated: device-credential/session flow) |
| **Depends on** | **W0-T2** (ADR-0051, the contract) |
| **ADRs** | ADR-0051 (binding, field-for-field), ADR-0006/0007/0011/0040, P3-W0-T8 (lockfile) |
| **PRODUCTION.md** | §2.4, §2.6, §11 G-SEC/G-MNT |
| **Status** | Proposed |

## Objective

Implement ADR-0051: the new **`VIRTUALIZATION_INVENTORY`** capability (enum
member, four-method ABC, `NormalizedVirtualMachine`/`NormalizedHypervisorHost`/
`NormalizedComputeCluster`/`NormalizedPortGroup` + nested
`NormalizedVirtualNic`/`NormalizedPhysicalNic`, `VmPowerState`/
`HostConnectionState`/`VirtualSwitchType` enums) and the **`vmware`** plugin —
pyVmomi against vCenter-as-device, short-lived per-collection sessions under a
read-only role, PropertyCollector collection with continuation paging, raw-first
as deterministic property-set JSON — with `pyvmomi` landing through the uv
lockfile, shipped against the conformance suite over recorded fixtures. **No
write path.**

## Scope

**In** — `base.py` + `normalized.py` additions (ADR-0051 §5.1–§5.4
field-for-field, incl. the §5.5 join-key contract); `plugins/vendors/vmware/`
(`client.py` wrapping pyVmomi behind typed `fetch_*` property-set-document
methods — the fixture-replay seam; `plugin.py`); `SmartConnect`/`Disconnect`
session lifecycle with re-auth-once (§2); TLS verify default on;
`_ApiKeyRedactFilter`-pattern coverage of password + session cookie; per-batch
`_record_raw` of deterministic JSON (§7); `_INTERFACE_SPECS` entry (§5.8);
recorded-fixture set incl. every mandatory case (§8); secret-leak assertions;
`pyvmomi` floor+cap in `pyproject.toml` + exact resolution in the lockfile
(same commit); golden-path script (+ documented `vcsim` substitute); plugin +
API docs.

**Out** — inventory API/UI (W1-T3); W2 derivation; any write surface
(`vmware` declares none — a future ADR + full CR gating); `INTERFACES`/
`HA_STATUS` declaration (rejected in ADR-0051 §4); ESXi-as-device;
host-config/vCenter-profile backup (named deferral).

## Requirements (grounded in ADR-0051)

1. **Field-for-field model fidelity** — §5.3 tables + §5.5 join/identity keys
   are the W2 derivation contract; no `vendor_attributes`; datacenter-scoped
   name joins; morefs as identity.
2. **Session discipline** — never cached across tasks/workers; cookie never
   persisted; `Disconnect` in `finally`; re-auth once on
   `NotAuthenticated`, then typed `PluginError`.
3. **Zero plaintext leakage** — password + session cookie in no log record,
   raw artifact, exception message, or `repr` (asserted); typed error mapping
   strips credentials (`InvalidLogin` → credential-free `PluginError`); no
   pyVmomi/`http.client` debug transports.
4. **Paging correctness** — `ContinueRetrievePropertiesEx` loop until token
   exhaustion; every batch recorded; multi-batch fixture mandatory.
5. **Empty-not-error** — Tools-less VMs, standalone hosts, trunked port groups
   normalize to `None`/`()`, never `PluginError` (ADR-0025 §4).
6. **Lockfile governance** — drift gate green with `pyvmomi` resolved;
   pip-audit/Trivy cover it from day one.

## Contracts / artifacts

- New capability surface in `base.py`/`normalized.py`; `vmware` plugin + entry
  point; `test_vmware_conformance.py` + property-set-JSON fixtures; lockfile
  update; golden-path script; docs (incl. the named raw-first deviation).

## Test & gate plan

- Full gate suite: `pytest`, `ruff check` + `ruff format --check`, `mypy`,
  `lint-imports`; coverage ≥80% on the plugin module (D16); lockfile/drift CI
  gate green.
- Mandatory fixture cases (ADR-0051 §8): multi-batch continuation; Tools-less
  VM; template VM; powered-off VM; duplicate names across folders; standalone
  host; maintenance-mode host; standard + distributed port groups; trunked
  dv-portgroup (`vlan_id=None`); disconnected vNIC; dv key→name resolution;
  teaming-override uplink resolution.
- Secret-leak assertions extended to the session cookie.
- Session-expiry regression case: a mid-run `NotAuthenticated` fault triggers
  exactly one re-auth attempt; a second failure raises the typed
  `PluginError` (both asserted).
- Existing cross-vendor suite shows no regression (full re-run is W4-T1).

## Exit criteria

- [ ] Conformance suite green over recorded property-set fixtures; models round-trip; `_INTERFACE_SPECS` entry present.
- [ ] Zero-plaintext-leakage assertions green (password/cookie); session lifecycle per ADR-0051 §2.
- [ ] No write capability declared anywhere in the plugin (asserted by conformance metadata case).
- [ ] `pyvmomi` in pyproject (floor+cap) + lockfile resolved in the same commit; drift gate green.
- [ ] Coverage ≥80%; plugin + API docs published (raw-first deviation named); golden path shipped + named deferred-accepted → live lab.
- [ ] One atomic commit.

## Workflow

`wf-implementer` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Sibling bug classes** with W1-T1 (pagination, fixture handling,
  empty-result) — sweep both in the same fix commit.
- **Join-key drift** — a fixture that joins names without datacenter scoping
  masks the collision class ADR-0051 §9.6 flags; the duplicate-name fixture is
  mandatory.
- **First SDK dependency** — supply-chain surface governed by lockfile +
  scanning; do not add transitive pins outside the lockfile.
