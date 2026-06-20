# ADR-0025: Cisco NX-OS Vendor Plugin

**Status:** Proposed | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

CLAUDE.md lists **Cisco NX-OS** in the required vendor set, and `PRODUCTION.md` §2.2 schedules it as the lead vendor of **Wave 1 (P1)** because it reuses the *exact* Wave-0 toolchain — netmiko + ntc-templates (ADR-0007 D7) — at the lowest marginal cost while closing "the most common gap in enterprise estates after IOS/IOS-XE": datacenter switching (Nexus). `P1-PLAN.md` §3 W1 hands the build to `wf-implementer-light` with the explicit instruction to **mirror the Wave-0 netmiko plugins**, ship the **plugin conformance suite**, **≥80% coverage**, **normalized-model round-trip**, and accept the **live-lab golden path as deferred** (no Nexus hardware).

The capability *target* for `cisco_nxos` (`PRODUCTION.md` §2.2) is the full Wave-0 surface plus one new member: **SSH/SNMP discovery, interfaces, routes, LLDP/CDP, BGP, OSPF, ACL, config backup/restore/deploy, and `HA_STATUS` (vPC)**. This is the same capability list `cisco_ios` already implements end-to-end (`backend/app/plugins/vendors/cisco_ios/plugin.py`), so the plugin contract (ADR-0006), the connectivity stack (ADR-0007), and the config write/rollback engine (ADR-0017/0021) are all already in place. This ADR is therefore **not** a new architecture — it is the **NX-OS-specific decision record**: where NX-OS *differs* from classic IOS in a way that changes command text, parsing, context handling, the write path, or the transport, and what we do about each difference. Every reusable mechanism (`_record_raw` raw-first audit, `ChangePlan`/`ChangeResult`, the conformance families) is inherited unchanged.

NX-OS is materially unlike IOS in four ways that force decisions: (1) it can emit **native structured output** (`show ... | json` / `| json-pretty`), so we are not forced to screen-scrape; (2) it has **VRF and VDC** context that IOS does not (a Nexus can be partitioned into virtual device contexts, and routing/management lives in named VRFs); (3) many `show`/`config` surfaces are **feature-gated** — `feature bgp`, `feature ospf`, `feature lldp`, `feature lacp/vpc` must be enabled or the command does not exist; (4) it offers **NX-API** (an HTTP/JSON-RPC management API) as an alternative to SSH. Each is decided below. Implementation lands in W1; this is the design gate.

## Decision

**Ship `cisco_nxos` as a netmiko + ntc-templates plugin that mirrors `cisco_ios` (ADR-0006/0007 reference), differing only in NX-OS command text, NX-OS TextFSM templates, VRF-scoped collection, and feature-gate tolerance. SSH is the primary and only P1 transport (parity with `cisco_ios`); structured `| json` output and NX-API are evaluated, scoped, and explicitly deferred as documented below. The config write path reuses the ADR-0021 capture→apply→verify-after→rollback engine, upgraded on NX-OS by `checkpoint`/`rollback` (NX-OS has a native config-rollback primitive IOS lacks). `HA_STATUS` (vPC) is delivered against a new typed `HaStatusCapability` ABC.**

### 1. Capability map — what `cisco_nxos` declares

`cisco_nxos` declares the Wave-0 set plus `HA_STATUS`, all behind the registry (ADR-0006 §4). The implementation classes mirror the `cisco_ios` ones one-for-one, swapping only the `SHOW_*` command constants and the parser module (`vendors/cisco_nxos/parsers.py`, NX-OS TextFSM indexes).

| Capability | NX-OS command (SSH) | Returns | Notes vs. `cisco_ios` |
|---|---|---|---|
| `DISCOVERY_SSH` | `show version` | `DeviceFacts` | netmiko `device_type="cisco_nxos"` |
| `DISCOVERY_SNMP` | system-MIB GET (sysDescr/sysObjectID/sysName) | `DeviceFacts` | identical OIDs; same `SnmpReadTransport` |
| `INTERFACES` | `show interface` | `list[NormalizedInterface]` | NX-OS is `show interface` (no trailing `s`); NX-OS template |
| `ROUTES` | `show ip route vrf all` | `list[NormalizedRoute]` | **VRF-scoped** — see §3 |
| `NEIGHBORS_LLDP` | `show lldp neighbors detail` | `list[NormalizedNeighbor]` | requires `feature lldp` — see §4 |
| `NEIGHBORS_CDP` | `show cdp neighbors detail` | `list[NormalizedNeighbor]` | CDP on by default on NX-OS |
| `BGP` | `show ip bgp summary vrf all` | `list[NormalizedBgpPeer]` | requires `feature bgp`; **VRF-scoped** |
| `OSPF` | `show ip ospf neighbor vrf all` | `list[NormalizedOspfNeighbor]` | requires `feature ospf`; **VRF-scoped** |
| `ACL` | `show ip access-lists` | `list[NormalizedAclEntry]` | NX-OS ACL syntax → same `NormalizedAclEntry` |
| `CONFIG_BACKUP` | `show running-config` | `str` (verbatim) | identical posture (ADR-0017) |
| `CONFIG_RESTORE` | `configure replace` / checkpoint-rollback | `ChangeResult` | NX-OS native rollback — see §5 |
| `CONFIG_DEPLOY` | `configure terminal` merge | `ChangeResult` | same merge surface; same guardrail — see §5 |
| `HA_STATUS` | `show vpc` (+ `| json`) | `list[NormalizedHaStatus]` | **new ABC** — see §6 |

The `NeighborsCapability` ABC already serves both LLDP and CDP (`backend/app/plugins/base.py`); `cisco_nxos` declares both members and maps them to one `CiscoNxosNeighbors` class, exactly as `cisco_ios` does. Command text lives in `SHOW_*` module constants (the `cisco_ios` convention) so the command surface is auditable in one place.

### 2. Transport decision — SSH-primary, mirroring `cisco_ios`; NX-API deferred

**Decision: SSH (netmiko `cisco_nxos`) is the sole P1 transport.** This is the binding `PRODUCTION.md` §2.2 rationale ("same netmiko + ntc-templates toolchain as Wave 0 — lowest marginal cost") and the `P1-PLAN.md` instruction to mirror `cisco_ios`. ntc-templates ships a maintained NX-OS template family, so parser effort is reuse, not invention. SNMP v2c/v3 (ADR-0007 §4, `pysnmp`) is the read-only enrichment channel for discovery, identical to `cisco_ios`.

**NX-API (httpx) is evaluated and deferred, not adopted, in P1.** NX-API is a real alternative transport — an HTTP endpoint accepting `cli_show`/`cli_show_ascii` JSON-RPC and returning structured JSON — and ADR-0007 already names `httpx` as the platform's REST transport. We do **not** adopt it for P1 for three reasons consistent with ADR-0007's posture:

1. **Toolchain reuse beats a second transport.** P1's whole vendor-rollout criterion (`PRODUCTION.md` §2, criterion (a)) is "reuse of proven connectivity/parsing paths first." Adding an httpx NX-API client path would be a *second* connectivity surface for one vendor before the netmiko path is even proven against NX-OS — the opposite of the wave ordering.
2. **NX-API is an opt-in feature (`feature nxapi`), often disabled** on hardened datacenter switches; SSH is always present. An SSH-primary plugin works against the default device posture.
3. **The capability contract is transport-agnostic.** Because transports are plugin-internal (ADR-0006 §6) and a capability returns normalized models regardless of how the bytes arrived, an NX-API transport can be added later as a non-breaking internal swap — exactly the migration ADR-0007 alt #2 reserves for scrapli. We record NX-API as the **designated future enrichment** for high-throughput Nexus fabrics (where SSH screen-scrape latency dominates) and as the structured-output source if `| json` proves insufficient (§3), to be picked up no earlier than a P2+ hardening item.

This mirrors how `cisco_ios` is SSH-only and how ADR-0024 chose one transport posture (`httpx` bearer) and justified it rather than offering two.

### 3. Native structured output (`show ... | json`) — decided OFF for P1, raw-first preserved

NX-OS can append `| json` (or `| json-pretty`) to most `show` commands and emit machine-parseable JSON instead of CLI text. This is genuinely attractive — JSON is more stable across releases than screen-scraped columns. **Decision: P1 uses plain CLI text + ntc-templates (TextFSM), not `| json`.** Rationale:

- **Parser reuse.** ntc-templates' NX-OS family targets the *plain* `show` output; adopting `| json` would mean writing and maintaining NX-OS-specific JSON shape mappers per command — net-new code, against the "reuse proven parsing paths" criterion. The maintenance tax ADR-0006 §"Negative" and ADR-0007 §"Negative" already accept (TextFSM template drift) is the same tax we are paying for every other CLI vendor; splitting NX-OS onto a different parsing mechanism fragments the plugin family.
- **`| json` is not uniformly available.** The JSON formatter is incomplete/inconsistent across NX-OS releases and command surfaces (some commands emit no JSON, some emit a different schema per release) — the very brittleness JSON was supposed to remove reappears as schema drift, just in a less-templated place.
- **Raw-first is unaffected either way.** Per ADR-0006 §3 and the `cisco_ios` `_run` pattern, **whatever** text the device emits is recorded verbatim via `PluginCapability._record_raw(command, output)` *before* parsing. The audit/`raw_artifacts` guarantee holds for CLI text exactly as it would for JSON. Choosing CLI text loses no auditability.

`| json` is recorded as the **preferred structured source if-and-when** a specific NX-OS command's TextFSM template proves too brittle; this is an in-P1 escape hatch, exercised per command and only when a named criterion is met: **no maintained ntc-templates TextFSM template exists for the command, or the template is demonstrably incomplete/wrong for the target NX-OS release family**. When that criterion is satisfied, the implementer may switch *that one command* to `| json` and a JSON mapper, leaving all other commands on TextFSM — the default for every command in P1. The `show vpc` command meets this criterion today (see §8) because vPC state spans multiple interleaved output sections with release-varying indentation that existing ntc-templates NX-OS templates do not cover; all other P1 commands use CLI text + ntc-templates unless the same criterion is met and documented at the call site.

### 4. Feature-gated commands — tolerate "feature disabled" as empty, never as error

On NX-OS a routing/discovery feature must be enabled (`feature bgp`, `feature ospf`, `feature lldp`, `feature lacp`, `feature vpc`) before its `show` command exists; against a switch without the feature, the command returns an error string or empty output rather than a parseable table. This is an NX-OS-specific failure mode `cisco_ios` does not have.

**Decision: a declared capability whose underlying NX-OS feature is disabled returns an empty normalized list, not a `PluginError`.** Concretely:

- The parser for each feature-gated capability (`BGP`, `OSPF`, `NEIGHBORS_LLDP`) treats the NX-OS "feature not enabled" / "Invalid command" sentinel and empty output as **"no records"** and returns `[]` — the same semantics as a device that genuinely has zero BGP peers. The verbatim error text is still recorded via `_record_raw`, so the audit trail shows *why* the result was empty.
- This is deliberately different from `CONFIG_BACKUP`, where empty output **is** an error (`cisco_ios` raises `PluginError` on an empty `show running-config`): a switch always has a running config, but it legitimately may have no BGP. Read capabilities are "best-effort, possibly empty"; the backup capability is "must return content."
- We do **not** pre-probe `show feature` to gate calls. Probing adds a round-trip and a second parse surface; the capability simply runs its command and normalizes "feature absent" to empty. (The discovery engine already tolerates a capability returning `[]`.)

This keeps `cisco_nxos`'s declared `capabilities` frozenset honest at the *plugin* level (the plugin *can* do BGP) while being robust at the *device* level (this particular Nexus has BGP turned off) — matching ADR-0006's "partial coverage is the norm" philosophy but pushing the partiality down to per-device feature state.

### 5. Config write path — reuse ADR-0021 engine; NX-OS upgrades the rollback primitive

`CONFIG_RESTORE`/`CONFIG_DEPLOY` reuse the ADR-0021 `_CiscoIosConfigWriteCapability` engine verbatim in shape: **capture fresh baseline → (management-path guardrail) → apply → verify-after equality → structured rollback → `ChangeResult`**, gated by `ChangePlan.is_executing` so a write **only** runs as the execution step of an `executing`, four-eyes-approved ChangeRequest (ADR-0020/0021 §2). The capability never self-authorizes; a direct call outside an `executing` CR is a typed `PluginError`, identical to `cisco_ios`. The redaction-safe `applied_diff` (line counts only, never config text) and the never-silent rollback contract (`rollback_failed` is surfaced, never reported as `rolled_back`) are inherited unchanged — config text is secret-bearing (ADR-0017 §"Context") and never appears in a `ChangeResult`.

NX-OS differs from classic IOS in one decisive way that **improves** the write path:

| Aspect | `cisco_ios` (ADR-0021 §4) | `cisco_nxos` (this ADR) |
|---|---|---|
| Apply (deploy) | `configure terminal` merge | same — `configure terminal` merge |
| Apply (restore) | `configure replace` (where available) | `configure replace <checkpoint>` (native) |
| Native rollback primitive | replay captured baseline (no transactional commit) | **`checkpoint` + `rollback running-config checkpoint`** — a native, atomic config-rollback engine |
| Dead-man auto-revert | only on images with `commit timer`; else mgmt-path guardrail | **`configure replace … commit-timeout`** rollback timer available on NX-OS |

**Decision: on NX-OS the executor takes a named `checkpoint` of the captured baseline before apply and rolls back via `rollback running-config checkpoint <name>` on failure** — the stronger primitive `cisco_iosxe` enjoys (ADR-0021 §4 commit-confirm tier), not the bare baseline-replay that classic `cisco_ios` is stuck with. This means:

- Rollback success is still an **asserted equality** (re-capture normalizes equal to the captured baseline) — the §3 ADR-0021 criterion is unchanged; NX-OS just has a cleaner mechanism to reach it.
- The §4.2 **management-path guardrail is still implemented** as defense-in-depth (reject a change touching the mgmt VRF interface / vty `access-class` / management default-route when no dead-man timer is armed), because a connectivity-severing change can still strand the worker mid-apply before the rollback fires. Where the NX-OS `configure replace … commit-timeout` dead-man timer *is* armed, a connectivity-breaking change auto-reverts even if the worker loses the session — the IOS-XE/EOS-equivalent safety ADR-0021 §4 prefers. The guardrail's NX-OS specifics (mgmt VRF, `vrf context management`) are the only delta from the `cisco_ios` `_MGMT_*` patterns.

`cisco_ios` is certified first against the conformance suite (ADR-0021); `cisco_nxos` mirrors it the way ADR-0021 §4 already anticipated NX-OS would ("NX-OS/JunOS/PAN-OS are production-roadmap").

### 6. VRF and VDC context handling

NX-OS has two context dimensions IOS lacks; each gets a decision.

**VRF — collect all VRFs, tag each normalized record with its VRF.** Routing, BGP, and OSPF on NX-OS are per-VRF; a default-VRF-only collection silently misses the management VRF and every tenant VRF. **Decision: route/BGP/OSPF collection uses the `vrf all` form** (`show ip route vrf all`, `show ip bgp summary vrf all`, `show ip ospf neighbor vrf all`) so a single command returns every VRF's table, and the NX-OS parser carries each row's VRF into the normalized record's VRF field. `NormalizedRoute` and `NormalizedBgpPeer` already carry a `vrf: str | None` field in `app/schemas/normalized` and the parser populates it from the `vrf all` section headers. **`NormalizedOspfNeighbor` does not yet carry a `vrf` field** — it must be added as a W1 schema-extension sub-task: the implementer adds `vrf: str | None = None` to `NormalizedOspfNeighbor` in `backend/app/schemas/normalized.py` following the ADR-0006 §"Negative" schema migration + review gate, so that OSPF VRF tagging is on equal footing with routes and BGP. Silently dropping the VRF column from OSPF results (while collecting with `vrf all`) would under-report OSPF neighbours in multi-VRF environments and produce misleading `[]`-equivalent merges under the per-device-VRF key. This makes `cisco_nxos` the first plugin to exercise the normalized models' VRF dimension against real multi-VRF output — a deliberate `PRODUCTION.md` §2 wave goal ("each wave must validate one *new* capability surface").

**VDC — out of P1 scope; the plugin addresses one VDC per `device` row.** A Nexus 7K/9K can be partitioned into Virtual Device Contexts, each a logical switch with its own config and management interface. **Decision: each VDC is modeled as its own inventory `device` (its own `ConnectionParams`/`credential_ref`), and the plugin operates within whatever VDC the SSH session lands in** — it does **not** issue `switchto vdc` to hop contexts inside one session. Rationale: a `switchto vdc` mid-session changes the device identity, the running config, and the management reachability under the executor's feet — exactly the kind of context shift that would make the ADR-0021 capture-baseline → verify-after equality meaningless (you would verify against a *different* VDC's config). Treating each VDC as a discrete device keeps one session = one config = one rollback baseline, preserves the four-eyes/audit invariants per-VDC, and needs zero new plugin machinery. Multi-VDC orchestration (discovering sibling VDCs from the admin/default VDC) is a documented P2+ enrichment, not a P1 capability.

### 7. Conformance, fixtures, and coverage

`cisco_nxos` ships against the existing reusable conformance suite (`backend/tests/plugins/conformance.py`, ADR-0006 M1-07) exactly as `cisco_ios`/`eos`/`infoblox`/`spatiumddi` do — a `test_cisco_nxos_conformance.py` parametrizing `make_conformance_cases(CiscoNxosPlugin(), capability_factory=…)` over `FixtureReplayTransport` bundled fixtures. The three case families apply automatically:

- **`metadata:*`** — `vendor_id="cisco_nxos"` is snake_case, `display_name="Cisco NX-OS"`, non-empty `capabilities`.
- **`implementation:<capability>`** — every declared capability (including the new `HA_STATUS`) resolves via `get_capability()` to a concrete class subclassing the typed interface and overriding each abstract method itself.
- **`fixtures:<capability>`** — each capability, run over bundled **raw-artifact fixtures recorded as verbatim NX-OS CLI output** (ADR-0006 §3 raw-first), returns non-empty results that re-validate against the normalized Pydantic models and carry `source_vendor="cisco_nxos"`.

**Fixtures are raw-recorded verbatim NX-OS CLI captures**, each file header labeled with the NX-OS release it was captured from, so the **normalized-model round-trip** (`PRODUCTION.md` §2.6: "normalized models round-trip") is exercised over real device text, not hand-authored dicts. Where no hardware capture exists (live-lab deferred, below), fixtures are sanitized public NX-OS `show` samples (no credentials, no real addresses) clearly labeled as such — the same "source-derived, clearly labeled" posture ADR-0024 §5 takes. Minimum fixture set mirrors the `cisco_ios` set plus: a multi-VRF `show ip route vrf all` (to prove §3 VRF tagging), a `feature ospf`-disabled `show ip ospf neighbor` capture (to prove §4 empty-not-error), and a `show vpc` capture for `HA_STATUS`.

**Coverage ≥80%** (D16 / `PRODUCTION.md` §2.6) is a CI gate on the plugin module. The write-path tests reuse the `cisco_ios` fake-transport harness (`ConfigWriteTransport` in-memory fakes) to cover apply / verify-after / rollback / `rollback_failed` / management-path-guardrail branches without a device.

**Cross-vendor eval regression** (`PRODUCTION.md` §2.6: "No regression in the cross-vendor eval suite (M3 agent evals re-run across all installed plugins)") is a required per-wave exit criterion: the M3 agent eval suite must be re-run across all installed plugins after `cisco_nxos` lands, and the result must show no regression. A new plugin that causes an existing vendor's eval case to fail blocks wave acceptance.

**Plugin documentation and API documentation** (`PRODUCTION.md` §2.6: "Plugin documentation + API docs published"; CLAUDE.md Development Standards: "every feature must include tests, documentation, and API documentation") are required deliverables for this wave. The implementer must publish: (a) plugin-level documentation covering supported capabilities, NX-OS-specific command choices, feature-gate behaviour, VRF/VDC scope, and rollback semantics; and (b) API documentation for every public method of `HaStatusCapability` and `NormalizedHaStatus` that other waves will consume.

### 8. New ABC — `HaStatusCapability` (`HA_STATUS`, vPC)

`HA_STATUS` is in the enum (ADR-0006 §1) but has **no typed interface in `plugins/base.py` yet** — `cisco_nxos` is the first plugin to implement it (vPC peer/role/keepalive state), and `PRODUCTION.md` later reuses it for PAN-OS/FortiOS/F5 HA. **Decision: add a minimal `HaStatusCapability` ABC** alongside the existing capability ABCs, returning a new `NormalizedHaStatus` model:

```python
class HaStatusCapability(PluginCapability):
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.HA_STATUS})

    @abstractmethod
    def get_ha_status(self) -> list[NormalizedHaStatus]:
        """Return high-availability peer state (vPC/HA) as normalized records."""
```

`NormalizedHaStatus` is vendor-neutral (vPC today, PAN-OS/F5 HA later): peer role (primary/secondary/operational-primary), peer-link state, keepalive state, and consistency-check status — the lowest-common-denominator HA fields, following the ADR-0006 §3 normalized-model pattern. Adding the ABC + model requires **no change to existing plugins** (ADR-0006 §6: "adding one requires no change to existing plugins"); the conformance suite's `fixtures:ha_status` family attaches once **all three** of the following code changes are made by the implementer:

1. **`backend/app/plugins/base.py`** — add the `HaStatusCapability` ABC (with the `get_ha_status()` abstract method above) and import `NormalizedHaStatus`; without this the capability has no typed interface and `get_capability()` cannot return a checkable class.
2. **`backend/app/schemas/normalized.py`** — add the `NormalizedHaStatus` Pydantic model; `HaStatusCapability.get_ha_status()` cannot be typed until the model exists, and the conformance suite's record-validation step would have nothing to validate against.
3. **`backend/tests/plugins/conformance.py`** — add a `Capability.HA_STATUS` entry to `_INTERFACE_SPECS` mapping it to `HaStatusCapability`, `"get_ha_status"`, and `NormalizedHaStatus`; until this entry is present the conformance suite's `fixtures:ha_status` case is **silently skipped** (the `_INTERFACE_SPECS.get(capability)` lookup returns `None` and the case is omitted), meaning HA_STATUS fixture coverage is never enforced even after the ABC and model land.

On NX-OS the implementation runs `show vpc` (with `| json` applied per the §3 per-command criterion — no maintained ntc-templates template for vPC multi-section state) and maps it to `NormalizedHaStatus`.

### 9. Live-lab golden path — deferred-accepted

`P1-PLAN.md` §3 W1 and §6 mark the vendor golden-path **live-lab run as deferred-accepted (no hardware)** — same posture as M4/M5 and ADR-0024 §5/§6.1. The plugin is fully verified by the mock/fixture-backed conformance suite + unit tests in the green CI suite; the live discover→CR→approve→execute→verify→audit golden path against a real Nexus (or a NX-OSv/`n9000v` sandbox image, the documented preferred substitute) is recorded as the **deferred acceptance item** for when datacenter-switch hardware/sandbox is available, with the open questions below to resolve then.

### 10. Open questions (require a NX-OS instance / sandbox)

1. **ntc-templates NX-OS coverage gaps** — which NX-OS `show` commands lack a current TextFSM template (forcing a per-command `| json` switch under §3) is only knowable against real release output; resolve when a `n9000v` sandbox is available.
2. **`vrf all` section-header stability** — the exact section delimiter the parser keys on for VRF tagging (§3) varies by release; confirm against ≥2 NX-OS releases.
3. **`checkpoint`/`rollback` semantics under partial apply** (§5) — whether NX-OS `rollback running-config checkpoint` cleanly reverses an order-sensitive fragment, and the precise `commit-timeout` dead-man behavior, need a live apply-fail test (mirrors ADR-0021 §3's deploy-rollback edge).
4. **`show vpc` JSON shape** (§8) — the `| json` schema for vPC state across releases, to pin the `NormalizedHaStatus` mapper.
5. **NX-API parity** (§2) — if/when NX-API is adopted, whether its `cli_show` JSON matches the SSH `| json` shape closely enough to share mappers.

## Consequences

**Positive**

- `cisco_nxos` is a near-pure mirror of `cisco_ios` — same plugin contract (ADR-0006), same connectivity stack (ADR-0007), same config write/rollback engine and four-eyes gate (ADR-0020/0021), same conformance suite — so it lands as a template-following `wf-implementer-light` task with maximal reuse and minimal new surface (`P1-PLAN.md` §3).
- NX-OS's native `checkpoint`/`rollback` and `configure replace … commit-timeout` give the write path a **stronger** rollback primitive than classic IOS — `cisco_nxos` sits in the IOS-XE/EOS commit-confirm tier (ADR-0021 §4), not the bare-replay tier.
- Treating each VDC as a discrete inventory device keeps the one-session = one-config = one-rollback-baseline invariant intact, so the ADR-0021 verify-after equality stays meaningful with zero new machinery.
- `cisco_nxos` is the first plugin to exercise the normalized models' **VRF dimension** (multi-VRF route/BGP/OSPF tagging) and the new `HA_STATUS` interface, validating two new normalized surfaces ahead of the firewall/ADC waves that will reuse `HA_STATUS`.
- Raw-first verbatim recording (`_record_raw`) is preserved for CLI text exactly as for JSON, so deferring `| json` costs no auditability.

**Negative**

- Choosing CLI text + ntc-templates over native `| json` accepts NX-OS template drift across releases (the ADR-0006/0007 TextFSM tax) on a vendor that offers a more stable JSON path; mitigated by the per-command `| json` escape hatch (§3) and raw-first re-parse.
- Feature-gating (§4) means a declared capability can legitimately return `[]` because a *device* feature is off — the plugin-level `capabilities` set advertises more than any single device may answer; the verbatim-recorded sentinel is the only signal distinguishing "feature off" from "genuinely empty," which engines/agents must not over-read.
- VDC multi-context discovery and NX-API are deferred (§2/§6), so a fabric that needs admin-VDC-driven sibling discovery or high-throughput NX-API collection is not fully served by P1 — documented as P2+ enrichment, not silently missing.
- Adding `HaStatusCapability` + `NormalizedHaStatus` (§8) is net-new shared surface; a poorly chosen HA model ripples into PAN-OS/FortiOS/F5 later (ADR-0006 §"Negative" interface-proliferation risk) — mitigated by keeping the first model lowest-common-denominator and vPC-grounded.

## Alternatives considered

1. **Adopt NX-API (httpx) as the primary transport.** *Rejected* for P1: it is a second connectivity surface for one vendor before the netmiko path is proven against NX-OS, against the `PRODUCTION.md` §2 "reuse proven paths first" wave criterion; NX-API is feature-gated (`feature nxapi`) and often disabled on hardened switches, whereas SSH is always present; and because transports are plugin-internal (ADR-0006 §6) NX-API can be added later as a non-breaking internal swap (the same option ADR-0007 alt #2 reserves for scrapli). **Chosen:** SSH-primary, mirroring `cisco_ios`, NX-API recorded as a P2+ enrichment.
2. **Parse `show ... | json` structured output instead of TextFSM.** *Rejected* for P1: `| json` is inconsistent/incomplete across NX-OS releases and command surfaces, so the brittleness it was meant to remove reappears as JSON schema drift in a *less-templated* place; and it fragments NX-OS onto a different parsing mechanism from the rest of the CLI plugin family, net-new per-command mappers against the reuse criterion. **Chosen:** CLI text + ntc-templates as default, with a per-command `| json` escape hatch reserved for commands whose template proves too brittle (e.g. `show vpc`).
3. **Raise `PluginError` when a feature-gated command is unavailable.** *Rejected:* a Nexus legitimately may have BGP/OSPF/LLDP disabled — that is normal device state, not a plugin failure; erroring would make discovery of a perfectly healthy switch fail. **Chosen:** normalize "feature disabled"/empty to `[]` for read capabilities (recording the verbatim sentinel for audit), reserving the empty-is-error rule for `CONFIG_BACKUP`, where a switch must always have a running config.
4. **Drive multiple VDCs from one session via `switchto vdc`.** *Rejected:* hopping VDCs mid-session changes the device identity, running config, and management reachability under the executor, breaking the ADR-0021 capture-baseline → verify-after equality (you would verify against a different VDC's config) and muddying the per-device audit trail. **Chosen:** model each VDC as its own inventory `device` (its own `credential_ref`); the plugin operates within the session's VDC only, preserving one-session = one-config = one-rollback-baseline.
5. **Collect default-VRF only and add other VRFs later.** *Rejected:* on NX-OS the management VRF and tenant VRFs carry the operationally critical routes/peers; a default-only collection silently under-reports the device and would have to be re-collected (and re-normalized) when VRF support lands. **Chosen:** `vrf all` collection from the start, with each normalized record carrying its VRF — validating the normalized models' VRF dimension as the Wave-1 "new surface."
6. **Reuse the classic-IOS bare-baseline-replay rollback unchanged.** *Rejected:* NX-OS ships a native `checkpoint`/`rollback running-config` engine and a `configure replace … commit-timeout` dead-man timer; ignoring them would needlessly keep NX-OS in the weakest (classic-IOS) rollback tier when it qualifies for the IOS-XE/EOS commit-confirm tier (ADR-0021 §4). **Chosen:** use NX-OS checkpoint-rollback + dead-man timer, keeping the §4.2 management-path guardrail as defense-in-depth.
