# ADR-0036: Fortinet FortiOS Vendor Plugin (REST + SSH fallback)

**Status:** Accepted | **Date:** 2026-06-25 (Accepted 2026-06-29) | **Milestone:** P2 W0 (Accepted P2 W5)

## Context

FortiOS (`fortios`) is the **second** W2 firewall vendor — the one whose independent
implementation proves `FIREWALL_POLICY` (ADR-0034) is vendor-neutral before W1-T1
declares the interface stable (`PRODUCTION.md` §2.3, the same two-vendor discipline
Wave 0 used to prove `INTERFACES` across three OSes). This ADR is the design gate;
the build is **W2-T2** (`P2-SECURITY-PLAN.md` §3).

`PRODUCTION.md` §2.3 assigns `fortios`: `DISCOVERY_API` (REST) + SSH fallback,
interfaces, routes, `FIREWALL_POLICY`, config backup, `HA_STATUS`. The decision is
bounded by ADR-0006, ADR-0007 §D7 (httpx REST **and** netmiko SSH both already in
the connectivity stack), ADR-0011 (credential vault), and ADR-0034.

FortiOS exposes a **REST API** (`/api/v2/cmdb/...` for configuration,
`/api/v2/monitor/...` for operational state). It is the primary surface; a small set
of operational details are cleaner over the CLI, for which the platform's existing
netmiko `fortinet` driver (ADR-0007) is the fallback. This is the platform's first
**two-transport** plugin, so the primary/fallback split must be pinned per
capability — a fallback that is never reached is dead surface.

## Decision

**Ship `fortios` as a FortiOS REST plugin (httpx) with a netmiko SSH fallback,
authenticating both transports from the vault, declaring the `PRODUCTION.md` §2.3
capability set, and binding `FIREWALL_POLICY` to the ADR-0034 models. Each
capability names exactly one primary transport; SSH is fallback only where REST does
not cleanly serve.**

### 1. Transport — one transport per capability in P2 (fallbacks named-deferred)

| Capability | P2 transport | Fallback (named-deferred) | Notes |
|---|---|---|---|
| `DISCOVERY_API` | REST `/monitor/system/status` | SSH `get system status` | facts |
| `INTERFACES` | REST `/monitor/system/interface` | SSH | `NormalizedInterface` |
| `ROUTES` | REST `/monitor/router/ipv4` | SSH `get router info routing-table` | `NormalizedRoute` |
| `FIREWALL_POLICY` | REST `/cmdb/firewall/policy` + `/cmdb/firewall/*nat*` | — | ADR-0034 models; REST fully serves |
| `CONFIG_BACKUP` | SSH `show full-configuration` | REST backup endpoint | full config text is cleaner over CLI |
| `HA_STATUS` | REST `/monitor/system/ha-*` | SSH `get system ha status` | `NormalizedHaStatus` |

A fallback that is never reached is dead surface (Context, above). Accordingly,
**each capability ships exactly one transport in P2**: REST for everything except
`CONFIG_BACKUP`, which is SSH-only. The "fallback" column lists the transport a
follow-up ADR will wire as a try-primary/except-fallback path; until that ADR ships
the fallbacks are **named-deferred**, not implemented — the plugin and its docstrings
advertise only the single transport each capability actually uses. The SSH path
reuses the netmiko `fortinet` transport (ADR-0007) — **no new transport stack** —
and backs only `CONFIG_BACKUP` in P2 (the full-config text export is the established,
lossless CLI surface). Raw payloads from **both** transports are stored verbatim
before parse (ADR-0006 §3).

### 2. Auth — vault credential_ref for both transports

The REST API token and the SSH login both resolve from the vault via
`credential_ref` (ADR-0011); neither is inlined or logged. A device may carry one
credential serving both transports or two scoped credentials — the credentials
service materializes whichever the `ConnectionParams` references.

### 3. Action / type mapping to ADR-0034 enums

- `FirewallAction`: FortiOS `accept`→`allow`, `deny`→`deny`. FortiOS has no native
  `drop`/`reject` policy verb distinct from `deny` (deny silently drops); `deny` maps
  to `deny`. (PAN-OS supplies the `drop`/`reject` distinctions — the union across the
  two vendors exercises the full ADR-0034 `FirewallAction` set.)
- `NatType`: FortiOS SNAT (policy `nat enable` / IP pool)→`source`, VIP /
  DNAT→`destination`, central-SNAT static→`static`.

### 4. VDOM handling — root VDOM in P2

The plugin targets the **root VDOM** (or the single VDOM on a non-VDOM device) in
P2. Multi-VDOM enumeration (iterating every VDOM's policy) is a **named-deferred**
enhancement (a future ADR), keeping W2-T2's scope fixed. The capability map above is
VDOM-scoped to root.

### 5. Read-only — no config-write capability

`fortios` declares neither `CONFIG_RESTORE` nor `CONFIG_DEPLOY` in P2 (not in the
§2.3 set). Firewall remediation routes through the Security Agent's CR draft
(ADR-0037 / ADR-0020).

### 6. `FIREWALL_POLICY` field realizability (cross-check ADR-0034 + ADR-0035)

Every ADR-0034 field is populatable from FortiOS REST `/cmdb/firewall/policy`: rule
name/policyid (→`name`/`position`), `status` (→`enabled`), `action` (→`FirewallAction`),
`srcintf`/`dstintf` zones, `srcaddr`/`dstaddr` (object names), `service`, `application`
list, `logtraffic` (→`logging`), `comments` (→`description`); NAT via the VIP /
central-SNAT tables. `hit_count` is available via the policy hit-count monitor
(best-effort; `None` otherwise). **Cross-vendor agreement with PAN-OS (ADR-0035)
confirmed** — no ADR-0034 field is realizable on one vendor but not the other; no
feedback to W0-T1 required. The two-vendor stability proof for `FIREWALL_POLICY`
holds.

## Consequences

**Positive**
- Independent second vendor with a different transport and a different action
  vocabulary proves `FIREWALL_POLICY` is genuinely vendor-neutral (the ADR-0034
  stability gate), not PAN-OS-shaped.
- REST-primary keeps the common path structured; SSH is used by exactly one
  capability (full-config) where the CLI is cleaner. The §1 cross-transport fallbacks
  are named-deferred (not shipped as inert code) — no dead surface.
- Read-only with a fixed root-VDOM boundary — no scope ambiguity for W2-T2.

**Negative**
- Two transports make `fortios` the most complex W2 build; the per-capability split
  table (§1) is the contract that keeps W2-T2 unambiguous.
- Root-VDOM-only omits multi-VDOM estates (named-deferred).
- FortiOS collapsing `drop`/`reject` into `deny` means those `FirewallAction` values
  are exercised only by PAN-OS — acceptable (the enum is the union; each vendor maps
  its own vocabulary).

## Alternatives considered

1. **SSH-only (netmiko `fortinet`) plugin.** Rejected (D7): REST is the structured,
   API-first surface; SSH is the fallback for the one config-text capability only.
2. **REST-only, no SSH.** Rejected: full running-config export is cleaner and more
   complete over the CLI; a REST-only plugin would ship a weaker `CONFIG_BACKUP`.
3. **Multi-VDOM enumeration in P2.** Rejected: materially larger scope that does not
   help prove the `FIREWALL_POLICY` contract; deferred with a named follow-up ADR.
4. **Defer FortiOS to a later wave (ship only PAN-OS now).** Rejected: a single
   vendor cannot prove vendor-neutrality; `PRODUCTION.md` §2.3 requires two
   independent firewalls in the same wave.
