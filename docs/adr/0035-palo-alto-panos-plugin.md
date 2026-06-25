# ADR-0035: Palo Alto PAN-OS Vendor Plugin (XML API)

**Status:** Proposed | **Date:** 2026-06-25 | **Milestone:** P2 W0

## Context

PAN-OS (`panos`) is the platform's **first firewall family** and the first of the
two W2 vendors that validate the `FIREWALL_POLICY` contract (ADR-0034). This ADR is
the design gate; the build is **W2-T1** (`P2-SECURITY-PLAN.md` §3). It fixes the
transport, the auth model, and the capability map so W2-T1 has no open question.

`PRODUCTION.md` §2.3 assigns `panos` the capability set: `DISCOVERY_API`,
interfaces, routes, `FIREWALL_POLICY`, ACL/NAT visibility, config backup,
`HA_STATUS`, "API-driven via XML API over httpx per D7". The decision is bounded by
ADR-0006 (plugin contract), ADR-0007 §D7 (API-first transport, httpx), ADR-0011
(credential vault `credential_ref`), and ADR-0034 (the model it returns).

PAN-OS exposes a stable **XML API over HTTPS** (`/api/?type=...&key=...`) that
returns running and candidate configuration and operational state. This is the
vendor-supported management surface; SSH CLI scraping is the fallback Palo Alto
itself discourages. The platform already runs several httpx-client plugins
(bluecat, infoblox, spatiumddi), so the transport pattern is proven.

## Decision

**Ship `panos` as an httpx XML-API plugin (D7 API-first), authenticating with a
vault-referenced API key, declaring the `PRODUCTION.md` §2.3 capability set, and
binding `FIREWALL_POLICY` to the ADR-0034 normalized models. No SSH. No config-write
capability in P2.**

### 1. Transport — XML API over HTTPS via httpx

The plugin uses an httpx client against the PAN-OS XML API
(`https://<host>/api/`), mirroring the existing httpx-client plugins, **not**
netmiko/SSH (D7 API-first: the XML API is the supported surface). Blocking httpx
calls run in Celery workers, never on the event loop (ADR-0007 §3 posture). Raw XML
is stored verbatim before parse (`_record_raw`, ADR-0006 §3). **A PAN-OS config
export can carry secret material** (phash/`type-7`-class secrets, API keys, SNMP
communities in the candidate/running config), so the stored raw artifact inherits
the same `raw_artifacts` storage, access-scoping, and retention controls as every
other raw payload (ADR-0006 §3 / ADR-0011) — it is not a new, unprotected secret
surface. The normalized `FIREWALL_POLICY` models stay secret-free (ADR-0034).

### 2. Auth — vault API key only

The PAN-OS API key is materialized from the credential vault via
`ConnectionParams.credential_ref` (ADR-0011); the plugin receives a reference and
the credentials service materializes the key in-process. The key is never inlined,
never logged, never placed in the URL query in any logged form (a redaction concern
the W2-T1 strong-quality review verifies).

### 3. Capability map (one row per declared capability)

| Capability | XML API request (`type`) | Normalized return |
|---|---|---|
| `DISCOVERY_API` | `op` show-system-info | device identity / facts |
| `INTERFACES` | `op` show-interface / config | `list[NormalizedInterface]` |
| `ROUTES` | `op` show-routing-route | `list[NormalizedRoute]` |
| `FIREWALL_POLICY` | `config` get security rules + NAT rules | `list[NormalizedFirewallRule]` / `list[NormalizedNatRule]` (ADR-0034) |
| `CONFIG_BACKUP` | `config` show (running) | running config (str) |
| `HA_STATUS` | `op` show-high-availability-state | `NormalizedHaStatus` |

ACL/NAT visibility (§2.3) is delivered through `FIREWALL_POLICY` (NAT rules) — PAN-OS
has no separate interface-ACL surface distinct from security policy, so no separate
`ACL` capability is declared.

### 4. Action / type mapping to ADR-0034 enums

- `FirewallAction`: PAN-OS `allow`→`allow`, `deny`→`deny`, `drop`→`drop`,
  `reset-client`/`reset-server`/`reset-both`→`reject`.
- `NatType`: PAN-OS source-NAT→`source`, destination-NAT→`destination`,
  static-NAT→`static`.

### 5. Config backup — running config; Panorama out

`CONFIG_BACKUP` captures the **running** configuration (the enforced state), not the
candidate (uncommitted) config — drift/compliance analysis must reflect what is
live. **Panorama (centralized management) and multi-vsys** are **out of P2 scope**:
the plugin targets a firewall-local policy on the default vsys; Panorama
device-group / shared policy is a named-deferred enhancement (a future ADR), so
W2-T1 has a fixed boundary.

### 6. Read-only — no config-write capability

`panos` declares none of `CONFIG_RESTORE` / `CONFIG_DEPLOY` in P2 (`PRODUCTION.md`
§2.3 does not list them for this vendor). Firewall remediation is the Security
Agent's CR-draft path (ADR-0037 / ADR-0020), not a direct plugin write.

### 7. `FIREWALL_POLICY` field realizability (cross-check ADR-0034)

Every ADR-0034 `NormalizedFirewallRule` / `NormalizedNatRule` field is populatable
from the PAN-OS XML API: rule name, position (rule order), enabled (`disabled`
negated), action, from/to zones, source/destination address (object names), service,
application, log-setting (`log-end`→`logging`), description; NAT original/translated
source/destination/service. `hit_count` is available via
`op` show-rule-hit-count (best-effort; `None` if not enabled). No ADR-0034 field is
unrealizable on PAN-OS — no feedback to W0-T1 required from this vendor.

## Consequences

**Positive**
- API-first (D7) on the vendor-supported surface; reuses the proven httpx-client
  pattern, so W2-T1 is a template-following build (`wf-implementer-light`).
- Running-config backup + full security/NAT policy give the Security Agent (W3) a
  real `FIREWALL_POLICY` source to analyze.
- Read-only with a fixed Panorama/vsys boundary — no scope ambiguity for W2-T1.

**Negative**
- Single-firewall-local scope omits Panorama-managed estates (named-deferred); a
  multi-vsys/Panorama ADR follows if demand appears.
- XML parsing is verbose; the raw-first store mitigates lossy parsing (the verbatim
  XML is always recoverable).

## Alternatives considered

1. **SSH CLI scraping instead of the XML API.** Rejected (D7): the XML API is the
   supported, structured surface; CLI scraping is brittle and Palo-Alto-discouraged.
2. **Include Panorama / multi-vsys in P2.** Rejected: materially larger scope
   (device groups, shared vs vsys precedence) that does not help prove the
   `FIREWALL_POLICY` contract; deferred with a named follow-up ADR.
3. **Candidate-config backup.** Rejected for `CONFIG_BACKUP`: drift/compliance must
   reflect the enforced running config, not uncommitted candidate edits.
4. **A separate `ACL` capability for PAN-OS.** Rejected (§3): PAN-OS expresses L3/L4
   control as security policy, already covered by `FIREWALL_POLICY`.
