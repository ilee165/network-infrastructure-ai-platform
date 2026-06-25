# ADR-0034: `FIREWALL_POLICY` Capability + `NormalizedFirewallRule` / `NormalizedNatRule`

**Status:** Proposed | **Date:** 2026-06-25 | **Milestone:** P2 W0

## Context

P2 ships the platform's first firewall vendors — Palo Alto PAN-OS (`panos`,
ADR-0035) and Fortinet FortiOS (`fortios`, ADR-0036) — and the read-only Security
Agent (ADR-0037) that analyzes their policy. All three bind to one normalized
contract: a typed firewall-policy capability and the normalized rule models it
returns. This ADR is the **design gate** that ratifies that contract; the code
lands in **W1-T1** (`P2-SECURITY-PLAN.md` §3), field-for-field against the tables
below. No code in this ADR.

The requirement traces to `PRODUCTION.md` §2.3, which names the capability and
marks the model names **PROPOSED**: "introduces the `FIREWALL_POLICY` capability
and `NormalizedFirewallRule` (PROPOSED model name, following the brief's
normalized-model pattern)". This ADR settles the final names, the
lowest-common-denominator field sets, and how vendor-unique richness rides.

The decision is bounded by the binding plugin contract, ADR-0006 (D6):

- **Capabilities are typed ABCs over an enum** (ADR-0006 §1). `Capability.FIREWALL_POLICY`
  **already exists** in the enum (`backend/app/plugins/base.py:113`) — this ADR adds
  **no enum member**; it adds only the typed interface + models.
- **Normalized models are the only engine-visible currency** (ADR-0006 §3); the raw
  vendor payload (XML / REST JSON) is stored verbatim first (`_record_raw`) and is
  never the interface return type.
- **Adding one typed capability is additive** (ADR-0006 §6, ADR-0025 §6 precedent):
  `HaStatusCapability` was added in P1 W0 with zero edits to existing plugins. The
  same pattern applies here.

The firewall-rule surface is **zone- and application-aware** and is distinct from
the existing interface ACL (`NormalizedAclEntry` / `AclCapability`,
`base.py:482` / `normalized.py:337`): an ACL is an ordered list of L3/L4
permit/deny entries bound to an interface; a firewall rule matches on
source/destination **zones**, named **address objects**, and **application/service**
identity. The two coexist; neither subsumes the other.

The known ADR-0006 negative governs the central tension here: "vendor-unique
richness either extends the schema or rides an escape-hatch field … a bad early
signature ripples through every plugin." PAN-OS carries security-profile groups,
rule UUIDs, and app-id richness FortiOS expresses differently; folding either
vendor's extras into the normalized model would bloat every other vendor's records
with `None`s and — worse — feed vendor-specific fields into the Security Agent's
analysis as if they were portable.

## Decision

**Add a typed `FirewallPolicyCapability` ABC returning two frozen, audit-safe
normalized models — `NormalizedFirewallRule` and `NormalizedNatRule` — whose fields
are the strict lowest common denominator both PAN-OS and FortiOS can populate.
Vendor-unique richness does NOT enter the normalized surface; it rides the
raw-first artifact (ADR-0006 §3) only. The interface is declared stable only after
both W2 plugins populate it (the two-vendor rule, `PRODUCTION.md` §2.3).**

### 1. Capability interface (ratified signature — implemented in W1-T1)

```python
# backend/app/plugins/base.py — mirrors AclCapability / HaStatusCapability
class FirewallPolicyCapability(PluginCapability):
    """``Capability.FIREWALL_POLICY`` — zone/application-aware firewall + NAT policy."""

    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.FIREWALL_POLICY})

    @abstractmethod
    def get_firewall_rules(self) -> list[NormalizedFirewallRule]:
        """Return firewall/security policy rules as normalized records."""

    @abstractmethod
    def get_nat_rules(self) -> list[NormalizedNatRule]:
        """Return NAT policy rules as normalized records."""
```

Both methods return normalized models, never dicts/raw (ADR-0006 §3). A plugin that
does not declare `FIREWALL_POLICY` is unaffected (ADR-0006 §6, additive).

### 2. `NormalizedFirewallRule` (final name; W1-T1 binds field-for-field)

Subclasses `NormalizedRecord` (inherits `device_id` / `collected_at` /
`source_vendor`; `frozen=True`, `extra="forbid"`).

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Rule name/identifier |
| `position` | `int \| None` (ge=0) | Evaluation order within the policy; `None` if vendor does not expose it |
| `enabled` | `bool` | A disabled rule is collected, not dropped (analysis needs it) |
| `action` | `FirewallAction` | `allow` / `deny` / `drop` / `reject` (new StrEnum, §4) |
| `source_zones` | `tuple[str, ...]` | `()` = any |
| `destination_zones` | `tuple[str, ...]` | `()` = any |
| `source_addresses` | `tuple[str, ...]` | Address-object names **or** CIDR/IP literals (see §5) |
| `destination_addresses` | `tuple[str, ...]` | as above |
| `applications` | `tuple[str, ...]` | App-id / application names; `()` = any |
| `services` | `tuple[str, ...]` | Service-object names or `proto/port`; `()` = any |
| `logging` | `bool \| None` | Logging enabled for the rule (session start/end collapsed to a bool) |
| `hit_count` | `int \| None` (ge=0) | For redundant/unused-rule analysis (W3) |
| `description` | `str \| None` | Free text |

### 3. `NormalizedNatRule` (final name)

| Field | Type | Notes |
|---|---|---|
| `name` | `str` (min_length=1) | Rule name |
| `nat_type` | `NatType` | `source` / `destination` / `static` (new StrEnum, §4) |
| `enabled` | `bool` | |
| `source_zones` | `tuple[str, ...]` | `()` = any |
| `destination_zones` | `tuple[str, ...]` | `()` = any |
| `original_source` | `tuple[str, ...]` | Pre-translation source (names or literals) |
| `original_destination` | `tuple[str, ...]` | Pre-translation destination |
| `original_service` | `str \| None` | Pre-translation service |
| `translated_source` | `tuple[str, ...]` | Post-translation source |
| `translated_destination` | `tuple[str, ...]` | Post-translation destination |
| `translated_service` | `str \| None` | Post-translation service |

### 4. New enums (in `normalized.py`, alongside `AclAction`)

- `FirewallAction(StrEnum)`: `ALLOW = "allow"`, `DENY = "deny"`, `DROP = "drop"`,
  `REJECT = "reject"`. PAN-OS `allow/deny/drop/reset` and FortiOS `accept/deny` both
  map onto this set (the plugin does the mapping; `reset` → `reject`, `accept` →
  `allow`). The mapping is the plugin's concern (W2), recorded in ADR-0035/0036.
- `NatType(StrEnum)`: `SOURCE = "source"`, `DESTINATION = "destination"`,
  `STATIC = "static"`.

### 5. Addresses are strings, not `IPvNNetwork` — deliberate

Unlike `NormalizedAclEntry.source` (an `IPv4Network | IPv6Network`), firewall rules
overwhelmingly reference **named address objects** ("DMZ-Web", "Any", an address
group), not literals. Forcing an IP type would make most rules unrepresentable.
Addresses are therefore `str` (an object name **or** a literal CIDR/range); resolving
an object to its members is a future enrichment, not part of this contract. `()` /
empty means **any** (firewall convention), consistent with `NormalizedAclEntry`'s
`None`-means-any.

### 6. Vendor-richness escape hatch — raw-first only (no normalized map)

**Decision: there is no `vendor_attributes` field.** Vendor-unique richness
(PAN-OS security-profile groups, rule UUIDs, FortiOS UTM profiles, schedule objects)
lives **only** in the verbatim raw artifact every plugin already stores
(`_record_raw`, ADR-0006 §3) and is retrievable out-of-band; it is **not**
engine-visible. Rationale: (a) a normalized escape-hatch map bloats all 13 vendors'
records and invites schema drift; (b) the Security Agent (ADR-0037) analyzes only
normalized fields — admitting vendor-specific keys would let non-portable data
silently become analysis input, defeating cross-vendor determinism. Cost: vendor
specifics are not engine-queryable in P2 (named-deferred enrichment).

### 7. Coexistence with `NormalizedAclEntry`

`FIREWALL_POLICY` and `ACL` are distinct capabilities and distinct models; a plugin
may declare either, both, or neither. The Security Agent consumes both (ACL for
L3/L4 posture, firewall policy for zone/app analysis). Neither model is changed by
this ADR.

## Consequences

**Positive**
- One typed contract both W2 plugins and the W3 agent bind to; additive, zero-touch
  to existing plugins (ADR-0006 §6 / ADR-0025 §6 precedent).
- LCD fields + raw-first escape hatch keep the engine-visible surface strictly
  normalized, so the Security Agent's analysis is portable across vendors by
  construction.
- Frozen, `extra="forbid"`, secret-free models inherit the audit-safe provenance
  triple — no credential field can appear (firewall policy is config metadata).

**Negative**
- The LCD drops vendor richness from the engine view (raw-first only, §6); a future
  ADR adds enrichment if analysis needs PAN-OS security profiles. Named, not silent.
- A field neither vendor can populate would be dead weight; the W0-T2/T3
  realizability cross-checks (and the two-vendor W2 validation) are the guard
  against both over- and under-specification.
- Addresses-as-strings (§5) defers object resolution; analysis that needs resolved
  membership waits for that enrichment.

## Alternatives considered

1. **A normalized `vendor_attributes` map (escape-hatch field).** Rejected (§6):
   bloats every vendor, drifts, and leaks non-portable data into the agent's
   analysis surface. Raw-first already preserves the richness without these costs.
2. **Extend `NormalizedAclEntry` instead of a new model.** Rejected (§7): firewall
   policy is zone/application-aware and NAT-bearing; overloading the ACL model would
   muddy both and force `None`s on every existing ACL-only plugin.
3. **Typed IP addresses (`IPvNNetwork`) like the ACL model.** Rejected (§5):
   firewalls reference named objects; literals are the minority. Strings represent
   both; resolution is a separate enrichment.
4. **Ship one firewall vendor now, normalize later.** Rejected: a single vendor
   cannot prove the model is vendor-neutral; `PRODUCTION.md` §2.3 mandates two
   independent firewalls validate `FIREWALL_POLICY` before it is declared stable.
