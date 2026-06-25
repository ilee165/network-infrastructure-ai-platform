# W0-T1 — ADR-0034 `FIREWALL_POLICY` Capability + `NormalizedFirewallRule` / `NormalizedNatRule`

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet spec + sonnet quality (design record; the *model* it ratifies feeds secret-surface W3, but the ADR itself is non-secret) |
| **Depends on** | — (first design-gate task; blocks W0-T2, T3, T4 and all of W1) |
| **ADRs** | ADR-0006 §1 (enum), §3 (normalized-model currency), §6 (additive-capability rule); ADR-0025 §6 (`HaStatusCapability` precedent for adding one typed ABC) |
| **PRODUCTION.md** | §2.3 (`FIREWALL_POLICY` + `NormalizedFirewallRule` PROPOSED names) |
| **Status** | Proposed |

## Objective

Ratify the design contract that the two firewall plugins (W2) and the Security
Agent (W3) bind to: a typed **`FirewallPolicyCapability`** ABC plus the
**`NormalizedFirewallRule`** and **`NormalizedNatRule`** normalized models. This
is the **design gate** — it decides names, fields, and the vendor-richness
escape hatch; W1-T1 implements exactly what this settles. No code in this task.

## Scope

**In**
- Decide the typed `FirewallPolicyCapability(PluginCapability)` ABC — method
  signatures and return types — mirroring the `HaStatusCapability` precedent
  (ADR-0025 §6: adding one typed ABC requires no change to existing plugins).
- Ratify the **final names** `NormalizedFirewallRule` / `NormalizedNatRule`
  (PRODUCTION.md §2.3 marks them PROPOSED) and their lowest-common-denominator
  field sets across **PAN-OS + FortiOS** (the two W2 validators).
- Decide how **vendor-unique richness** rides (the ADR-0006 known negative:
  "vendor-unique richness either extends the schema or rides an escape-hatch
  field"). **Settled by ADR-0034 §6: raw-first-only — no `vendor_attributes`
  map** (a normalized escape-hatch field would bloat every vendor and leak
  non-portable data into the agent's analysis surface); the engine-visible surface
  stays strictly normalized, vendor extras live only in the verbatim raw artifact.
- Decide the relationship to the existing `NormalizedAclEntry` / `AclCapability`:
  firewall policy is **zone/application-aware** and distinct from an interface
  ACL; both coexist, neither subsumes the other.
- Record that `Capability.FIREWALL_POLICY` **already exists** in the enum
  (`base.py` L113 / ADR-0006 §1) — **no enum change**; this ADR adds only the
  typed interface + models.

**Out**
- Implementation (ABC class, Pydantic models, conformance families) → **W1-T1**.
- Per-vendor command/endpoint mapping → **W0-T2** (PAN-OS), **W0-T3** (FortiOS).
- How the Security Agent *analyzes* rules → **W0-T4** / **W3**.

## Requirements (grounded in ADR-0006 §1/§3/§6, PRODUCTION.md §2.3)

1. **Normalized models are the only currency** (ADR-0006 §3): capability methods
   return `list[NormalizedFirewallRule]` / `list[NormalizedNatRule]`, never raw
   dicts; raw XML/REST is stored verbatim first (`_record_raw`, ADR-0006 §3).
2. **Lowest-common-denominator fields** (ADR-0006 negative): the model carries
   only fields both PAN-OS and FortiOS can populate — at minimum rule
   name/position, source/destination zones, source/destination addresses,
   application/service, action, logging, enabled, hit-count, description; NAT
   carries name, type (source/destination/static), original + translated
   address/service. Vendor extras do **not** enter the normalized surface.
3. **Additive only** (ADR-0006 §6): adding `FirewallPolicyCapability` must not
   require editing any existing plugin or capability; the registry resolves it
   like every other capability.
4. **Frozen, audit-safe models** (`NormalizedRecord` convention): `frozen=True`,
   `extra="forbid"`, carry `device_id` / `collected_at` / `source_vendor`; no
   secret material in any field (policy is config metadata, but state it).

## Contracts (the shape this ADR ratifies — implemented in W1-T1)

```python
class FirewallPolicyCapability(PluginCapability):
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.FIREWALL_POLICY})

    @abstractmethod
    def get_firewall_rules(self) -> list[NormalizedFirewallRule]: ...

    @abstractmethod
    def get_nat_rules(self) -> list[NormalizedNatRule]: ...
```

Field tables for `NormalizedFirewallRule` / `NormalizedNatRule` are fixed in the
ADR body (the W1-T1 implementation is field-for-field bound to them).

## Validation / Test & gate plan (ADR review)

- ADR follows the repo template (Status/Date/Milestone header → Context →
  Decision → numbered sections → Consequences → Alternatives), as ADR-0025.
- **Internal consistency:** field set is realizable on both PAN-OS and FortiOS
  (cross-check against the W0-T2/T3 capability maps authored in the same wave).
- **No supersession:** does not contradict ADR-0006 §3; cites the enum member as
  pre-existing.
- markdownlint / no orphan cross-references; `docs/adr/README.md` index updated.

## Exit criteria

- [ ] ADR-0034 written; status **Proposed** (flipped → Accepted in W5-T3).
- [ ] `FirewallPolicyCapability` ABC signature ratified (the W1-T1 contract).
- [ ] `NormalizedFirewallRule` / `NormalizedNatRule` final names + field tables fixed.
- [ ] Vendor-richness escape-hatch decision recorded with rationale.
- [ ] ACL-vs-firewall-policy coexistence stated; "enum already exists, no change" recorded.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-implementer` writes ADR → `wf-spec-reviewer` (sonnet) + `wf-quality-reviewer`
(sonnet) in parallel → `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **A bad early signature ripples through both plugins and the agent** (ADR-0006
  negative: "a bad early signature ripples through 13 plugins"). The two-vendor
  W2 validation is the guardrail, but getting the field set right *here* avoids a
  W2/W3 rework cycle — cross-check both W0-T2/T3 maps before finalizing.
- **Over-normalizing** (folding PAN-OS security-profile richness into the model)
  bloats every other vendor's `None`s; the escape-hatch decision must hold the line.
