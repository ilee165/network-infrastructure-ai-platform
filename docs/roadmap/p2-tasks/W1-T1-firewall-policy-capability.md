# W1-T1 — `FIREWALL_POLICY` Capability Interface + `NormalizedFirewallRule` / `NormalizedNatRule` + Conformance

| | |
|---|---|
| **Wave** | P2 W1 — `FIREWALL_POLICY` capability (novel cross-vendor model) |
| **Owner** | `wf-implementer` (strong — novel cross-vendor normalized model; a bad signature ripples through both W2 plugins + W3) |
| **Review tier** | sonnet spec + sonnet quality (no secret surface — config metadata only; escalate only if quality review flags a secret path) |
| **Depends on** | **W0** (ADR-0034 ratifies names/fields; ADR-0035/0036 confirm realizability) |
| **ADRs** | ADR-0034 §all (the contract this implements), ADR-0006 §3 (normalized currency), §6 (additive capability) |
| **PRODUCTION.md** | §2.3 (`FIREWALL_POLICY` + models), §2.6 (conformance + ≥80% cov), §11 G-MNT |
| **Status** | Proposed |

## Objective

Implement exactly what **ADR-0034** ratified: the typed
**`FirewallPolicyCapability`** ABC in `app/plugins/base.py` and the
**`NormalizedFirewallRule`** / **`NormalizedNatRule`** Pydantic models in
`app/schemas/normalized.py`, plus the **conformance-suite families** the two W2
plugins will be checked against. This is the contract `panos` (W2-T1), `fortios`
(W2-T2), and the Security Agent (W3) all bind to — **it blocks W2 + W3**. No
vendor implementation here; only the interface + models + conformance.

## Scope

**In** (`backend/app/plugins/base.py`, `backend/app/schemas/normalized.py`,
`backend/tests/plugins/conformance.py`, `backend/tests/plugins/test_conformance.py`)
- **`FirewallPolicyCapability(PluginCapability)`** ABC mirroring the
  `HaStatusCapability` precedent (base.py L737): `capabilities =
  frozenset({Capability.FIREWALL_POLICY})`, abstract `get_firewall_rules()
  -> list[NormalizedFirewallRule]` and `get_nat_rules() -> list[NormalizedNatRule]`
  (final signatures per ADR-0034). Add both class name(s) to `__all__` and the
  `normalized` import block.
- **`NormalizedFirewallRule`** / **`NormalizedNatRule`** subclassing
  `NormalizedRecord` (frozen, `extra="forbid"`, inherit `device_id` /
  `collected_at` / `source_vendor`), with the **field tables fixed in ADR-0034**
  (lowest-common-denominator across PAN-OS + FortiOS). Vendor-richness escape
  hatch exactly as ADR-0034 decided (no broader surface).
- **Conformance families**: extend `conformance.py` so a plugin declaring
  `FIREWALL_POLICY` is checked for the round-trip + raw-first + normalized-type
  contract the existing families enforce (interfaces/routes/acl). A plugin that
  does **not** declare `FIREWALL_POLICY` is unaffected (ADR-0006 §6 additive).
- **`Capability.FIREWALL_POLICY` already exists** (base.py L113) — **no enum edit**.
- **No migration** — these are in-memory normalized models (like `NormalizedAclEntry`),
  not ORM tables; confirm nothing persists them via a new table.

**Out**
- `panos` / `fortios` implementations → **W2-T1 / W2-T2**.
- Security-Agent analysis over these models → **W3**.
- Firewall-analysis eval corpus → **W5-T1**.

## Requirements (grounded in ADR-0034, ADR-0006 §3/§6)

1. **Field-for-field with ADR-0034**: the model fields match the ratified tables
   exactly — no field added/renamed/dropped here (the ADR is the contract; this
   task does not re-decide it, P2-tasks/README spec-template rule).
2. **Normalized currency only** (ADR-0006 §3): the ABC returns the normalized
   models, never dicts/raw; raw artifacts are the plugin's `_record_raw` concern
   (W2), not the interface's.
3. **Additive, zero-touch to existing plugins** (ADR-0006 §6): adding the ABC +
   conformance family must leave every existing plugin and its conformance run
   green with no edits.
4. **Frozen + audit-safe**: `frozen=True`, `extra="forbid"`; no secret-bearing
   field (firewall policy is config metadata — assert no credential field).
5. **Two-vendor stability is a W2 concern, seeded here**: the conformance family
   is written so both W2 plugins are validated against it before `FIREWALL_POLICY`
   is declared stable (PRODUCTION.md §2.3).

## Contracts (implements ADR-0034)

```python
# app/plugins/base.py
class FirewallPolicyCapability(PluginCapability):
    capabilities: ClassVar[frozenset[Capability]] = frozenset({Capability.FIREWALL_POLICY})

    @abstractmethod
    def get_firewall_rules(self) -> list[NormalizedFirewallRule]: ...

    @abstractmethod
    def get_nat_rules(self) -> list[NormalizedNatRule]: ...
```

```python
# app/schemas/normalized.py
class NormalizedFirewallRule(NormalizedRecord):
    # fields exactly per ADR-0034 table (name/position, src/dst zones,
    # src/dst addresses, application/service, action, logging, enabled,
    # hit_count, description, + ratified escape hatch)

class NormalizedNatRule(NormalizedRecord):
    # fields exactly per ADR-0034 table (name, type, original/translated
    # address+service, zones)
```

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff (check + format), mypy strict, import-linter, pytest **≥80%** on the
  touched modules (`base.py` additions, `normalized.py` additions).
- **Round-trip**: each model serializes → deserializes equal; `extra="forbid"`
  rejects an unknown field; `frozen=True` rejects mutation.
- **Conformance**: a fixture plugin declaring `FIREWALL_POLICY` passes the new
  family; an existing plugin (e.g. `cisco_ios`, no `FIREWALL_POLICY`) stays green
  with zero edits (additive proof).
- **No-migration check**: `alembic heads` unchanged; no new table references the models.
- **fastapi route-introspection** stays green (no lockfile — standing fact; verify
  after any incidental import change).

## Exit criteria

- [ ] `FirewallPolicyCapability` ABC present (signatures per ADR-0034); `__all__` + imports updated.
- [ ] `NormalizedFirewallRule` / `NormalizedNatRule` present, field-for-field with ADR-0034; frozen, `extra="forbid"`, no secret field.
- [ ] Conformance family added; a `FIREWALL_POLICY`-declaring fixture passes it.
- [ ] Every existing plugin + conformance run green, **zero edits** (additive, ADR-0006 §6).
- [ ] No Alembic migration; `alembic heads` unchanged.
- [ ] D16 gates green (ruff/mypy/import-linter/pytest ≥80%); one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-implementer` (strong) implements → `wf-spec-reviewer` (sonnet) +
`wf-quality-reviewer` (sonnet) in parallel → `wf-fixer` if findings →
`wf-verifier` → **one atomic commit**.

## Risks

- **Drift from ADR-0034**: this task must implement, not re-decide. If a field
  proves unrealizable, that is an ADR-0034 fix (loop back), not an ad-hoc change
  here — otherwise W2/W3 bind to a model the ADR doesn't describe.
- **Conformance family too weak**: if it doesn't actually assert the round-trip /
  raw-first contract, both W2 plugins can pass while diverging — defeating the
  two-vendor stability proof. The family is the guardrail; make it bite.
- **Interface proliferation cost** (ADR-0006 negative): a wrong signature here
  ripples through `panos`, `fortios`, and the Security Agent — the strong-model
  implementer + the W0 design gate are the mitigations.
