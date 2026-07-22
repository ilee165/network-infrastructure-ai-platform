# W2-T1 — Shared cloud capability, models, and credential kinds

| Field | Contract |
|---|---|
| Owner | `wf-implementer` (strong) |
| Depends on | W0-T1 / ADR-0055 |
| Review | strong spec + quality; secret surface |
| Status | Proposed |

## Objective and scope

Implement ADR-0055 once for AWS and Azure: typed cloud capability and models,
cross-provider security normalization, and three vault credential kinds with
rotation hooks. Out: provider SDK clients and cloud writes.

## Requirements and contracts

1. Capability enum/ABC and `_INTERFACE_SPECS` conformance wiring return the
   exact normalized inventory; canonical identities and ordering are stable.
2. Models reject invalid CIDRs, port ranges, missing parents, and secret-like
   arbitrary payload fields; round trips preserve defined nullable semantics.
3. SG/NSG mappings produce equivalent `NormalizedFirewallRule` shapes for
   equivalent semantics, preserving named references and explicit any CIDRs.
4. Credential payloads are encrypted through D11, scope-checked, metadata-only
   over APIs, redacted in all failures, and integrated with ADR-0040 rotation.
5. Operator policy templates are read-only and tested against required action
   inventories; no IAM/Entra provisioning call exists.

## Test and gate plan

Begin with model/interface and equivalence contract tests. Add planted-secret
tests for API/log/exception/repr/raw artifact paths and rotation failure/rollback
tests. Run credential PG integration, conformance collection, ruff, format,
mypy, lint-imports, full pytest, and module coverage ≥80%.

## Exit criteria

- [ ] One shared capability/model surface is conformance-wired.
- [ ] Credential vault/rotation/leak tests pass for all three kinds.
- [ ] AWS/Azure semantic equivalence and firewall mappings are executable tests.
- [ ] Strong review and D16 pass; one atomic commit.
