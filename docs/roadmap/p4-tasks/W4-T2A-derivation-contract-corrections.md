# W4-T2A — Derivation contract corrections: route-domain safety and complete provenance

| | |
|---|---|
| **Wave** | P4 W4 — Evals + phase-exit gate |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** |
| **Depends on** | **W2-T2** (shipped derivation runtime), **W4-T1** (prior branch task) |
| **Blocks** | **W4-T2** (the eval-only derivation corpus) |
| **ADRs** | ADR-0050 §5 (F5 route domains); ADR-0052 §2/§3.1 (sources and provenance), §4 (idempotent derivation) |
| **PRODUCTION.md** | §2.4, §2.6, §11 (correctness and green-and-biting gates) |
| **Status** | Proposed |

## Objective

Correct the bounded runtime contract defects identified by W4-T2 preflight
after W4-T1 landed, before the independent W4-T2 corpus is authored. Bare
member-IP reconciliation must respect F5 route domains, while VMware-derived
edges must retain the complete virtual-server → pool → member evidence chain.

## Scope

**In** — preserve each member's established stable member name as its identity
and provenance ref; parse the canonical address, then admit it as globally
joinable evidence only when `vrf` is absent, empty, or `"0"`; apply that same
safe evidence boundary to F5 inventory and VMware guest-IP reconciliation;
keep FQDN evidence independent of route-domain IP safety; include the pool step
in VMware provenance; focused regression and guard tests; W4 plan/dependency
documentation.

**Out** — `_AddressIndex` changes; schemas or migrations; derivation source
expansion or precedence changes; new normalized fields; W4-T2 corpus/scorer
work; any edit to the T2/T3/T4 evidence-ledger sections.

## Requirements

1. **Nondefault route domains never use global bare-IP evidence.** A member
   with `vrf="2"` cannot match a global interface or a VMware guest IP, even
   when the text of the address is identical. The unmatched F5 path increments
   `f5_members_unreconciled`.
2. **Default-domain compatibility is preserved.** An absent `vrf`, an empty
   value, and `"0"` continue to reconcile against global inventory.
3. **FQDN evidence remains independent.** A nondefault-domain member may still
   match a VMware guest hostname by normalized FQDN; route-domain filtering
   applies only to the ambiguous bare-IP join.
4. **VMware provenance is complete.** Every member-to-VM placement edge carries
   virtual-server → pool → member steps, followed by the VM and host placement
   steps already defined by ADR-0052.
5. **Exclusions remain exclusions.** A Tools-less VM with no guest hostname or
   guest IP emits no VMware placement edge.

## Contracts / artifacts

- `backend/app/engines/topology/app_derivation.py` remains the sole production
  module changed; stable member-name identity/provenance is preserved while the
  parsed canonical address is admitted as joinable evidence only when
  route-domain-safe.
- `backend/tests/engines/topology/test_app_derivation.py` carries the regression
  matrix and guards.
- W4 ordering is T0A → T0B → T1 → T2A → T2 → T3 → T4. T2A has no evidence
  ledger section, and T2 remains eval-only.

## Test & gate plan

- RED: focused derivation tests must expose the unsafe global F5 join, unsafe
  VMware guest-IP join, and missing pool provenance.
- GREEN: the focused suite covers the three corrections plus default-domain,
  FQDN, and Tools-less guards.
- Run adjacent derivation-store and PostgreSQL coverage where locally
  available, Ruff check/format for touched Python, touched-module mypy, and
  `git diff --check`.

## Exit criteria

- [ ] All route-domain and provenance regressions pass with the guards intact.
- [ ] No address-index, schema, migration, precedence, or ledger change lands.
- [ ] W4 plans and task dependencies encode T1 → T2A → T2 and seven commits.
- [ ] One atomic commit with subject
  `fix(topology): preserve route-domain and provenance contracts`.

## Workflow

`wf-implementer` → **strong** review → fixer if findings → verifier → one
atomic commit.

## Risks

- **Identity loss** — replacing the established stable member-name ref with
  embedded address content would violate the ADR-0052 §3.1 reference contract;
  keep the stable name in provenance and use the parsed address only as
  joinable evidence.
- **Over-filtering** — route-domain safety must not suppress valid FQDN joins
  or default/global route-domain matches.
- **Eval contamination** — mixing runtime fixes into T2 would make the corpus
  self-referential; T2A lands first and T2 stays evaluation-only.
