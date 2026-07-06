# W0-T2 — ADR-0051 VMware plugin (pyVmomi, `VIRTUALIZATION_INVENTORY`, read-only vCenter role)

| | |
|---|---|
| **Wave** | P4 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet; **strong** on the credential/session-lifecycle section (§2) |
| **Depends on** | — |
| **Builds on** | ADR-0006 (plugin contract), ADR-0007 D7 (pyVmomi for VMware), ADR-0011 (vault/audit), ADR-0034/0050 (capability-ratification precedents), P3-W0-T8 (lockfile) |
| **PRODUCTION.md** | §2.4 (Wave 3 row), §2.6, §11 G-SEC/G-MNT |
| **Status** | **Done** (W0, `feat/p4-w0-adrs`) |

## Objective

Ratify the VMware plugin design the W1-T2 build implements field-for-field:
**pyVmomi confirmed per D7 (first new runtime dependency since the lockfile —
floor+cap pin, lockfile-resolved), vCenter-as-device, short-lived per-collection
sessions under a least-privilege read-only vCenter role, the NEW
`VIRTUALIZATION_INVENTORY` capability with final
`NormalizedVirtualMachine`/`NormalizedHypervisorHost`/`NormalizedComputeCluster`/
`NormalizedPortGroup` models (+ nested vNIC/pNIC sub-models), PropertyCollector
collection with continuation paging, and the named raw-first deviation
(deterministic property-set JSON)**. No write path exists in this plugin.

## Scope

**In** — the design decisions and rationale: SDK choice + lockfile/pin posture
(§1), credential flow + session lifecycle to the strong bar (§2), read-only role
+ explicit no-write-path statement (§3), capability map incl. why `INTERFACES`/
`HA_STATUS` are NOT declared (§4), models/enums/join-key contract for the W2
derivation (§5), PropertyCollector paging (§6), the raw-first JSON deviation —
named, not silent (§7), conformance/fixture obligations incl. `vcsim` posture
(§8), open lab questions (§9).

**Out** — implementation (W1-T2); inventory UI (W1-T3); the W2 derivation
(ADR-0052); any write surface (VM tags/snapshots/power — future ADR + full CR
gating); ESXi-as-device collection; host-config/vCenter-profile backup
(named-deferred).

## Requirements (grounded in PRODUCTION.md §2.4/§2.6, ADR-0006/0011, P4-PLAN §0a)

1. **New capability surface ratified before code:** enum member, four-method
   ABC, final model names + field tables + the §5.5 join-key/identity-key
   contract W2 consumes.
2. **Secret surface to the strong bar:** password + SOAP session cookie
   lifecycle, TLS-verify default, no debug transports, typed credential-free
   errors — zero plaintext leakage is a W1 exit criterion.
3. **Least privilege stated:** dedicated read-only service account
   (`System.Anonymous`/`System.Read`/`System.View` on the root object,
   propagated); compromise yields visibility, never control.
4. **Dependency governance:** `pyvmomi` lands via floor+cap constraint +
   lockfile resolution in the same W1-T2 commit; drift gate covers it day one.
5. **Named deviations, never silent:** raw artifacts are post-deserialization
   property-set JSON; single-vendor validation (§5.7); live golden path
   deferred-accepted → live lab with `vcsim` as the documented substitute.

## Contracts / artifacts

- `docs/adr/0051-vmware-plugin.md` (Proposed); index entry via W0-T5.

## Test & gate plan

- D16 docs gates only (ADR — no code). The ADR names the mandatory fixture
  cases, secret-leak assertions, and `_INTERFACE_SPECS` wiring W1-T2 must
  satisfy.

## Exit criteria

- [x] ADR-0051 written (Proposed): pyVmomi + pin posture, credential/session flow, read-only role + no-write-path, `VIRTUALIZATION_INVENTORY` + models/enums, join-key contract, paging, raw-first deviation.
- [x] Credential/session section (§2) reviewed at the strong bar.
- [x] Named deviations recorded (raw-first JSON, single-vendor validation, live-lab/`vcsim` posture).
- [x] One atomic commit (`deca752`, review fixes folded).

## Workflow

`wf-implementer` drafts → spec + quality review (strong on §2) → fixer if findings → verifier → one atomic commit.

## Risks

- **Join-key ambiguity** (names not unique per vCenter) → derivation corruption.
  The ADR pins moref-based identity + datacenter-scoped name joins (§5.5).
- **Raw-first deviation unstated** → audit-surface drift. Named in the ADR and
  required in plugin docs.
