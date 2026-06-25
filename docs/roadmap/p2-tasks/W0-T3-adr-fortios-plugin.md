# W0-T3 — ADR-0036 Fortinet FortiOS Vendor Plugin (REST + SSH fallback)

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet spec + sonnet quality (design record; credential-hygiene *implementation* reviewed strong in W2) |
| **Depends on** | W0-T1 (cites `FIREWALL_POLICY` model + ABC) |
| **ADRs** | ADR-0006 (plugin contract), ADR-0007 §D7 (transport: httpx REST + netmiko SSH), ADR-0011 (credential vault), ADR-0034 (the model it binds to) |
| **PRODUCTION.md** | §2.3 (`fortios`: `DISCOVERY_API` REST + SSH fallback, interfaces, routes, `FIREWALL_POLICY`, config backup, `HA_STATUS`) |
| **Status** | Proposed |

## Objective

Decision record for the **second firewall plugin** (the one that proves
`FIREWALL_POLICY` is vendor-neutral, PRODUCTION.md §2.3): ship `fortios` as a
**FortiOS REST API (httpx)** plugin with a **netmiko SSH fallback** for surfaces
REST does not cover. Design gate; build is **W2-T2**.

## Scope

**In**
- **Transport decision:** **REST API over HTTPS via httpx** primary; **netmiko
  SSH (`fortinet`) fallback** for any §2.3 capability not exposed (or not cleanly
  exposed) by REST. State the per-capability primary/fallback split explicitly —
  a fallback that is never reached is dead surface.
- **Auth model:** FortiOS **REST API token** from the vault `credential_ref`
  (ADR-0011); SSH fallback uses a vault credential too — neither inlined/logged.
- **Capability map** per §2.3: `DISCOVERY_API`, `INTERFACES`, `ROUTES`,
  `FIREWALL_POLICY` (firewall policy + NAT → ADR-0034 models), `CONFIG_BACKUP`,
  `HA_STATUS`.
- **VDOM** handling decision (FortiOS multi-VDOM — scoped or deferred).
- **Raw-first** for both transports (ADR-0006 §3).

**Out**
- Implementation + conformance + ≥80% cov → **W2-T2**.
- Config write paths (not in the §2.3 `fortios` set).
- Security-Agent analysis → **W0-T4 / W3**.

## Requirements (grounded in ADR-0006, ADR-0007 §D7, ADR-0011, ADR-0034)

1. **REST-primary, SSH-fallback** (D7): each capability declares which transport
   serves it; the SSH path reuses the netmiko transport (ADR-0007) — no new
   transport stack.
2. **Credential reference only** (ADR-0011) for both REST token and SSH login.
3. **Binds to ADR-0034**: `FIREWALL_POLICY` returns the W0-T1 normalized models.
4. **Two-vendor validation** (§2.3): `fortios` + `panos` must both populate
   `FIREWALL_POLICY` — this ADR's field realizability check is the second half of
   the ADR-0034 stability proof.

## Contracts / artifacts

- `VendorPlugin` subclass `fortios`; capability classes via `_capability_classes()`.
- httpx REST client (`vendors/fortios/client.py`) + netmiko SSH fallback path.

## Validation / Test & gate plan (ADR review)

- Repo ADR template; per-capability transport split table complete.
- **Cross-check W0-T1 + W0-T2**: every `FIREWALL_POLICY` field is populatable from
  FortiOS REST (and the PAN-OS set agrees) — divergence feeds back into ADR-0034.
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0036 written; status **Proposed**.
- [ ] REST-primary / SSH-fallback split fixed per capability; auth model recorded.
- [ ] `FIREWALL_POLICY` field realizability vs ADR-0034 confirmed across both vendors.
- [ ] VDOM scope decision recorded.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-implementer` writes ADR → `wf-spec-reviewer` + `wf-quality-reviewer` (sonnet)
→ `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Two-transport plugin is the most complex W2 build**: a vague primary/fallback
  split here becomes ambiguous code in W2-T2. Pin every capability to one
  transport (with the other as named fallback) in the ADR.
- **Cross-vendor field divergence** (PAN-OS has it, FortiOS doesn't, or vice
  versa) is exactly what the two-vendor rule exists to catch — surface it now, not
  after W1-T1 froze the model.
