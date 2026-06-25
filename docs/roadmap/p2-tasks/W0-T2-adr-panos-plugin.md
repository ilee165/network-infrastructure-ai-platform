# W0-T2 — ADR-0035 Palo Alto PAN-OS Vendor Plugin (XML API)

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet spec + sonnet quality (design record; credential-hygiene *implementation* is reviewed strong in W2) |
| **Depends on** | W0-T1 (cites `FIREWALL_POLICY` model + ABC) |
| **ADRs** | ADR-0006 (plugin contract), ADR-0007 §D7 (API-first transport, httpx), ADR-0011 (credential vault `credential_ref`), ADR-0034 (the model it binds to) |
| **PRODUCTION.md** | §2.3 (`panos`: `DISCOVERY_API`, interfaces, routes, `FIREWALL_POLICY`, ACL/NAT visibility, config backup, `HA_STATUS`) |
| **Status** | Proposed |

## Objective

Decision record for the **first firewall plugin**: ship `panos` as an
**httpx XML-API** plugin (D7 API-first), declaring the PRODUCTION.md §2.3
capability set and binding `FIREWALL_POLICY` to the ADR-0034 model. This is the
design gate; the build is **W2-T1**.

## Scope

**In**
- **Transport decision:** PAN-OS **XML API over HTTPS via httpx** (mirroring the
  bluecat/infoblox/spatiumddi httpx-client pattern), not SSH. State why
  (API-first per D7; the XML API is the supported management surface).
- **Auth model:** PAN-OS **API key** materialized from the vault via
  `ConnectionParams.credential_ref` (ADR-0011) — never inlined, never logged.
- **Capability map** (one row per declared capability → XML API request →
  normalized return), per PRODUCTION.md §2.3: `DISCOVERY_API`, `INTERFACES`,
  `ROUTES`, `FIREWALL_POLICY` (security rules + NAT → `NormalizedFirewallRule` /
  `NormalizedNatRule`), `CONFIG_BACKUP` (config export), `HA_STATUS`.
- **Running vs candidate config** decision for `CONFIG_BACKUP` (which the backup
  captures and why); **multi-vsys/Panorama** handling — decided or explicitly deferred.
- **Raw-first** (ADR-0006 §3): verbatim XML stored before parse.

**Out**
- Implementation + conformance + ≥80% cov → **W2-T1**.
- Config *write* paths (`CONFIG_RESTORE`/`CONFIG_DEPLOY`) — not in the §2.3 set
  for `panos`; out unless the ADR explicitly scopes them in.
- Security-Agent analysis of PAN-OS rules → **W0-T4 / W3**.

## Requirements (grounded in ADR-0006, ADR-0007 §D7, ADR-0011, ADR-0034)

1. **API-first transport** (D7): httpx XML API client; netmiko/SSH is **not** the
   PAN-OS path. Concurrency: blocking httpx calls run in Celery workers, never on
   the event loop (ADR-0007 §3 posture).
2. **Credential reference only** (ADR-0011): the API key is a vault `credential_ref`;
   the plugin receives a reference, the credentials service materializes in-process.
3. **Binds to ADR-0034**: `FIREWALL_POLICY` returns the W0-T1 normalized models —
   no PAN-OS-specific shape leaks past the plugin boundary.
4. **Two-vendor validation contract**: this plugin + `fortios` (W0-T3) must both
   populate `FIREWALL_POLICY` before the interface is declared stable
   (PRODUCTION.md §2.3) — note the dependency on W0-T3's field realizability.

## Contracts / artifacts

- `VendorPlugin` subclass `panos` declaring the §2.3 capability set; capability
  classes mapped via `_capability_classes()` (ADR-0006 §6).
- httpx XML-API client (new `vendors/panos/client.py`), mirroring existing
  httpx-client plugins.

## Validation / Test & gate plan (ADR review)

- Repo ADR template; capability-map table complete; each capability cites its XML
  API request shape.
- **Cross-check W0-T1**: every `FIREWALL_POLICY` field is populatable from the
  PAN-OS XML API (flag any field that is not — feeds back into ADR-0034).
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0035 written; status **Proposed**.
- [ ] Transport (XML API/httpx), auth (vault API key), capability map fixed.
- [ ] `FIREWALL_POLICY` field realizability vs ADR-0034 confirmed (or feedback raised).
- [ ] Config-backup running/candidate + multi-vsys/Panorama decision recorded.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-implementer` writes ADR → `wf-spec-reviewer` + `wf-quality-reviewer` (sonnet)
→ `wf-fixer` if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **XML-API field gaps**: a `NormalizedFirewallRule` field PAN-OS cannot fill
  means ADR-0034 over-specified — caught here by the realizability cross-check,
  cheaper than discovering it mid-W2.
- **Panorama vs firewall-local policy** scope creep; decide the boundary in the
  ADR so W2-T1 has no open question.
