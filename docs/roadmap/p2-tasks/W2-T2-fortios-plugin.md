# W2-T2 — `fortios` Plugin (Fortinet FortiOS, REST + SSH fallback)

| | |
|---|---|
| **Wave** | P2 W2 — Vendor Wave 2 |
| **Owner** | `wf-implementer-light` (template-following: httpx-client + netmiko-fallback patterns both already in-repo) |
| **Review tier** | sonnet spec + **strong** quality (credential hygiene — REST token + SSH login leak surface) |
| **Depends on** | **W1-T1** (`FirewallPolicyCapability` + models); ADR-0036 (W0-T3) |
| **ADRs** | ADR-0036 (the plugin decision), ADR-0006 (contract, raw-first), ADR-0007 §D7 (httpx REST + netmiko SSH), ADR-0011 (`credential_ref`), ADR-0034 (`FIREWALL_POLICY` models) |
| **PRODUCTION.md** | §2.3 (capability set), §2.6 (conformance + ≥80% cov + normalized round-trip) |
| **Status** | Proposed |

## Objective

Implement the **second firewall plugin** exactly as ADR-0036 decided: `fortios`,
a **REST (httpx) primary + netmiko SSH fallback** plugin declaring
`DISCOVERY_API`, `INTERFACES`, `ROUTES`, `FIREWALL_POLICY`, `CONFIG_BACKUP`,
`HA_STATUS` (§2.3). This is the plugin that **proves `FIREWALL_POLICY` is
vendor-neutral** — two independent firewalls populating the same model (§2.3).
Runs **parallel to W2-T1** (disjoint files).

## Scope

**In** (`backend/app/plugins/vendors/fortios/{__init__,plugin,client}.py` + SSH
fallback path, `backend/tests/plugins/test_fortios_conformance.py`, unit tests,
`pyproject.toml` entry)
- `FortiosPlugin(VendorPlugin)` — `vendor_id="fortios"`, §2.3 capability set via
  `_capability_classes()`.
- `FortiosClient` (REST over httpx) mirroring `BamClient`/`WapiClient`; **netmiko
  SSH (`fortinet`) fallback** (reuse the ADR-0007 transport) for the capabilities
  ADR-0036 assigned to SSH. **Per-capability transport split exactly per ADR-0036**
  — no capability served by a transport the ADR didn't assign it.
- Auth: REST **API token** and SSH **login** both from vault `credential_ref`
  (ADR-0011). Raw-first on **both** transports (ADR-0006 §3).
- Capability classes: `DiscoveryApiCapability`, `InterfacesCapability`,
  `RoutesCapability`, **`FirewallPolicyCapability`** (→ `NormalizedFirewallRule` /
  `NormalizedNatRule`), `ConfigBackupCapability`, `HaStatusCapability`.
- Entry-point registration (`netops.plugins`).

**Out**
- `panos` → **W2-T1** (parallel, disjoint).
- Config write paths (not in the §2.3 `fortios` set).
- Security-Agent analysis → **W3**.
- Any model/ABC change → **W1-T1 / ADR-0034** (loop back, no local patch).

## Requirements (grounded in ADR-0036, ADR-0006, ADR-0011, ADR-0034)

1. **REST-primary, SSH-fallback per ADR-0036**: each capability uses the transport
   the ADR assigned; a fallback that is never reachable is dead code — remove or
   justify. Blocking calls (httpx + netmiko) run in Celery workers.
2. **Credential reference only** (ADR-0011) for both REST token and SSH login;
   neither logged / normalized / raised — **strong quality review's focus**.
3. **Raw-first on both transports** (ADR-0006 §3).
4. **Binds to W1-T1 models** field-for-field (ADR-0034); the cross-vendor
   agreement with `panos` is the stability proof — flag any field FortiOS cannot
   fill that PAN-OS can (or vice versa).
5. **Conformance + ≥80% cov + round-trip** (§2.6).

## Contracts / artifacts

- `FortiosPlugin` + capability impls + `FortiosClient` (REST) + SSH fallback path.
- `test_fortios_conformance.py` (shared families incl. firewall family).
- `pyproject.toml` `netops.plugins` entry for `fortios`.

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff / mypy strict / import-linter / pytest **≥80%** on the plugin.
- **Conformance green** for `fortios` (all declared capabilities + firewall family);
  raw-first asserted on both transports.
- **Round-trip** for all normalized models, incl. firewall/NAT.
- **Two-vendor cross-check**: `fortios` + `panos` populate the *same*
  `NormalizedFirewallRule` fields from real fixture data — the §2.3 stability
  evidence (record any divergence for W1-T1/ADR-0034).
- **Credential-hygiene tests** (REST token + SSH password) green.
- Registry resolves `(fortios, <capability>)`; live golden-path **deferred-accepted**.

## Exit criteria

- [ ] `FortiosPlugin` declares §2.3 set; per-capability transport split per ADR-0036.
- [ ] REST + SSH-fallback both vault-credentialed, raw-first; no dead fallback.
- [ ] `FIREWALL_POLICY` returns W1-T1 models field-for-field; cross-vendor agreement
      with `panos` demonstrated (or divergence raised to ADR-0034).
- [ ] Conformance green; **≥80% cov**; round-trip green; credential-hygiene tests green.
- [ ] Entry point registered; live golden-path deferred-accepted + documented.
- [ ] D16 gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, credential-hygiene escalation)

`wf-implementer-light` implements → `wf-spec-reviewer` (sonnet) +
**`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings →
`wf-verifier` → **one atomic commit**.

## Risks

- **Two-transport complexity** (REST + SSH) is the hardest W2 build: an ambiguous
  split (already pinned in ADR-0036) or a leaked SSH password are the live risks —
  the ADR + strong review + hygiene tests mitigate.
- **Cross-vendor field divergence** is exactly what this task exists to expose;
  surface it to W1-T1/ADR-0034 rather than silently filling/nulling.
