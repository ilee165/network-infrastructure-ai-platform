# W2-T1 — `panos` Plugin (Palo Alto PAN-OS, XML API)

| | |
|---|---|
| **Wave** | P2 W2 — Vendor Wave 2 |
| **Owner** | `wf-implementer-light` (template-following: mirror the httpx-client plugin pattern — bluecat/infoblox/spatiumddi) |
| **Review tier** | sonnet spec + **strong** quality (credential hygiene / API-key leak surface) |
| **Depends on** | **W1-T1** (`FirewallPolicyCapability` + models); ADR-0035 (W0-T2) |
| **ADRs** | ADR-0035 (the plugin decision), ADR-0006 (contract, raw-first), ADR-0007 §D7 (httpx API transport), ADR-0011 (`credential_ref`), ADR-0034 (`FIREWALL_POLICY` models) |
| **PRODUCTION.md** | §2.3 (capability set), §2.6 (conformance + ≥80% cov + normalized round-trip) |
| **Status** | Done — `b6190df` (impl) + `7472803` (fix); 89% cov, conformance green, credential-hygiene green |

## Objective

Implement the **first firewall plugin** exactly as ADR-0035 decided: `panos`,
an httpx **XML-API** vendor plugin declaring `DISCOVERY_API`, `INTERFACES`,
`ROUTES`, `FIREWALL_POLICY`, `CONFIG_BACKUP`, `HA_STATUS` (PRODUCTION.md §2.3),
binding `FIREWALL_POLICY` to the W1-T1 models. One of the two independent
firewalls that validate `FIREWALL_POLICY` before it is declared stable (§2.3).

## Scope

**In** (`backend/app/plugins/vendors/panos/{__init__,plugin,client}.py`,
`backend/tests/plugins/test_panos_conformance.py`, unit tests, `pyproject.toml`
entry point)
- `PanosPlugin(VendorPlugin)` — `vendor_id="panos"`, capability set per §2.3, each
  mapped via `_capability_classes()` (mirror `BluecatPlugin`).
- `PanosClient` (XML API over httpx) mirroring `BamClient`/`WapiClient`: auth via a
  vault **API key** materialized from `ConnectionParams.credential_ref` (ADR-0011);
  **every response `_record_raw`'d verbatim before parse** (ADR-0006 §3).
- Capability classes: `DiscoveryApiCapability`, `InterfacesCapability`,
  `RoutesCapability`, **`FirewallPolicyCapability`** (→ `NormalizedFirewallRule` /
  `NormalizedNatRule`), `ConfigBackupCapability`, `HaStatusCapability`.
- Register under the `netops.plugins` entry-point group (`pyproject.toml`), exactly
  like the existing in-repo plugins (ADR-0006 §5).

**Out**
- `fortios` → **W2-T2** (disjoint files; runs in parallel).
- Config *write* paths (not in the §2.3 `panos` set).
- Security-Agent analysis over PAN-OS rules → **W3**.
- Any `FIREWALL_POLICY` model/ABC change → that is **W1-T1 / ADR-0034** (loop back
  if a field is unrealizable; do not patch locally).

## Requirements (grounded in ADR-0035, ADR-0006, ADR-0011, ADR-0034)

1. **XML API / httpx only** (D7): no SSH path for `panos`; blocking httpx runs in
   Celery workers, never on the event loop (ADR-0007 §3).
2. **Credential reference only** (ADR-0011): the API key is a vault reference; it
   is never logged, never in a normalized row, never in an exception message — the
   **strong quality review's focus**.
3. **Raw-first** (ADR-0006 §3): verbatim XML stored before parsing; every normalized
   row re-derivable.
4. **Binds to W1-T1 models** field-for-field (ADR-0034); no PAN-OS-specific shape
   crosses the plugin boundary (vendor extras via the ratified escape hatch only).
5. **Conformance + coverage** (PRODUCTION.md §2.6): passes the shared conformance
   families (incl. the W1-T1 firewall family); **≥80% coverage**; normalized
   round-trip green.

## Contracts / artifacts

- `PanosPlugin` + capability impls + `PanosClient`.
- `test_panos_conformance.py` instantiating the shared conformance families
  (mirror `test_bluecat_conformance.py`).
- `pyproject.toml` `netops.plugins` entry for `panos`.

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff (check + format), mypy strict, import-linter, pytest **≥80%** on the plugin.
- **Conformance suite green** for `panos` (all declared capabilities + the firewall
  family); raw-first asserted (each capability records verbatim before parse).
- **Round-trip**: parsed XML → `NormalizedFirewallRule`/`NormalizedNatRule` and the
  other normalized models serialize/deserialize equal.
- **Credential-hygiene tests**: API key never appears in logs / normalized output /
  raised exceptions (strong-review exit criterion).
- Plugin registry resolves `(panos, <capability>)`; `importlib` sees the new entry.
- **Live golden-path deferred-accepted** (no PAN-OS hardware) — code paths
  fixture/mock-verified; documented for W5-T3.

## Exit criteria

- [ ] `PanosPlugin` declares the §2.3 capability set; all mapped + registry-resolvable.
- [ ] `PanosClient` httpx XML-API; vault API key; raw-first on every call.
- [ ] `FIREWALL_POLICY` returns W1-T1 models field-for-field; escape hatch only for extras.
- [ ] Conformance green; **≥80% cov**; round-trip green.
- [ ] Credential-hygiene tests green (no key leak anywhere).
- [ ] Entry point registered; live golden-path deferred-accepted + documented.
- [ ] D16 gates green; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, credential-hygiene escalation)

`wf-implementer-light` implements → `wf-spec-reviewer` (sonnet) +
**`wf-quality-reviewer` (strong)** in parallel (credential-leak surface) →
`wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **API-key leak** via a logged request, an error string, or a normalized field —
  the strong quality review + the hygiene tests are the guard.
- **`FIREWALL_POLICY` field unrealizable from the XML API** — surfaces here; if so,
  it is an ADR-0034/W1-T1 fix, not a local hack (otherwise `fortios` and the agent
  bind to a divergent model).
- **No hardware** ⇒ golden path deferred-accepted; conformance + round-trip over
  recorded/fixture XML is the CI-level coverage.
