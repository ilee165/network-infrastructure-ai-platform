# W1-T1 — F5 BIG-IP plugin: `ADC_SERVICES` + archive capabilities + normalized models + `f5_bigip` + conformance fixtures

| | |
|---|---|
| **Wave** | P4 W1 — Vendor Wave 3 plugins |
| **Owner** | `wf-implementer` (strong) |
| **Review tier** | **strong** spec + quality (escalated: device-credential flow + UCS secret surface) |
| **Depends on** | **W0-T1** (ADR-0050, the contract) |
| **ADRs** | ADR-0050 (binding, field-for-field), ADR-0006/0007/0011/0017/0020/0021/0032/0040 |
| **PRODUCTION.md** | §2.4, §2.6, §11 G-SEC/G-MNT |
| **Status** | Proposed |

## Objective

Implement ADR-0050: the new **`ADC_SERVICES`** capability +
**`CONFIG_BACKUP_ARCHIVE`/`CONFIG_RESTORE_ARCHIVE`** pair (enum members, typed
ABCs, `NormalizedVirtualServer`/`NormalizedPool`/`NormalizedPoolMember` +
`ConfigArchive`/`ConfigArchiveRef` models, `AdcProtocol`/`AdcAvailability`/
`AdcAdminState` enums) and the **`f5_bigip`** plugin — plain-httpx iControl REST
client with token auth, `DISCOVERY_API`/`INTERFACES`/`ROUTES` (self-IPs +
route-domain→`vrf`)/`ADC_SERVICES`/`HA_STATUS`, and UCS backup as opaque secret
material with CR-gated restore — shipped against the conformance suite over
recorded fixtures.

## Scope

**In** — `base.py` additions (3 enum members, 3 ABCs per ADR-0050 §4.1/§7.1);
`normalized.py` models + enums (ADR-0050 §4.2–§4.4 field-for-field);
`plugins/vendors/f5_bigip/` (`client.py` with `$top`/`$skip` paging, token
lifecycle + revocation, redaction filter covering password + token;
`plugin.py`); `config_archives` table (expand-only migration) + double envelope
encryption + per-backup vault passphrases (ADR-0050 §7.2/§7.3); archive restore
via approved CR with baseline-first, never-silent rollback (§7.4);
`_INTERFACE_SPECS` entries for all new capabilities (the three-file lesson,
§4.7); recorded-fixture set incl. every mandatory case (§8); secret-leak
assertions (password, token, passphrase); live golden-path script
(ready-to-run, deferred-accepted); plugin + API docs.

**Out** — inventory API/UI (W1-T3); W2 derivation; archive download endpoint
(named deferral); F5 text-config drift/compliance (ADR-0050 §7.6, named
deferral); AFM/`FIREWALL_POLICY`.

## Requirements (grounded in ADR-0050)

1. **Field-for-field model fidelity** — the §4.3 tables are the W2 derivation
   contract; no extra fields, no `vendor_attributes`.
2. **Raw-first** — every collection page recorded verbatim via `_record_raw`
   before parsing; login/token and UCS binary bodies NEVER raw-recorded.
3. **Zero plaintext leakage** — password, token, and UCS passphrase appear in
   no log record, raw artifact, exception message, or `repr` (asserted).
4. **Restore refuses without an approved CR** (typed `PluginError`);
   `rollback_failed` surfaced, never reported as `rolled_back` (ADR-0021).
5. **Route domains** — `%<id>` stripped before IP parsing, id carried as `vrf`
   (`"0"` → `None`) on routes, VIPs, and members alike.
6. **Conformance wiring complete** — without the `_INTERFACE_SPECS` entries the
   fixture cases silently skip (ADR-0025 §8); their presence is an exit
   criterion, not an assumption.

## Contracts / artifacts

- New capability surface in `base.py`/`normalized.py`; `f5_bigip` plugin +
  entry point; `config_archives` migration; `test_f5_bigip_conformance.py` +
  fixtures; golden-path script; docs.

## Test & gate plan

- Full gate suite: `pytest` (conformance green incl. `fixtures:adc_services`,
  `fixtures:config_backup_archive`), `ruff check` + `ruff format --check`,
  `mypy`, `lint-imports`; coverage ≥80% on the plugin module (D16).
- Mandatory fixture cases: multi-page collection; route-domain-suffixed
  addresses; FQDN-node member; VS without default pool; empty pool;
  `forced_offline` member; standalone `HA_STATUS`; UCS control-plane JSON
  sequence (synthetic binary blob).
- Secret-leak test set extended to the two new secrets (token, passphrase).
- `tests/pg/` coverage where PG semantics bind (archive table + encryption
  round-trip under `pg-integration`).
- Existing cross-vendor suite shows no regression (full re-run is W4-T1).

## Exit criteria

- [ ] Conformance suite green over recorded fixtures; raw payloads stored verbatim; normalized models round-trip.
- [ ] All three `_INTERFACE_SPECS` entries present (no silently-skipped fixture family).
- [ ] Zero-plaintext-leakage assertions green (password/token/passphrase).
- [ ] Archive restore CR-gated with baseline rollback; write path covered by integration tests.
- [ ] `config_archives` expand-only migration; metadata-only API surface (no download endpoint).
- [ ] Coverage ≥80%; plugin + API docs published; golden path shipped + named deferred-accepted → live lab.
- [ ] One atomic commit.

## Workflow

`wf-implementer` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Sibling bug classes** (pagination, fixture handling, empty-result) — W1-T2
  is built in parallel; a class fix here is swept there in the same commit.
- **UCS passphrase lifecycle** — a leaked passphrase or an orphaned vault row
  breaks the pair-is-atomic invariant; deletion couples archive + vault row.
- **Token in percent-encoded form** slipping the redaction filter — the filter
  covers literal AND percent-encoded forms of both secrets.
