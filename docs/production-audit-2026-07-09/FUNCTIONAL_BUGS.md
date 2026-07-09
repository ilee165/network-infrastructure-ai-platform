# Functional Bugs & Correctness Findings

Production readiness audit, 2026-07-09 (HEAD `5403c3b`). Severity: Critical / High / Medium / Low. Effort: S / M / L / XL.

---

## 1. F5 / VMware plugins are not wired into live discovery collection

- **Severity:** High (feature incomplete / vertical integration)
- **Location:** `backend/app/workers/tasks/discovery.py:448–463` (SSH + SNMP only); `backend/app/engines/discovery/engine.py` (transport map); `backend/app/models/adc.py:15–21` (documents named deferral); virt inventory models (same pattern)
- **Root cause:** Production `collect_device` materializes only `CredentialKind.SSH` / SNMP and runs `_collect_over_ssh` / `_collect_over_snmp`. There is no API/HTTPS/iControl/vSphere collection path. Plugin packages, conformance fixtures, ADC/virt tables, and UI pages ship, but **live runs never populate** `adc_*` / virtualization rows from devices.
- **User impact:** ADC and Virtualization pages stay empty unless rows are hand-inserted/seeded. P4 W1 is plugin-complete, not ops-complete.
- **Proposed fix:** Introduce API credential kind (or documented param shape), `_collect_over_api` building `F5Client` / `VsphereClient`, extend `DeviceCollectionResult` + persistence for `ADC_SERVICES` / virtualization inventory, feature-flag until green. Strong-model review (secret surface).
- **Effort:** L | **Risk of fix:** Medium

---

## 2. Application-dependency derivation and impact stay empty without collection + DNS

- **Severity:** High (feature incomplete; depends on #1)
- **Location:** `backend/app/workers/tasks/topology.py` (ADC/virt fetch + DNS hard-return); derivation store / applier / Neo4j projector (implemented and tested)
- **Root cause:** Derivation, projection, impact API/agent tool, and manual tagging are complete. Production step 0 has empty ADC/virt tables and DNS fetch is not composed. Impact answers under-report real dependents.
- **User impact:** Operators using Applications / impact tools see mostly manual tags only; automated F5/VMware/DNS sources do not fire.
- **Proposed fix:** Block on #1; wire DDI DNS record read into derivation; add an integration gate that fails if derivation sources are permanently empty when plugins are enabled (or document “manual-only mode” in UI).
- **Effort:** L (blocked on #1) | **Risk:** Low once data exists

---

## 3. F5 token revocation puts session token in the URL path

- **Severity:** Medium (secret hygiene / doc contract break)
- **Location:** `backend/app/plugins/vendors/f5_bigip/client.py` (DELETE `/mgmt/shared/authz/tokens/{token}`); docs claim secrets never appear in URLs
- **Root cause:** iControl revoke API shapes the token into the path. `_SecretRedactFilter` mitigates httpx logger leakage; proxies or access logs outside that filter can still see the path.
- **Proposed fix:** Prefer body/header revoke if available; otherwise document residual risk and ensure all logging stacks redact path secrets.
- **Effort:** S–M | **Risk:** Low

---

## 4. F5 UCS archive: plugin complete, operational path incomplete

- **Severity:** Medium
- **Location:** `backend/app/plugins/vendors/f5_bigip/plugin.py` (backup/restore + CR gate); no worker/automation path for `CONFIG_BACKUP_ARCHIVE` / restore end-to-end
- **Root cause:** Capability implementation + CR refuse-before-I/O exist; Celery/automation executor + PassphraseVault materialization for live ops are not closed.
- **Proposed fix:** Worker tasks + vault-backed passphrase + Automation Agent executor under existing ChangeRequest lifecycle.
- **Effort:** L | **Risk:** High secret surface — strong model

---

## 5. F5 `upload_ucs` bypasses unified auth-retry

- **Severity:** Medium
- **Location:** `f5_bigip/client.py` upload path vs `_request` with 401 re-auth
- **Root cause:** Binary upload uses raw client post; mid-session 401 fails restore hard.
- **Proposed fix:** Share auth+retry helper for binary bodies.
- **Effort:** S | **Risk:** Low

---

## 6. F5 interfaces / routes / self-IPs not paged

- **Severity:** Medium
- **Location:** `f5_bigip/client.py` single-GET helpers vs paged virtuals/pools
- **Root cause:** Large devices may truncate inventory → wrong topology/impact.
- **Proposed fix:** Use collection paging for net/interface, net/route, net/self.
- **Effort:** S | **Risk:** Low

---

## 7. Application DELETE makes If-Match optional

- **Severity:** Medium (concurrency)
- **Location:** `backend/app/api/v1/applications.py:402–432` (PATCH requires If-Match; DELETE does not)
- **Root cause:** Documented intentional difference; non-UI clients can lost-delete under concurrent editors. Frontend usually sends version.
- **Proposed fix:** Require If-Match for DELETE (parity with PATCH) or codify OpenAPI + client contract as intentional.
- **Effort:** S | **Risk:** Low

---

## 8. Impact residual: IP co-key under-reports multi-homed dependents

- **Severity:** Medium (product correctness, partially documented)
- **Location:** `backend/app/knowledge/topology_read.py` (depth + IP binding)
- **Root cause:** IP-bound dependents only surface when winning interface is within physical depth; shared-IP / multi-homed cases under-report.
- **Proposed fix:** Product copy on API; optional second hop / HAS_IP edges with tests.
- **Effort:** M | **Risk:** Semantics change

---

## Baseline items — re-verified CLOSED

| # | Prior finding | Evidence |
|---|---|---|
| B1 | Live troubleshooting reads “not yet wired” | `tools.py` transport path; `test_troubleshooting_live_reads.py` sentinel pin |
| B2 | WS fan-out relay race | `agents.py` relay; idle-drain + cross-replica tests green |
| B3 | Redis not closed on shutdown | `main.py` `aclose()`; `test_shutdown_closes_shared_redis_client` |
| B4 | Frontend refresh single-flight | Present (prerequisite for reuse detection) |
| B5 | Packet default-OFF | ADR-0049; compose/Helm default on; bite-proof job |

---

## Verified non-findings (checked, clean)

- No bare `except:` in application Python.
- Troubleshooting live tools no longer return the M5 sentinel (only test pin mentions the string).
- ChangeRequest four-eyes / no self-approve intact.
- Credential vault envelope + scope deny + redacted decrypt surfaces intact.
- OIDC PKCE / asymmetric algs / nonce-iss-aud checks intact.
- Packet executor-split confinement + CR gate on F5 restore refuse-before-I/O.
- Application PATCH If-Match + `FOR UPDATE` + PG concurrency tests.
- Derivation applier rules (manual-wins, derived lifecycle) covered by unit + PG tests.
- Zero Critical defects found in this pass.
