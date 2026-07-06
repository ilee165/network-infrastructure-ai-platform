# F5 BIG-IP plugin (`f5_bigip`)

The platform's first **ADC** vendor plugin: a plain-`httpx` iControl REST client
(no third-party F5 library) that discovers device identity, interfaces, routes,
the ADC service topology (virtual servers / pools / members), HA state, and
takes/restores full-fidelity **UCS** config archives as secret-bearing binary
material. Design gate: **ADR-0050**. Build: **P4 W1-T1**.

## Capabilities

| Capability | iControl REST source | Normalized return |
|---|---|---|
| `DISCOVERY_API` | `GET /mgmt/tm/sys/version` + `/mgmt/tm/sys/global-settings` | one `NormalizedDiscoveredObject` (`kind=OTHER`) / `DeviceFacts` |
| `INTERFACES` | `GET /mgmt/tm/net/interface` | `list[NormalizedInterface]` |
| `ROUTES` | `GET /mgmt/tm/net/route` (static) + `/mgmt/tm/net/self` (connected) | `list[NormalizedRoute]` — route domains → `vrf` |
| `ADC_SERVICES` **(new)** | `GET /mgmt/tm/ltm/virtual` + `/mgmt/tm/ltm/pool?expandSubcollections=true` | `list[NormalizedVirtualServer]` / `list[NormalizedPool]` (nested `NormalizedPoolMember`) |
| `HA_STATUS` | `GET /mgmt/tm/cm/failover-status` + `/mgmt/tm/cm/sync-status` | `list[NormalizedHaStatus]` |
| `CONFIG_BACKUP_ARCHIVE` **(new)** | `POST /mgmt/tm/sys/ucs` (save) + `/mgmt/shared/file-transfer/ucs-downloads/` | `ConfigArchive` (secret-bearing) |
| `CONFIG_RESTORE_ARCHIVE` **(new)** | upload + `POST /mgmt/tm/sys/ucs` (load) | `ChangeResult` — **CR-gated only** |

No text `CONFIG_BACKUP`/`CONFIG_RESTORE` and no `FIREWALL_POLICY` (AFM out of
scope). F5 text-config drift/compliance is a **named deferral** (ADR-0050 §7.6):
the shell-escape endpoints are rejected on security grounds, so F5 shows as
out-of-scope (not passing) in the compliance-posture report until a supported
non-shell text export is validated.

## Connection & credentials

Token-based auth is the only steady-state mode (ADR-0050 §2). The device's
vault `credential_ref` materializes a username/password in-process; the client
POSTs them once to `/mgmt/shared/authn/login` (with a configurable
`loginProviderName`, default `tmos` — override for RADIUS/TACACS+/LDAP service
accounts) and carries the returned `X-F5-Auth-Token` on every subsequent
request. A 401 triggers a single re-auth + retry (no pre-emptive token-timeout
raise — least privilege); on session close the token is best-effort **revoked**.

- Secrets travel in headers / POST bodies, **never** in a URL (literal or
  percent-encoded).
- The password and live token are held name-mangled with no leaking `repr`; a
  per-instance redaction filter on the `httpx` logger drops any record
  containing either secret in literal or percent-encoded form.
- Collections are read with `$top`/`$skip` paging; every page body is recorded
  verbatim (`_record_raw`) before parsing. The login/token exchange and the UCS
  **binary** body are never raw-recorded.

**Least-privilege note:** the read capabilities work with a low-privilege F5
role, but UCS create/download/load require an **administrator-role** account (an
F5 RBAC constraint). Use a dedicated service account; a lower-privilege device
still serves every read capability, with the archive capabilities failing with a
typed `PluginError`.

## Route domains → `vrf`

F5's route-domain suffix (`%<id>`, e.g. `10.1.1.1%2`) maps to the house `vrf`
field. The `%<id>` is stripped before IP parsing and the id carried as `vrf`
(`"0"` → `None`) on routes, self-IP networks, virtual-server VIP addresses, and
pool-member addresses alike — two identical addresses in different route domains
are different endpoints and are never collapsed.

## UCS config archive (secret surface)

A UCS archive is the total device backup: it contains credentials, password
hashes, **SSL/TLS private keys**, and device master-key material. It is opaque
secret material end-to-end (ADR-0050 §7):

- **Backup** (`CONFIG_BACKUP_ARCHIVE`, a read) mints a fresh high-entropy
  per-backup passphrase (stored in the credential vault, referenced by
  `passphrase_ref`), saves the UCS **passphrase-encrypted on the box before it
  crosses the wire**, downloads it, deletes the on-box residue, and returns a
  `ConfigArchive` — `content` is `SecretBytes` (masked in `repr`/serialization),
  `sha256` is the digest of the encrypted archive, and `passphrase_ref` is a
  vault reference (never the passphrase).
- **At rest** the archive is **double-encrypted**: the persistence service
  (`app.services.config_archives`) envelope-encrypts the already-encrypted bytes
  a second time under a per-archive DEK wrapped by the ADR-0032 KMS-backed KEK,
  AAD-bound to the archive row id, into the `config_archives` table. Reading the
  DB alone yields double-encrypted bytes; the vault passphrase row **and** the
  KEK are both required to reconstruct a usable UCS. The archive row and its
  vault passphrase row are an atomic pair.
- **API surface is metadata-only** (id, device, timestamps, size, sha256).
  **There is no download endpoint in P4** — the only consumer of archive bytes
  is the CR-gated restore path, minimizing the exfiltration surface to zero HTTP
  endpoints. A future operator-download need is a follow-up ADR behind admin
  RBAC + step-up audit.
- **Redaction:** archive bytes appear in no log line, `repr`, exception, task
  result, or API response; the passphrase never leaves the vault.

## Restore (CR-gated, never-silent rollback)

`CONFIG_RESTORE_ARCHIVE` is the device-write path and **never self-authorizes**:
`restore_archive()` refuses (typed `PluginError`) unless the `ChangePlan` attests
an `executing`, four-eyes-approved ChangeRequest — **before any device call**.
The sequence (ADR-0050 §7.4):

1. capture a fresh pre-change **baseline** UCS (the rollback artifact);
2. upload + load the target archive under its vault-materialized passphrase;
3. **verify-after**: management API reachable + DSC failover not degraded
   (byte-equality verify-after is impossible — UCS saves are not byte-stable);
4. on verify failure, load the baseline and verify it; `rollback_failed` is
   surfaced, **never** reported as `rolled_back` (ADR-0021 never-silent contract).

The `ChangeResult` carries metadata only (archive ids, sha256s, verify outcomes)
— never contents, never a diff. **Blast radius:** a UCS load restarts BIG-IP
services (traffic interruption; on an HA pair it can force a failover and
overwrite device-trust/ConfigSync state) — the generated CR description names
this so the human approver approves the outage, not just the change.

## Fixtures, tests, live path

- Conformance runs over recorded iControl REST JSON fixtures
  (`tests/plugins/test_f5_bigip_conformance.py`), covering the mandatory cases:
  multi-page collection, route-domain-suffixed addresses, FQDN-node member, VS
  with no default pool, empty pool, `forced_offline` member, standalone
  `HA_STATUS`, and the UCS save/download/delete control-plane sequence over a
  synthetic binary blob. Zero-plaintext-leakage is asserted for the password,
  token, passphrase, and archive bytes.
- The at-rest double-envelope round-trip is re-asserted under real PostgreSQL in
  `tests/pg/test_config_archives_pg.py` (CI `pg-integration` job).
- The live golden path (discover → ADC inventory → UCS backup → CR-approved
  restore against a real/virtual BIG-IP) ships ready-to-run in
  `tests/agents/eval/test_f5_bigip_live_golden_path.py` — **deferred-accepted →
  live lab**, collected-but-skipped in CI (env-var gated); the destructive
  restore step is additionally behind an explicit opt-in flag.
