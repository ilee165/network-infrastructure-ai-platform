# ADR-0026: Juniper JunOS Vendor Plugin

**Status:** Accepted | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

CLAUDE.md requires Juniper JunOS in the vendor matrix, and `PRODUCTION.md` §2.2 schedules it in **Vendor Wave 1 (P1)** as the second-largest route/switch install base — the first **non-Cisco CLI OS** the platform certifies. Its stated purpose in the wave is to *"exercise the normalized models against a non-Cisco syntax family, hardening vendor-agnosticism before firewalls"*: every capability JunOS implements must round-trip through the same `Normalized*` models (ADR-0006 §3) that three Cisco-shaped OSes and Arista EOS produced in Wave 0, with **no engine or agent change** (`PRODUCTION.md` §2 "zero engine changes" parity with ADR-0024). The Wave-1 capability set (`PRODUCTION.md` §2.2) is: **SSH/SNMP discovery, interfaces, routes, LLDP, BGP, OSPF, ACL (firewall filters → `NormalizedAclEntry`), config backup/restore/deploy**. CDP is absent — JunOS does not speak CDP.

ADR-0007 already pins JunOS to **netmiko** (`device_type="juniper_junos"`) for SSH/CLI with **ntc-templates (TextFSM)** parsing, and **pysnmp** for `DISCOVERY_SNMP`. ADR-0006 names the in-repo package `junos` under `app/plugins/vendors/`. ADR-0021 built the `CONFIG_RESTORE`/`CONFIG_DEPLOY` capability interfaces, the `ChangePlan`/`ChangeResult`/`RollbackResult` types, and the capture-before → apply → verify-after → structured-rollback contract — but only certified `cisco_ios`/`cisco_iosxe`/`eos`, explicitly deferring NX-OS/JunOS/PAN-OS to the production roadmap. This ADR extends ADR-0021 onto JunOS without contradicting it.

JunOS differs from the Wave-0 OSes in two ways that drive real decisions: (1) its CLI has a **first-class structured-output channel** (`| display json` / `| display xml`, and the RPC/NETCONF layer behind `jnpr.junos` PyEZ) — so unlike IOS we are *not* forced to screen-scrape; and (2) it has a **native transactional config model** — `candidate config` → `commit confirmed <minutes>` → automatic revert on timeout, plus addressable `rollback N` history — which is a strictly stronger rollback backing than the `cisco_iosxe`/`eos` commit-confirm that ADR-0021 §4 already leans on, and far stronger than classic IOS replay. This ADR is the **design gate**: implementation lands in P1 W1 against the conformance suite, live-lab **deferred-accepted** (no hardware; `P1-PLAN.md` §6, same posture as M4/M5/ADR-0024 §5).

## Decision

**The `junos` plugin implements the Wave-1 capability set over the ADR-0007 netmiko `juniper_junos` transport, collecting structured output via `| display json` (XML as fallback) parsed to the existing `Normalized*` models — not PyEZ. The config write path reuses the ADR-0021 `CONFIG_RESTORE`/`CONFIG_DEPLOY` interfaces and structured-rollback contract unchanged, but binds the rollback primitive to JunOS's native `candidate config + commit confirmed + rollback N` transaction — making JunOS the strongest commit-confirm platform in the matrix. Reads are raw-first recorded before parsing; writes execute only as the execution step of an `executing` ChangeRequest.**

### 1. Capability set and `vendor_id`

`vendor_id = "junos"`, `display_name = "Juniper JunOS"` (ADR-0006 §5 package list). Declared `capabilities` mirror the `CiscoIosPlugin` shape (one capability class per member, resolved by the registry), minus `NEIGHBORS_CDP`, plus nothing new — JunOS introduces **no new `Capability` enum member and no new normalized model**, which is the wave's vendor-agnosticism proof.

| Capability | Source command (raw-first recorded) | Parser target |
|---|---|---|
| `DISCOVERY_SSH` | `show version \| display json` | `DeviceFacts` |
| `DISCOVERY_SNMP` | system-MIB GET (sysDescr/sysObjectID/sysName) via pysnmp | `DeviceFacts` |
| `INTERFACES` | `show interfaces \| display json` | `NormalizedInterface` |
| `ROUTES` | `show route \| display json` | `NormalizedRoute` |
| `NEIGHBORS_LLDP` | `show lldp neighbors \| display json` | `NormalizedNeighbor` |
| `BGP` | `show bgp neighbor \| display json` | `NormalizedBgpPeer` |
| `OSPF` | `show ospf neighbor \| display json` | `NormalizedOspfNeighbor` |
| `ACL` | `show configuration firewall \| display json` (firewall **filters/terms**) | `NormalizedAclEntry` |
| `CONFIG_BACKUP` | `show configuration \| display set` (verbatim) | raw config text |
| `CONFIG_RESTORE` | candidate load + `commit confirmed` (§3) | `ChangeResult` |
| `CONFIG_DEPLOY` | candidate load + `commit confirmed` (§3) | `ChangeResult` |

Notes that shape the parsers (the "non-Cisco syntax family" hardening):

- **ACL ≠ Cisco access-lists.** JunOS expresses packet filtering as **firewall filters** composed of ordered **terms** (`from`/`then`). Each term maps to one or more `NormalizedAclEntry` rows (`PRODUCTION.md` §2.2 "firewall filters → `NormalizedAclEntry`"). This is the lowest-common-denominator approximation ADR-0006's negative anticipates; a term whose `then` is a non-permit/deny action (e.g. `count`, `policer`, `routing-instance`) is normalized as faithfully as the model allows and the divergence is noted in code, never silently dropped — the verbatim raw artifact remains authoritative.
- **`CONFIG_BACKUP` uses `| display set`,** not the hierarchical brace form, because set-style is line-oriented and idempotent to re-apply as configuration (parity of intent with `cisco_ios` using `show running-config`), and it is the form the restore/deploy path loads. The hierarchical and JSON forms are *display* projections; the set form is the settable one.
- **Routes:** `show route` JSON yields per-protocol entries; `NormalizedRoute` carries protocol/next-hop/prefix exactly as the Cisco parsers do, so the topology/discovery engines consume JunOS routes identically.

### 2. Structured output: `| display json` over PyEZ (`jnpr.junos`)

**Decision: collect structured output via the netmiko CLI session piped through `| display json` (with `| display xml` as the parse fallback); do not adopt `jnpr.junos` PyEZ.** Rationale, grounded in ADR-0007:

- ADR-0007 §Decision pins **one transport library per protocol family** and lists `junos` under **netmiko** deliberately, for the same reason every other CLI OS uses it: a single audited SSH dependency, blocking-I/O placed inside Celery workers (ADR-0007 §3). Adding PyEZ (which brings `ncclient`/NETCONF, paramiko, lxml, and a second device-session model) would create a **second transport stack** for one vendor — exactly the "per-vendor SDK sprawl" ADR-0007 alternative #3 rejected, and it inflates the single-image CVE surface (ADR-0007 negative) for thirteen vendors' worth of deployments that may never touch Juniper.
- The CLI **`| display json`** modifier gives us machine-parseable output *over the existing netmiko session* — we get structured data **without** screen-scraping `show` tables and **without** a new dependency. JSON is the primary parse target; **`| display xml`** is the fallback for the handful of commands whose JSON schema is unstable or absent across JunOS releases (parsers select per-command, recorded in the plugin's command table). This keeps JunOS *less* brittle than the Cisco TextFSM path while staying inside the ADR-0007 contract.
- **Raw-first is preserved and is the JSON/XML text itself.** Each capability records the verbatim `| display json` (or `xml`) response to `raw_artifacts` via `PluginCapability._record_raw(command, output)` (ADR-0006 §3, `plugins/base.py`) **before** `json.loads`/parse, so every normalized row re-derives from stored bytes — the audit guarantee is unchanged from the TextFSM plugins, only the parse step differs (JSON decode vs TextFSM).

`ntc-templates` (ADR-0007) remains the declared fallback for any command lacking a reliable `display json`/`xml` form, so the ADR-0007 toolchain statement holds; in practice JunOS structured output displaces most template parsing. **PyEZ is explicitly reserved** as a plugin-internal option *only* if a future capability needs an RPC with no CLI/`display` equivalent — and adopting it would amend ADR-0007 (alternative #3's escape hatch), not this ADR.

### 3. Config write path: native JunOS transaction backs the ADR-0021 contract

The ADR-0021 capability interfaces, `ChangePlan` gating, and capture → apply → verify-after → structured-rollback **state machine are reused verbatim** — `CONFIG_RESTORE` and `CONFIG_DEPLOY` on `junos` are new *implementations* of existing interfaces, exactly as ADR-0021 §4 already lists per-vendor rollback primitives in a table. JunOS just supplies the strongest primitive in that table.

#### 3.1 JunOS transaction maps onto ADR-0021's capture/apply/verify/rollback

| ADR-0021 step | `cisco_ios` (no commit-confirm) | **`junos` (this ADR)** |
|---|---|---|
| Capture-before baseline (§3) | `show running-config` snapshot | `show configuration \| display set` snapshot **and** note the live `rollback 0` point |
| Apply (§3) | `configure terminal` merge / `configure replace` | enter config mode → **load** into the **candidate** (`load merge`/`load override` set-form) → **`commit confirmed <N>`** |
| Dead-man auto-revert (§4) | armed EEM/kron or *guardrail* | **native `commit confirmed <N>`** — device auto-reverts the candidate to the prior committed config if not confirmed within N minutes |
| Verify-after (§3) | re-capture running config, assert end-state | re-capture `\| display set`, assert end-state predicate |
| Confirm / finalize | n/a (replay is the only net) | on verify-after success → **`commit check`-clean `commit`** (confirm) to make it permanent |
| Rollback on failure (§3) | replace/replay captured baseline | **`rollback N` to the captured baseline point → `commit`**, *or* simply let the unconfirmed `commit confirmed` time out |

- **`commit confirmed` is JunOS's first-class realization of ADR-0021 §4's dead-man auto-revert.** ADR-0021 §4 calls IOS-XE `configure replace ... configure confirm` and EOS commit-timer *"the strongest of the three"* and arms an EEM/kron dead-man on classic IOS precisely because *"a connectivity-breaking change auto-reverts even if the worker loses the session."* JunOS provides this **natively and unconditionally** — no EEM scripting, no image-capability check, no management-path guardrail (the ADR-0021 §4.2 classic-IOS-only fallback is **not needed on JunOS**). If the deploy/restore severs the management path, the worker simply never sends the confirming `commit`, and the device auto-rolls-back at the timeout. This closes, by construction, the single highest-blast-radius hole ADR-0021 had to special-case for classic IOS.
- **Restore success predicate (unchanged from ADR-0021 §3):** after the confirming commit, the re-captured `| display set` normalizes **equal** to the restored snapshot. **Deploy success predicate (unchanged):** the re-captured config contains every line of the applied fragment with no unintended residual diff outside the fragment's scope. Verify-after is the authoritative signal, not the `commit` return code (ADR-0021 §5).
- **Rollback success is an asserted equality, never an assumption (ADR-0021 §3):** after `rollback N` + `commit` (or after a `commit confirmed` timeout), the re-captured config must normalize **equal** to the captured baseline; if it does not, the result is `rollback_failed` → CR stays `failed` → operator alert — never reported as `rolled_back`. Because `rollback N` is a device-side atomic operation to a known-good committed point (not a line-by-line replay), JunOS does **not** suffer the classic-IOS "order-sensitive partial replay may not reproduce the baseline" risk (ADR-0021 §4 / negative) — the rollback target is the exact prior committed configuration.

#### 3.2 Mapping the ADR-0021 normalization / settable-form details to JunOS

- A `_normalize_config` equivalent operates on **`| display set` lines** (not IOS preamble): it unifies CR/LF, strips trailing whitespace, drops volatile/non-settable artifacts (e.g. the `## Last commit:` annotation header and any `version` timestamp line that changes every capture — the JunOS analogue of the `cisco_ios` "Building configuration..." / byte-count preamble that ADR-0021 §5 strips), and guarantees a single trailing newline, so a verify-after / rollback equality reflects a real config difference, not display noise. This keeps the M4 snapshot stored at backup time comparable to a fresh capture (ADR-0017 §1 parity).
- **Restore = `load override` of the snapshot set-text** (replace semantics: JunOS `load override`/`load replace` can remove device-only lines, the analogue of `cisco_ios` `configure replace`, which a merge cannot do — ADR-0021 §4). **Deploy = `load merge`** of the fragment (additive). Both land in the **candidate** and are realized only by `commit confirmed` → confirm.
- **`commit check` before `commit confirmed`** is run as a pre-apply validation: JunOS validates the candidate's syntactic/semantic integrity server-side. A `commit check` failure aborts before any device state changes (no candidate is committed), surfaced as a typed `PluginError` — a stronger pre-condition than the IOS path, which has no equivalent dry-run.
- **`_require_executing(plan)` is unchanged:** the capability refuses to run unless the `ChangePlan` attests an `executing` CR (ADR-0021 §2). A direct tool call outside the Automation-Agent CR executor is a typed `PluginError`; there is no second write path (ADR-0020 four-eyes spine preserved). The `payload` the approver reviewed is exactly what is loaded into the candidate — no re-render between approval and apply (ADR-0021 §2).

#### 3.2.1 Tracked gap: worker-crash during `commit confirmed` window leaves CR stuck in `executing`

JunOS is the first plugin to introduce an **autonomous device-side revert window** that can outlive a Celery worker crash. The ADR-0021 state machine (approved → executing → failed / rolled\_back) requires a **living worker** to drive every terminal transition; it has no heartbeat timeout, task-tombstone check, or reaper mechanism.

The stuck-state scenario:

1. The worker sends `commit confirmed <N>` and enters the verify-after step.
2. The Celery worker process dies (OOM, node eviction, pod restart, etc.) before verify-after completes — and therefore before the confirming `commit` or an explicit `rollback N` is issued.
3. The device **correctly auto-reverts** to its prior committed configuration at the `commit confirmed` timeout (the dead-man fires as designed — network is safe).
4. Because the worker is dead, **no code ever transitions the CR from `executing` to `failed` or `rolled_back`**. The CR is permanently stuck in `executing`, with the change register showing a live execution that is no longer running.

This is a **new failure mode unique to the JunOS plugin** among the currently-certified vendors: `cisco_ios` and `eos` have no autonomous revert window, so a dead worker leaves the device in whatever state the apply reached, but the CR state is the same kind of orphan — the gap is not new in principle but the JunOS auto-revert creates the additional ambiguity that the device is safe while the CR record disagrees.

**Resolution is deferred as a tracked gap** — it is out of scope for this ADR and P1 W1. A future ADR (or an amendment to ADR-0021) must specify one of the following reaper paths before any `executing` CR can be considered fully lifecycle-managed in production:

- **Celery task heartbeat + reaper worker:** each `CONFIG_DEPLOY`/`CONFIG_RESTORE` task emits periodic heartbeats; a reaper job queries Celery's result backend for tasks whose heartbeat has been absent for longer than `N + grace_seconds` and transitions any corresponding `executing` CR to `failed` (with a `system_reaped` flag in `metadata`).
- **CR-level deadline field:** `ChangeRequest` carries a `confirmed_deadline` timestamp set to `now + N*60 + grace_seconds` at the moment `commit confirmed <N>` is issued; a database-level scheduled job (pg\_cron or equivalent) transitions overdue `executing` CRs to `failed` when the wall-clock passes the deadline, regardless of worker state.
- **Task tombstone on startup:** on Celery worker start, scan `executing` CRs whose `updated_at` predates the current epoch by more than `N + grace_seconds`; emit a `worker_restart_reap` event and transition them to `failed` — a simpler but less timely variant of the heartbeat approach.

Until a reaper path is implemented and the relevant ADR is approved, the `commit confirmed` timeout window **`N`** should be configured conservatively short (the platform default is expected to be ≤ 2 minutes) to minimise the window in which a stuck `executing` CR misrepresents device state. Operators must be aware that a worker crash during this window will require manual CR triage via the admin API.

**References:** ADR-0021 §3 (state machine), ADR-0021 §4 (dead-man auto-revert per vendor), `P1-PLAN.md` §6 (deferred-accepted posture).

#### 3.3 Relationship to ADR-0024's structured-rollback inverse spec

ADR-0021 (config) and ADR-0024 (DDI) are two faces of the same structured-rollback principle: *the inverse of a mutation is captured structurally and verified after apply.* For config, ADR-0021's inverse is "restore the captured baseline"; JunOS realizes that inverse as **`rollback N` to the captured commit point**, the cleanest possible mapping (a single addressable inverse, not a re-create or a line replay). This ADR does **not** touch the DDI `ChangeRequestDraft` path (no `DDI_*` capability on `junos`); it extends the *config* structured-rollback of ADR-0021 only. No deviation from any D-decision: D6 (plugin shape), D7 (netmiko transport), D11/ADR-0020 (CR-gated writes, four-eyes, no secret logging) all hold exactly.

### 4. Credentials and secret hygiene

Device credentials come **only** from the encrypted vault (`device_credentials`, D11) via the credentials service as in-memory objects; the plugin receives a connected transport and **never reads the vault table, never logs a secret, and never returns one** (ADR-0007 §2, ADR-0011, ADR-0024 §2 posture). `ConnectionParams` carries a vault **reference** (`credential_ref`), never raw secret material (`plugins/base.py`). No example in this ADR inlines a token, password, or key. `raw_artifacts` store device *config and command output*, which for JunOS may contain hashed secrets in the config text (e.g. `$9$...` encrypted-password fields) exactly as the device emits them — these are stored verbatim for audit fidelity (they are already one-way-encrypted on-device and are part of the authoritative config), and the redaction-safe `_diff_summary` (ADR-0021 §3, line counts only) is what flows into a `ChangeResult`, never raw config text.

### 5. Conformance, coverage, and live-lab posture

- **Conformance suite (`PRODUCTION.md` §2.6, `P1-PLAN.md` §5):** every declared capability passes the M1 plugin conformance family — capability ⇒ interface ⇒ normalized model ⇒ **verbatim raw artifact** ⇒ docs ⇒ **≥80% coverage** (D16). The conformance harness drives the plugin through a **`FixtureReplayTransport`** stub (same machinery ADR-0024 §5 uses for SpatiumDDI), so no live device is required for the green suite.
- **Raw-first recording is tested:** each read capability test asserts that the verbatim `| display json`/`xml` (or `| display set`) output is recorded to `raw_artifacts` **before** parsing, and that the normalized rows **round-trip** (parse(raw) == expected normalized set) — the `PRODUCTION.md` §2.6 "raw output stored verbatim; normalized models round-trip" exit bullet.
- **Fixtures are source-derived JunOS structured output** (labeled `"source-derived, not live-recorded"` in each file header, ADR-0024 §5 convention): `show version`, `show interfaces`, `show route`, `show lldp neighbors`, `show bgp neighbor`, `show ospf neighbor`, and `show configuration firewall` JSON; plus a `| display set` config snapshot and a deploy/restore fixture pair exercising the `commit confirmed` → confirm path and a `rollback N` inverse. **Live-recorded fixtures are deferred to the opt-in live run** (no Juniper hardware in the lab — `P1-PLAN.md` §6 live-lab **deferred-accepted**).
- **Write-path tests** assert: (a) a write refuses outside an `executing` CR (`PluginError`); (b) verify-after success → confirming `commit`; (c) verify-after failure → `rollback N` + re-capture-equals-baseline → `rolled_back`, else `rollback_failed` (never silent); (d) `commit check` failure aborts before any committed state. These mirror the ADR-0021 `cisco_ios` certification tests (`PRODUCTION.md` §2.6 "write paths execute only via ChangeRequest; covered by integration tests").
- **No cross-vendor eval regression** (`PRODUCTION.md` §2.6, `P1-PLAN.md` W7): the M3 agent eval suite re-runs across all installed plugins including `junos` with no regression.

## Consequences

**Positive**
- JunOS is the **strongest commit-confirm platform in the matrix**: `commit confirmed` + `rollback N` give a *native, atomic, device-side* dead-man revert and a single-operation inverse — closing the classic-IOS reachability-loss hole (ADR-0021 §4.2) by construction, with **no management-path guardrail and no EEM scripting** needed.
- `| display json`/`xml` makes JunOS reads **less brittle than the Cisco TextFSM path** while adding **zero new dependencies** (still netmiko per ADR-0007), so the single-image CVE/maintenance surface does not grow for one vendor.
- Reusing the ADR-0021 interfaces, `ChangePlan` gating, and rollback state machine unchanged means `junos` is a drop-in second-family config-write vendor with **zero engine/agent change** — proving the normalized models and the write spine generalize off Cisco syntax (the explicit Wave-1 goal).
- A `commit check` dry-run gives JunOS a server-validated pre-apply gate the IOS path lacks, catching bad candidates before any committed state.

**Negative**
- JunOS **firewall filters/terms** do not map 1:1 onto `NormalizedAclEntry` (term actions like `count`/`policer`/`routing-instance` have no permit/deny analogue) — the normalized model stays lowest-common-denominator (ADR-0006 negative); the approximation is noted in code and the verbatim raw artifact remains authoritative.
- Choosing `| display json` over PyEZ means we forgo PyEZ's typed RPC ergonomics and depend on the **stability of per-command JSON schemas across JunOS releases** — mitigated by the `| display xml` fallback and ntc-templates as a last resort, and by raw-first storage making a parser fix a re-parse, not a re-collect.
- `commit confirmed` introduces a **timed window**: the executor must reliably send the confirming `commit` after verify-after, or a *successful* change auto-reverts at timeout — a new operational invariant (handled in the executor; the timeout N is a conservative `core/` config value, not hard-coded in the plugin) absent from the replay-based IOS path.
- Source-derived fixtures pin to current JunOS structured-output schemas; a JunOS upgrade may require refreshing them (the same maintenance tax ADR-0024 §5 accepts), and the `commit confirmed`/`rollback N` timing and the firewall-filter normalization edges stay unverified until the opt-in live run.

## Alternatives considered

1. **Adopt `jnpr.junos` (PyEZ) as the JunOS transport for structured RPC + NETCONF.**
   Rejected. PyEZ brings a second transport stack (`ncclient`/NETCONF + paramiko + lxml) for a single vendor, contradicting ADR-0007's one-library-per-protocol-family decision and reviving the per-vendor-SDK-sprawl ADR-0007 alternative #3 rejected (more CVE surface in the single image for every deployment). `| display json`/`xml` over the existing netmiko session yields machine-parseable output with no new dependency. PyEZ stays reserved as a plugin-internal escape hatch only for an RPC with no CLI/`display` equivalent — and adopting it would amend ADR-0007, not this ADR.

2. **Screen-scrape JunOS `show` tables with ntc-templates (TextFSM), matching the Cisco plugins exactly.**
   Rejected as the default. JunOS ships a first-class `| display json`/`xml` structured channel; ignoring it to TextFSM-parse human tables would make JunOS *more* brittle than necessary for no gain. ntc-templates is kept only as the fallback for commands lacking a reliable structured form (preserving the ADR-0007 toolchain statement), with JSON/XML as the primary target.

3. **Map the config write path to a generic line-merge + captured-baseline replay (mirror classic `cisco_ios`), ignoring `commit confirmed`/`rollback N`.**
   Rejected as a downgrade. It would discard JunOS's native transactional safety — the exact dead-man auto-revert ADR-0021 §4 had to *synthesize* on classic IOS via EEM/kron and gate behind a management-path guardrail. Using the native `commit confirmed` + addressable `rollback N` is strictly safer (atomic, device-side, no management-path restriction) and is the precise JunOS row of the ADR-0021 §4 vendor primitive table.

4. **Use `| display set | compare` / config diff to derive the applied/rollback diff instead of capture-then-normalize-equality verify-after.**
   Rejected as the verify-after authority. ADR-0021 §3/§5 makes the **re-captured end-state equality** the asserted, tested post-condition (and the symmetric rollback criterion), not the apply/diff return — a `commit` succeeding does not prove the intended end-state or continued reachability. JunOS `compare` output is recorded verbatim as useful evidence and feeds the redaction-safe diff summary, but the success/rollback predicates remain the normalized re-capture equality, identical in rigor to the certified `cisco_ios` path.

5. **Introduce a JunOS-specific normalized firewall model now (anticipating `FIREWALL_POLICY`).**
   Rejected for this wave. `PRODUCTION.md` §2.2 scopes JunOS ACL to **firewall filters → `NormalizedAclEntry`**, and `FIREWALL_POLICY` + its `NormalizedFirewallRule` (PROPOSED) are deliberately introduced in **Wave 2** by two firewall vendors (PAN-OS + FortiOS) so the firewall model is validated across vendors before being declared stable (`PRODUCTION.md` §2.3). Adding a Juniper-only firewall model here would pre-empt that cross-vendor validation and contradict ADR-0006's "extend the schema only via migration + review" discipline.

---

## Addendum — Wave 3 (2026-07-11): implementation gap closed (Option A)

**Status:** Accepted addendum (does not rewrite the Decision body above).

### Implementation gap that was closed

Prior to Wave 3, plugin docstrings and this ADR promised `load` → `commit confirmed <N>` → confirming `commit`, but production `SshTransport.send_config` only called netmiko `send_config_set` and `replace_config` issued Cisco `flash:`/`tclsh`/`configure replace` syntax. JunOS deploy/restore/rollback therefore never committed — the dead-man auto-revert cited as the safety control did not exist on the wire.

Wave 3 T1 lands `JunosSshTransport` (selected via `make_ssh_transport` when `device_type == juniper_junos` on the config write open path) implementing:

1. **Apply:** `configure` → `load merge|override terminal` → `commit check` → `commit confirmed <N>`
2. **Verify-after:** unchanged plugin re-capture + normalize equality (ADR-0021 §3)
3. **Confirm:** `confirm_config()` → confirming `commit` only on the verified success branch
4. **Failure:** confirming `commit` withheld; structured `replace_config`/`rollback N` primary; confirmed timer is the backstop

### Option A and the widened worker-crash window (§3.2.1)

Under Option A the unconfirmed device window spans **apply + verify-after + confirming commit**, not apply alone. Device fail-safe direction is unchanged (auto-revert at `N`). The CR-orphan gap in §3.2.1 is correspondingly wider and remains a tracked deferred reaper item.

`N` is `NETOPS_JUNOS_COMMIT_CONFIRMED_MINUTES` (default 2, bounds 1–60). Operators may increase it for large configs / slow control planes so the timer survives apply → verify-after → confirm.

### Protocol note

`ConfigWriteTransport.confirm_config()` is a typed surface: JunOS implements confirming `commit`; Cisco-family transports no-op so a shared lifecycle can always call it after verify without capability sniffing.
