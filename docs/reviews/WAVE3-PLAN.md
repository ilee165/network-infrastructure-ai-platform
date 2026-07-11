# Wave 3 Implementation Plan — Config-Write Transport

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source findings:
[`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) C2/C3/H7/H8,
[`AR1-REMEDIATION-PLAN.md`](AR1-REMEDIATION-PLAN.md) AR-W2-T1.

**This entire wave is a change-safety / secret-adjacent surface.** Every task
runs on the STRONG model, pinned explicitly (never "inherit") — the config
write/rollback path is the mechanism the platform uses to touch live network
devices, and its failure mode is a broken safety net during an incident.
Dual review (quality + spec) per task, as with prior secret-surface work.

**Shape:** one branch (`fix/review-wave3`), one PR. T1–T3 are correctness
fixes on the transport; T4 is the `cli_common` extraction refit, one vendor
per atomic commit. T1–T3 land **before** T4 begins so the extraction refit
carries the corrected behavior, not the bugs.

**Scope guard:** no new vendor capabilities; no touching the deterministic
firewall engine or DDI plugins; the agent read-facade (AR-W2-T2) is Wave 6.
Wave must land before any new CLI vendor is added (P4 vendor waves).

---

## T1 — C2: JunOS config writes are no-ops (CRITICAL)

`backend/app/plugins/vendors/junos/plugin.py:383-403` +
`backend/app/plugins/transport/ssh.py:190-259`.

**Problem.** Plugin docstrings — and ADR-0026's justification for skipping the
management-path guardrail — promise `load merge` → `commit confirmed <N>` →
confirming `commit`, "driven by the transport's `send_config`". Reality:
`SshTransport.send_config` only calls netmiko `send_config_set`; **no commit
exists anywhere in the file**, and `replace_config` sends Cisco-only syntax
(`flash:`, `tclsh`, `configure replace`) that does not exist on JunOS. Every
JunOS deploy/restore/rollback never commits; the dead-man auto-revert cited as
the safety control does not exist.

**Fix.** Dedicated JunOS `ConfigWriteTransport`:
- `send_config`: `load merge` (or `load override` for full replace) →
  `commit confirmed <N>` → verification → confirming `commit`.
- `replace_config`: `load override` + the same confirmed-commit flow.
- Inverse/rollback: `rollback N` + commit.
- Failure at any step before the confirming commit → let the confirmed timer
  auto-revert; surface the device output in the error.
- Update the plugin docstrings and, if the guardrail rationale changes,
  annotate ADR-0026 (do not silently rewrite an Accepted ADR — add an
  addendum noting the implementation gap and its closure).

**Tests.** Transport-level unit tests on the command sequence (mock netmiko
channel, assert exact ordered command strings incl. `commit confirmed`);
failure-path test proving no confirming commit is sent when verification
fails; JunOS plugin parity suite green.

## T2 — C3: unescaped config text corrupts `replace_config` staging (CRITICAL)

`backend/app/plugins/transport/ssh.py:241`.

**Problem.** `f'puts [open "{staged}" w+] "{candidate}"'` embeds the whole
multi-line candidate config inside a Tcl double-quoted string. Literal `$`,
`"`, `[`, `]` (banners, AS-path regexes, cert blobs) trigger Tcl substitution
or terminate the string, corrupting the staged file. Device errors come back
as plain output text, not exceptions. This is the **sole apply surface for
`CONFIG_RESTORE` and the sole rollback surface** for
cisco_ios/iosxe/nxos/eos — the post-apply equality assert converts silent
corruption into a *failed rollback during an incident*.

**Fix.** Base64-encode the payload and decode device-side (preferred —
sidesteps the whole metacharacter class), or escape every Tcl metacharacter.
Fail closed: treat any tclsh error output as a hard failure before
`configure replace` is issued; verify staged-file integrity (length or hash)
before apply.

**Tests.** Round-trip tests with hostile payloads — `$variable`, embedded
quotes, `[brackets]`, backslashes, multi-line banner with `^C` delimiters,
certificate blob. Error-output-detection test: tclsh error text → exception,
no apply attempted.

## T3 — H7: SSH host keys never verified (HIGH)

`backend/app/plugins/transport/ssh.py:136-144`.

**Problem.** `ConnectHandler` without `ssh_strict`/`system_host_keys` →
paramiko `AutoAddPolicy`; every CLI vendor silently accepts any host key.
MITM/host-substitution exposure on the same transport that carries device
credentials and config writes — contradicts "secure by default".

**Fix.**
- Default `ssh_strict=True` + `system_host_keys=True`.
- Optional pinned per-device host-key fingerprint on `ConnectionParams`
  (schema + settings plumbing; verify against the presented key).
- Explicit lab-only opt-out setting (`NETOPS_SSH_STRICT=false` shape),
  default-on, documented in `.env.example` + Helm values — config-contract
  1:1 rule applies.
- Failure mode: unknown host key → typed transport error naming the expected
  remediation (add to known_hosts or pin fingerprint), not a bare paramiko
  stack trace.

**Tests.** Strict-mode rejects unknown key; pinned fingerprint accepted /
mismatch rejected; opt-out restores legacy behavior with a logged warning.

## T4 — AR-W2-T1 / H8: extract `plugins/vendors/cli_common/` (LARGE)

`cisco_ios/plugin.py:475-588`, `cisco_iosxe/plugin.py:368-466`,
`cisco_nxos/plugin.py:470-553`, `eos/plugin.py:436-536`,
`junos/plugin.py:443-546` — ADR-0021 write engine copy-pasted 5×.

**Fix.** New `backend/app/plugins/vendors/cli_common/` package:
- Shared lifecycle mixin: `_run / _execute / _diff_summary /
  _rollback_to_baseline / _require_executing / _replace_config /
  _send_config`.
- Shared textfsm parser helpers: `_parse_with_template / _int_or_none /
  _address_or_none / _statuses`.
- `cli_common` must respect the plugin-boundary contract (imports only
  `core.errors` + `schemas.discovery`, like the vendors it serves) —
  import-linter must stay green.

**Refit order — one vendor per atomic commit:**
1. `cli_common` base package (no vendor wired) — full suite green.
2. `cisco_ios` refit.
3. `eos` refit.
4. `cisco_nxos` refit.
5. `junos` refit (carries T1's JunOS-specific write transport — JunOS
   overrides the Cisco-shaped `_replace_config`, it does not inherit it).

**Hard rules:**
- Per-vendor parity/plugin suites (35 test files) stay green **unchanged**
  after each commit — the suites are the regression harness; they are not
  edited in this wave.
- Any behavioral divergence discovered between the 4 Cisco-family copies is a
  **finding, not a silent unification** — surface it, decide, document the
  decision in the commit message. (Parallel-build lesson: divergences here
  are likely a shared-bug class; sweep all vendors for each one found.)
- `cisco_iosxe` shares the `cisco_ios` shape — refit it in the same commit as
  `cisco_ios` only if the diff stays mechanical; otherwise its own commit.

**Tests.** No new test files required; the existing 35-file parity/plugin
matrix is the acceptance gate per commit. Add `cli_common`-level unit tests
only for helper edge cases not already pinned by parity suites.

---

## Ordering & dependencies

```
T2 (Tcl staging fix) ─┐
T3 (host keys)        ├──► T4 (cli_common extraction, 5 commits)
T1 (JunOS transport) ─┘
```

- T1–T3 are independent of each other; land all three before T4 so the
  extraction moves corrected code.
- T4's junos commit depends on T1's transport being in place.
- Wave 3 must complete before any new CLI vendor plugin work.
- Coordination: touches `plugins/vendors/*` + `plugins/transport/ssh.py`
  only — no collision with P4-W3 (compliance reporting) files; safe to run
  concurrently with it per the AR1 collision matrix.

## Model & review policy

| Task | Implementer | Review |
|------|-------------|--------|
| T1–T3 | `wf-implementer`, **STRONG pinned** | quality + spec reviewers, STRONG |
| T4 | `wf-implementer`, **STRONG pinned** | quality + spec reviewers per vendor commit |

Never "inherit" — pin explicitly (workflow inherit-strong gotcha).

## Gates (per commit and PR exit)

- `pytest` + `pg-integration` green; `ruff check . && ruff format --check .
  && mypy && lint-imports` (plugin boundary contract must hold for
  `cli_common`).
- Parity suites green **unchanged** after every T4 commit.
- `.env.example` ↔ `config.py` updated together for T3's new settings.
- No PR-body green claim without re-verification at final HEAD.
- `graphify update .` after merge.

## Exit criteria

- JunOS config writes actually commit, with working confirmed-commit
  dead-man auto-revert and `rollback N` inverse (C2 closed).
- `replace_config` staging safe against arbitrary config content, fails
  closed on tclsh errors (C3 closed).
- SSH host-key verification on by default with pin + lab opt-out (H7 closed).
- 5 CLI vendors on `cli_common`; write engine exists exactly once (H8 /
  AR-W2-T1 closed); divergence findings documented in commit messages.
- All CI checks green; `REVIEW-WAVES-PLAN.md` status table updated.
