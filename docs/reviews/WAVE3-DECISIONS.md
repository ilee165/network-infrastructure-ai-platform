# Wave 3 decisions (from planning Q&A)

Locked before implement. Parent: `WAVE3-PLAN.md`.

## Q1 — Option A (ADR-faithful)

- Apply: `load` + `commit check` + `commit confirmed <N>` only.
- Confirming `commit` after plugin verify-after success via `confirm_config()`.
- On verify failure: do not confirm; structured rollback primary; timer = backstop.
- Seam: `junos/plugin.py` `_execute` success branch (~490) → `confirm_config()`; failure (~499) withholds confirm.
- Docstrings at 345–351 already match A.

### Protocol (small, typed)

- `confirm_config() -> str` on `ConfigWriteTransport`.
- Optional `rollback_config(n)`.
- Cisco-family: no-op (apply already final).
- Uniform `cli_common` `_execute`: always call `confirm_config()` after verify success.
- No `hasattr` sniffing; typed capability only.

### T1 pins

1. Timer N covers apply + verify-after + margin; configurable; tests pin sequence.
2. Failure path: verify-fail → rollback 1 (or load override baseline) → commit; never bare commit before rollback. Structured rollback primary; timer backstop.
3. Worker-crash gap widens (apply + verify-after); update plugin ~361 docstring + ADR-0026 addendum.

## Q2 — Setting

- Name: `NETOPS_JUNOS_COMMIT_CONFIRMED_MINUTES` (JunOS-scoped).
- Default: 2; `Field(ge=1, le=60)`.
- Wiring: `config.py` + `.env.example` + Helm (with T3 settings trio).
- `.env.example` comment: increase for large configs / slow control planes.
- ADR addendum notes Option A window includes verify-after.

## Q3 — Host-key pin placement

- Primary: `ssh_strict=True` + `system_host_keys` (known_hosts).
- Pin = supplementary for hosts not in known_hosts.
- Optional on `ConnectionParams`: session field after materialization.
- No Device/API/UI persistence this PR.
- Fill path: `DeviceCredential.params` (same as `device_type` override).
- **Trap:** shared credentials → host-keyed map only:
  `{"host_key_fingerprints": {"10.0.0.1": "SHA256:..."}}`
  Materialize entry for `ConnectionParams.host`. Flat single-fp on shared cred = bug.
  First-class Device column = follow-up wave.

## Q4 — Class placement

- `JunosSshTransport(SshTransport)` in `plugins/transport/` (own module or ssh sibling).
- Overrides `send_config`/`replace_config`; adds `confirm_config`/`rollback_config`.
- Factory: `make_ssh_transport(params)` keyed on `device_type == "juniper_junos"`.
- Wire **only** `workers/tasks/config.py` `_open_ssh` (write path).
- Do **not** wire discovery/troubleshooting/packet `_open_ssh`.
- Defensive: base `SshTransport` refuse juniper_junos writes with typed error + one test.
- Cisco family keeps `SshTransport` + T2/T3; aligns T4 junos override of Cisco-shaped replace.

## Q5 — Execution

- **Inline** (option 2), sequential; same gates; dual reviewers spawned per commit.
- Reasons:
  1. Parallelism payoff ~zero (T2+T3 both edit ssh.py; T1 same package; T4 sequential).
  2. STRONG-pin by construction — session model is strong; no workflow `inherit` gotcha
     (the exact failure mode workflows risk when model is not pinned).
  3. T4 divergence-finding needs **context continuity** — one mind carrying
     cisco_ios → eos → nxos → junos refits catches the shared-bug class across
     vendors (plan L130–132). Separate `wf-implementer`s per vendor lose that.
  4. **Review discipline preserved:** after each task/vendor commit, spawn
     `wf-quality-reviewer` + `wf-spec-reviewer` (read-only, model pinned strong),
     fold findings as **atomic fix commits** before starting the next task.

## Process (from written workflow — hard rules)

- **Atomic commit per task** (T1–T3 each one commit; T4 = base + one commit per vendor).
- **Full gates per commit** before review:
  - `pytest` (targeted while iterating; full suite before commit)
  - `ruff check . && ruff format --check .`
  - `mypy`
  - `lint-imports`
  - T4: parity/plugin suites stay **green and unchanged** after every vendor commit
- **Findings ≠ silent unification** — behavioral divergences between vendor copies are
  surfaced, decided, and documented in the commit message (plan L129–132).
- **One PR at end** on `fix/review-wave3` (not per task).
- Dual strong review per commit; fix commits before next task (Q5.4).
