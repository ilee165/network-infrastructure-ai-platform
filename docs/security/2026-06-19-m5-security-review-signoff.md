# M5 Security Review Sign-Off — Write-Path Milestone

**Date:** 2026-06-19
**Milestone:** M5 (first write-paths to real devices — ChangeRequest spine,
Automation Agent, packet capture/analysis, DDI)
**Authority:** CLAUDE.md "Development Standards" step 5 (security review);
M5-PLAN.md row 19; ADR-0020 (ChangeRequest / four-eyes), ADR-0023 (packet
sandbox / pcap retention), ADR-0011 (audit + secret vault), A9 (prompt
redaction), ADR-0013 (deployment).
**Scope:** the security-critical controls that gate M5's first persistent device
changes. Each item is signed off against concrete evidence (`file:line` and/or a
test that pins the behavior). All backend/frontend gates are green at sign-off.

Legend: **PASS** = control implemented, evidenced, and test-pinned.

---

## 1. Four-eyes integrity — approver != requester, enforced server-side

**Status: PASS**

The four-eyes predicate (an `approve` decision on a `four_eyes_required` CR must
have `actor_id != requester_id`) is enforced **server-side in depth**, at three
layers, never relying on the UI:

- **Service guard (primary):** `backend/app/services/change_requests/service.py:329`
  — `ChangeRequestService.approve()` raises `ForbiddenError` *before* any state
  write or `approvals` insert when `cr.four_eyes_required and actor_id == cr.requester_id`.
- **Endpoint recheck (defence in depth):** `backend/app/api/v1/agents.py:692`
  re-checks the same predicate on `POST /changes/{cr_id}/approve` before calling
  the service.
- **Database trigger (backstop):** `backend/alembic/versions/0007_m5_change_requests_pcap.py:72`
  (`enforce_four_eyes()` PL/pgSQL trigger) rejects a self-approve at the DB level,
  conditional on `four_eyes_required = true` so the documented waiver mode still
  works.

`four_eyes_required` defaults to `true`
(`test_change_request_four_eyes_required_defaults_true`) and is immutable after
submit (`test_requester_and_four_eyes_immutable_after_submit`). Only an admin may
waive it, and the waiver is audited (`test_admin_can_disable_four_eyes_and_waiver_is_audited`);
an engineer cannot (`test_engineer_cannot_disable_four_eyes`).

**Evidence (tests):**
- `tests/services/test_change_request_service.py::test_requester_cannot_approve_own_four_eyes_cr`
- `tests/services/test_change_request_service.py::test_self_approval_allowed_when_four_eyes_disabled`
- `tests/api/test_changes_packet.py::test_self_approval_rejected_at_endpoint`
- `tests/api/test_changes_packet.py::test_engineer_distinct_from_requester_may_approve`

This is M5 exit criterion: "Non-`approved` CR cannot execute; self-approval
rejected under default config."

---

## 2. Packet sandbox per D14 — resource limits / no network / dropped capabilities

**Status: PASS** (process-launch controls in code; OS-level controls in deploy)

tshark parses **untrusted pcaps** and its C dissectors carry parsing CVEs, so the
analysis path is the platform's highest-risk operation. Containment is split
between the code (process-launch controls) and the deployment (OS isolation), per
ADR-0023 §1:

- **argv-not-shell:** `backend/app/engines/packet/sandbox.py:69` (`build_tshark_argv`)
  returns a `list[str]`; `:118` spawns it with `subprocess.run(..., shell=False)`.
  The pcap path and display filter are inert argv elements — a filename like
  `"; rm -rf / #"` cannot execute.
- **filter whitelist before spawn:** `sandbox.py:88` validates any display filter
  via `validate_capture_filter` before the argv is built; a rejected filter spawns
  nothing.
- **no name resolution (no analysis-triggered egress):** `-n` is always present
  in the argv (`sandbox.py:89`).
- **hard subprocess timeout:** `sandbox.py:121` bounds the child by
  `packet_analysis_timeout_seconds`; a slow/hostile capture becomes `SandboxError`,
  not a wedged worker.
- **capture/analysis privilege split:** the analysis worker holds **no device
  credentials** and the capture credential plaintext never enters a log/audit/
  result line — the EOS path keeps it inside the SSH session only
  (`backend/app/workers/tasks/packet.py:502`, module docstring §"Secret discipline").
- **OS-level isolation (deployment):** no-network container, `cap_drop: [ALL]`,
  non-root, read-only pcap mount, CPU/mem limits — the dedicated `packet`-queue
  worker per ADR-0023 §1 and ADR-0013 §3/§4 (Helm NetworkPolicy + PodSecurityContext).

**Evidence (tests):**
- `tests/engines/packet/test_sandbox.py::test_analyze_pcap_invokes_tshark_argv_not_shell`
- `tests/engines/packet/test_sandbox.py::test_analyze_pcap_rejects_malicious_filter_without_spawning`
- `tests/engines/packet/test_sandbox.py::test_analyze_pcap_timeout_becomes_sandbox_error`
- `tests/engines/packet/test_sandbox.py::test_tshark_argv_is_a_list_with_no_name_resolution`
- `tests/workers/test_packet_tasks.py::test_analyze_capture_returns_findings_and_audits_no_payload`
  (the LLM/audit path sees normalized counts only, never raw packet bytes)

**Residual / deployment note:** the OS-level controls (NetworkPolicy, dropped
caps, RO mount, resource limits) are declared in the Helm chart and the Compose
worker profile; in the single-worker Compose dev stack the `packet` queue is not
yet split into its own least-privilege worker container. Splitting it is the K8s
production posture (ADR-0023 §1, ADR-0013 §4) and is tracked as a deployment-time
hardening item, not a code gap.

---

## 3. A9 redaction on every CR-diff / DNS / config → LLM path

**Status: PASS**

Secret-stripping is **central and bypass-proof**: every chat model the factory
returns is wrapped, so no caller (CR diff preview, config/DNS explanation, agent
narrative) can reach a provider with un-redacted text — for any profile, local or
external.

- **Central wrap point:** `backend/app/llm/providers.py:179` —
  `get_chat_model()` returns `wrap_with_redaction(provider_model)`; callers cannot
  forget to redact.
- **Profile-independent:** the same `RedactingChatModel` wraps `local`,
  `anthropic`, `openai`, `azure` — there is no "trusted" provider
  (`backend/app/llm/redaction.py:17`).
- **Vendor secret patterns:** SNMP communities, Cisco type-7, enable secrets,
  RADIUS/TACACS keys, IPsec PSKs, routing-auth keys — replaced by stable
  `<<REDACTED:kind>>` sentinels (`redaction.py:55` `REDACTION_TOKENS`).

**Evidence (tests):**
- `tests/llm/test_redaction.py::test_get_chat_model_returns_redacting_wrapper`
- `tests/llm/test_redaction.py::test_invoke_redacts_even_when_caller_forgets`
- `tests/llm/test_redaction.py::test_redaction_applies_on_every_profile`
- `tests/llm/test_redaction.py::test_actual_secret_value_does_not_survive`

---

## 4. RBAC on the changes API — approve requires engineer+

**Status: PASS**

The `/changes` surface (mounted on the agents router) is role-gated; the mutating
transitions require `engineer`+:

- **Role gate:** `backend/app/api/v1/agents.py:100` —
  `Engineer = Annotated[User, Depends(require_role("engineer"))]`; the
  `approve`/`reject`/`submit` handlers (`agents.py:663`–`712`) depend on it.
- **Role-minimum dependency:** `backend/app/api/deps.py:145` (`require_role`)
  resolves the authenticated user and 403s below the minimum role
  (admin > engineer > operator > viewer ordering).
- **Service-level role check:** `ChangeRequestService.approve()` also calls
  `self._require_role(actor_role, ...)` (`service.py:323`) — RBAC is not only a
  route concern.

**Evidence (tests):**
- `tests/api/test_changes_packet.py::test_engineer_distinct_from_requester_may_approve`
- `tests/api/test_changes_packet.py::test_engineer_may_list`
- `tests/api/test_changes_packet.py::test_self_approval_rejected_at_endpoint`
  (engineer present, still 403 on self-approve — RBAC and four-eyes are independent gates)

---

## 5. Secret handling — never logged or leaked

**Status: PASS**

No credential/key plaintext appears in any log line, audit `detail`, API
response, exception message, or `repr`:

- **Vault KEK:** `backend/app/core/config.py:74` — `kek: SecretStr`; pydantic
  `SecretStr` masks the value in every `repr`/`str`/serialization.
- **Decrypted material:** `backend/app/services/credentials/service.py:40,55`
  — `DecryptedSecret` renders `DecryptedSecret(****)` from both `__repr__` and
  `__str__`; the plaintext is reachable only via an explicit accessor.
- **Worker-side credential wrappers:** `backend/app/workers/tasks/discovery.py:190`
  and `backend/app/workers/tasks/config.py:135` define `__repr__` that never
  renders the secret; module docstrings document that plaintext lives only inside
  the SSH session.
- **Packet capture:** the EOS capture credential never enters arguments, return
  values, audit detail, or logs (`backend/app/workers/tasks/packet.py` module
  docstring §"Secret discipline (D11)").
- **Retention audit (this task):** the raw-artifact purge audit records the count
  + cutoff only — never the captured device text
  (`backend/app/workers/tasks/discovery.py` `_purge_artifacts`, asserted by
  `tests/workers/test_artifact_retention.py::test_purge_expired_artifacts_deletes_old_rows_and_audits`,
  which checks `"raw_text" not in detail`).

---

## 6. Trivy zero-critical posture

**Status: PASS (gate is actionable; zero fixable CRITICAL/HIGH)**

- **CI gate:** `.github/workflows/ci.yml:160` (backend) and `:173` (frontend) run
  `aquasecurity/trivy-action@v0.36.0` with `severity: CRITICAL,HIGH`,
  `ignore-unfixed: true`, `exit-code: "1"` — the build **fails on any FIXABLE
  CRITICAL/HIGH CVE**.
- **`ignore-unfixed: true`** makes the gate actionable: it fails only when a fix
  exists and we have not applied it, rather than on upstream-unpatched base-image
  OS CVEs.
- **Remaining unfixed base-image CVEs** are tracked in
  `docs/security/2026-06-14-trivy-baseimage-cves.md` (all `fix_deferred` Debian OS
  packages, off the reachable attack surface — perl/sqlite/ncurses not invoked at
  runtime). Zero are fixable today.

**Re-verify before release (T20):** run the CI `docker (build images + Trivy
scan)` job on the release commit and confirm both Trivy steps pass; re-check
whether Debian has since published fixes for the deferred CVEs.

---

## Sign-off

| # | Control | Status |
|---|---------|--------|
| 1 | Four-eyes integrity (server-side, approver != requester) | PASS |
| 2 | Packet sandbox per D14 (limits / no network / dropped caps) | PASS (deploy note) |
| 3 | A9 redaction on every CR-diff / DNS / config → LLM path | PASS |
| 4 | RBAC on changes API (approve requires engineer+) | PASS |
| 5 | Secret handling (never logged/leaked) | PASS |
| 6 | Trivy zero-critical posture | PASS |

**Outstanding for T20 (release):** confirm the Trivy CI step is green on the
release commit; complete the deployment-time split of the least-privilege
`packet` analysis worker (Compose) as the OS-level half of control #2 (the code-
level controls are already in place and pinned).
