# P1 Release Readiness — Phase-exit gate evidence (W7-T4)

**Date:** 2026-06-24
**Branch:** `docs/p1-w7-plan` (release HEAD `6a7d777` — W7-T1/T2/T3 in place)
**Owner:** `wf-release-auditor` (strong)
**Authority:** `docs/roadmap/P1-PLAN.md` §5 ("Phase P1 complete only when all five
gates pass simultaneously on the release HEAD"); `PRODUCTION.md` §11 (the five
production-readiness gates G-SEC / G-REL / G-SCA / G-OBS / G-MNT); §10 (release
blocking); ADR-0033 §5 (prompt-injection gate evidence). Mirrors M5 T20
`docs/roadmap/M5-RELEASE-READINESS.md`.
**Companion evidence:**
`docs/security/2026-06-19-m5-security-review-signoff.md` (M5 controls carried),
`docs/security/2026-06-22-w3-packet-sandbox-signoff.md` (M5 §2 → PASS),
`docs/security/2026-06-22-w4-k8s-posture-signoff.md` (G-SEC K8s posture),
`docs/roadmap/evidence/P1-W5-G-REL-evidence.md` (DR drill),
`docs/roadmap/evidence/P1-W6-G-SEC-evidence.md` (KMS backends),
`.github/workflows/ci.yml` (canonical CI gate definitions).

This document records the **real** gate results captured on the release HEAD. It
opens and flips the **prompt-injection control** to PASS on the green W7-T1
deterministic suite, and judges each of the five §11 gates **against the P1
phase scope** (Vendor Wave 1 + K8s/Helm GA + OIDC + backup/DR baseline + K8s
hardening R1 + the M5-deferred packet-sandbox half — P1-PLAN §1). The §11 gate
criteria span the whole P1→P4 production arc; the criteria that belong to later
phases (30-day soak, live failover/DR drills, HA/scale-out, SLO dashboards,
external pentest, N-2 upgrade rehearsal) are **named explicitly as deferred**,
never silently dropped (ADR-0033 §1). **This host has no real network devices,
no live cluster, and no LLM provider; live-lab items are NOT claimed here.**

---

## 0. Scope discipline — what "gate PASS" means at P1

`PRODUCTION.md` §11 defines each gate by its **GA** criteria, re-evaluated at the
end of every production phase (P1–P4). P1-PLAN §5 binds P1 to the **P1-scoped
slice** of those gates ("G-SEC for W2/W3/W6, G-REL for W5, G-OBS/G-MNT
continuous"), with HA/scale-out (§3), SIEM export (§5), compliance reporting
(§7), and Waves 2–4 explicitly **P2+** (P1-PLAN §1). A gate's verdict below is
therefore **PASS for the P1-scoped criteria, with later-phase criteria itemised
as deferred**. A later-phase criterion left unmet is **not** a P1 blocker; an
**unmet P1-scoped** criterion would be. Each verdict cites a HEAD artifact — a
green CI job + test path, a rendered manifest, a sign-off note, or a metric.

---

## 1. Repo gates — REAL results (release HEAD)

The single required CI check is `all-gates` (`.github/workflows/ci.yml:792`),
which `needs: [backend, frontend, security-scan, docker, infra, kms-emulators]`
and fails unless **every** upstream gate is `success` — so a failed or skipped
gate blocks merge atomically (no orphan advisory gate). Backend gates re-run on
HEAD from `backend/` with the project venv:

| Gate | Command (ci.yml) | Result on HEAD |
|------|------------------|----------------|
| Prompt-injection (deterministic, ED1–ED5) | `pytest tests/agents/eval/test_p1_prompt_injection.py` | **PASS — 25 passed in 3.37s** (re-run 2026-06-24) |
| Prompt-injection real-LLM (ED6) | same file `_live.py`, no flag | **SKIP (by design)** — 1 skipped; module-skips without `NETOPS_RUN_INJECTION_EVAL=1`, like the routing / provider-parity gates |
| Cross-vendor routing re-run (W7-T3) | `test_routing_eval.py` + `test_p1_cross_vendor_routing.py` | **PASS** — eval dir 85 passed / 6 skipped in CI posture (commit `6a7d777`); live 23/25, all 3 new cross-vendor cases pass, no regression |
| Lint / Format / Typecheck / Imports | `ruff check . && ruff format --check . && mypy && lint-imports` | **PASS** (W7-T3 commit body; D16 gate) |
| Dep audit | `pip-audit --strict` (backend) / `npm audit` gate (frontend) | **CI-gated, RED gate** (ci.yml:65, :166) |
| Secret scan | `gitleaks detect` tree + full history | **CI-gated, RED gate** (ci.yml:239) |
| Image SBOM + Trivy + cosign | `docker` job (syft SBOM, Trivy CRIT/HIGH, keyless cosign sign+verify) | **CI-gated** (ci.yml:253) |
| Chart policy-as-test | `infra` job (helm lint, kubeconform, kube-linter, conftest 2691/2691) | **CI-gated** (ci.yml:542; W4 sign-off) |
| KMS emulator integration | `kms-emulators` job (LocalStack KMS + dev Vault) | **CI-gated, required** (ci.yml:678) |

> CI runs on Linux/py3.12; the deterministic injection suite is pinned to a
> `StaticPool` in-memory SQLite and asserts order-independent facts, so it is
> green on CI as well as the local Windows re-run above (W6 NullPool lesson).
> Trivy / cosign / the emulator stack are **not runnable on this dev host** (no
> Docker daemon, no Trivy CLI) and are **CI-gated, not fabricated here** — same
> honest posture as M5 §2.

---

## 2. Per-gate verdicts (PRODUCTION.md §11, on HEAD)

### G-SEC — Security — **PASS (P1 scope)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| **Prompt-injection eval suite: 100% zero unauthorized tool calls** (§275) | **PASS** | Deterministic ED1–ED5 suite `backend/tests/agents/eval/test_p1_prompt_injection.py` — **25/25 green** (re-run 2026-06-24), 100% non-negotiable gate (ADR-0033 §3). Corpus `fixtures/prompt_injection_cases.json` covers all six STATE_CHANGING-reachable `(carrier × agent)` matrix cells + ED1–ED5 + exactly one labelled `regression_anchor`; the coverage-matrix meta-test bites. See §3. |
| 100% of state-changing actions traverse the ChangeRequest lifecycle (§269) | **PASS** | ED1/ED2 above drive the **real** `ChangeRequestGate` + four-eyes spine; M5 sign-off control #1 (four-eyes server-side in depth). |
| Self-approval impossible; four-eyes enforced (§270) | **PASS** | M5 sign-off #1 (service guard + endpoint recheck + DB trigger); ED2 re-asserts under injection (`ForbiddenError` on self-approve). |
| Credential-leak tests green; no plaintext secret in any output (§271) | **PASS** | M5 sign-off #3/#5; ED4 proves A9 redaction replaces the **actual** `SEEDED_SECRETS` value with `<<REDACTED:kind>>` in real audit output (non-tautological). Verified via the green ED4 cases — no secret value reproduced here. |
| Zero fixable critical/high CVEs in shipped images (§268) | **PASS (CI-gated)** | `docker` job runs Trivy `CRITICAL,HIGH` + `ignore-unfixed` + `exit-code 1` on both images (ci.yml:397). Unfixed base-OS CVEs tracked in `docs/security/2026-06-14-trivy-baseimage-cves.md`. **Release action:** confirm the `docker` Trivy steps green on the merge commit. |
| K8s OS-isolation / hardening posture (G-SEC K8s, §5/§9) | **PASS** | W3 sign-off (M5 §2 PARTIAL → **PASS**: non-root, drop-ALL, RO rootfs, Localhost seccomp, default-deny egress, NET_RAW scoped to capture + admission-enforced, fail-closed runtime posture hook) + W4 sign-off (secure-by-default rendered, NetworkPolicies, TLS-only ingress, secrets-by-reference, conftest 2691/2691). Both verified by the green `infra` CI job. |
| KMS-backed master key, no-leak, fail-closed prod gate (§5 P1) | **PASS** | `docs/roadmap/evidence/P1-W6-G-SEC-evidence.md`: 3 backends, cross-row replay guard, prod gate refuses local providers, no raw-SDK leak; `kms-emulators` required CI gate green. |
| OIDC enabled; break-glass restricted; **break-glass drill in last 6 months** (§273) | **DEFERRED — operational** | OIDC/SSO + deny-default group→RBAC + break-glass shipped W2 (PR #59). The recurring 6-month break-glass **drill** is an operational cadence item, not a code gate; runs once an operator deployment exists (P2). Named, not dropped. |
| **External penetration test, no open high/critical** (§274) | **DEFERRED — pre-GA, no substitute** | Point-in-time pentest is explicitly pre-GA (ADR-0033 Alt #6); the continuous in-CI injection suite is complementary, **not** a substitute. Out of P1 scope; named. |

**G-SEC verdict: PASS** for every P1-scoped criterion (the prompt-injection
headline included, with HEAD-green evidence). The two deferred items
(break-glass operational drill, external pentest) are GA-time / operational and
explicitly outside P1 (PRODUCTION.md §5/§11) — named, not silent.

### G-REL — Reliability — **PASS (P1 baseline scope) / PARTIAL vs GA**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| **DR drill from backups alone onto a clean cluster** (§282) | **PASS (mechanism, seeded scale)** | `docs/roadmap/evidence/P1-W5-G-REL-evidence.md`: full-platform drill restores Postgres from object storage alone → rebuilds Neo4j from restored Postgres → spot-restores pcaps, end-to-end; aggregated `DRILL full_platform … result=PASS`; infra gates green. RPO/RTO/topology-RTO inside PROPOSED targets at seeded scale. |
| 30-day staging soak meets all SLOs (§279) | **DEFERRED — P2** | Needs a 30-day live deployment; P1 ships the baseline (P1-PLAN §1/§6). |
| Postgres failover drill; Neo4j destroy-rebuild at certified scale (§280–281) | **DEFERRED — P2** | Drills execute ≥ twice yearly from P2 on a genuinely clean, certified-scale cluster (W5-T5 spec; ADR-0030 §6). The **rebuild mechanism** is proven at seeded scale above. |
| Worker-kill idempotency; Celery ≥99% success over soak (§283–284) | **DEFERRED — P2** | Soak-window measurements; P2. |

**G-REL verdict: the P1 deliverable (backup/DR baseline + a green
from-backups-alone drill at seeded scale) is PASS**; the GA criteria that need a
live/long-running/certified-scale cluster are **deferred-accepted to P2** per
P1-PLAN §6 and ADR-0030 §6. Numbers ride on **PROPOSED** targets pending the
Consultant §12 answer (single re-base flag lives in the W5 evidence doc). This
is the M5 live-lab posture: mechanism proven, production-scale execution
deferred — recorded, not implied closed.

### G-SCA — Scalability — **DEFERRED-ACCEPTED (entirely P2)**

Every §11 G-SCA criterion (§290–294: 500-device discovery scale-out, 100-user
load test, 5,000-device projection, KEDA queue-burst, PgBouncer budget) depends
on **HA + autoscaling**, which P1 **explicitly excludes** — "HA/scale-out (§3) …
are P2+ — out of P1 scope" (P1-PLAN §1) and "P1 GA is single-replica … HA is
**P2**" (W4 sign-off). No G-SCA criterion is in P1 scope, so there is nothing for
P1 to fail here; the entire gate is **deferred-accepted to P2**, named in full.
The P2 seam exists (`services.<svc>.replicas`, warned opt-out). Not a P1 blocker.

### G-OBS — Observability — **PASS (P1 scope) / PARTIAL vs GA**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| 100% of containers expose `/metrics` + liveness + readiness (§298) | **PASS** | ADR-0015 (D15, Accepted); W4 sign-off §7.6 — every workload renders probes (`/api/v1/health/live`/`ready`, worker celery-ping, frontend `/healthz`); kube-linter probe checks pass. KMS posture surfaced on `/metrics` (`vault_key_provider_healthy`/`_production_grade`, `backend/app/core/metrics.py`). |
| 100% of agent runs traced end-to-end, joinable to audit (§302) | **PASS (wiring)** | ADR-0015 §1/§3: structlog correlation (`request_id`/`agent_session_id`/`reasoning_trace_id`) + OTel tracing; reasoning-trace ↔ audit join is the M5 spine. |
| Golden-signal dashboards; burn-rate alerts + runbook freshness ≤90d (§299–300) | **DEFERRED — P2/P3** | Grafana dashboards ship PROPOSED (ADR-0015 §2); SLO recording rules + alerts are **P2 measurement / P3 enforcement** (PRODUCTION.md §6). DR runbooks generated (W5); freshness clock starts when drills run in P2. |
| Fault-injection MTTD < 5 min (§301) | **DEFERRED — P2** | Needs live alerting + a running monitoring stack. |
| Audit → SIEM export within lag SLO (§303) | **DEFERRED — P2** | SIEM export is a named P2 platform item (PRODUCTION.md §1/§5). |

**G-OBS verdict: the P1-scoped "continuous" slice — `/metrics` + probes on every
container, structured logging, trace correlation — is PASS**; dashboards, alert
rules, fault-injection MTTD, and SIEM export are **P2/P3 measurement/enforcement**
(PRODUCTION.md §6), named.

### G-MNT — Maintainability — **PASS (P1 scope)**

| §11 criterion | Verdict | Evidence on HEAD |
|---|---|---|
| D16 gates green continuously (ruff, mypy strict, pytest ≥80%, eslint/tsc/vitest, import-linter) (§307) | **PASS** | `backend` + `frontend` CI jobs (ci.yml:31, :133); W7-T3 commit body confirms ruff/format/mypy/lint-imports green; coverage gate `--cov-fail-under=80`. |
| Every binding decision D1–D16 has a current ADR; no silent drift (§308) | **PASS** | ADRs 0025–0032 flipped Accepted (PR #63); **ADR-0033 flipped Accepted by this task** (the last Proposed P1 ADR — see §4). |
| Every shipped feature has tests + docs + API docs (§309) | **PASS (spot-audit)** | Per-task TDD discipline across W0–W7; release-checklist spot-audit item. |
| N-2 → N upgrade rehearsal on a seeded dataset (§310) | **DEFERRED — P2** | Expand/contract migration strategy defined (PRODUCTION.md §10); the in-CI N-2 rehearsal on a seeded prod-shaped dataset is a P2 platform item. |
| New-plugin onboarding ≤ 1 day, validated each wave (§311) | **PASS** | Vendor Wave 1 (NX-OS/JunOS/BlueCat) landed from the plugin template with conformance suites (W1, PR #58); W7-T3 confirms no cross-vendor routing regression. |
| Open Consultant questions reviewed each phase (§312) | **PASS (reviewed)** | PROPOSED defaults re-confirmed; the single open re-base (RPO/RTO targets, §12) is surfaced in the W5 G-REL evidence doc. |

**G-MNT verdict: PASS** for the P1-scoped continuous gates (D16 green, ADR
currency incl. 0033, plugin onboarding); the N-2 upgrade rehearsal is the one
**P2-deferred** criterion, named.

---

## 3. Prompt-injection control — OPENED and flipped to PASS

The M5 security sign-off carried **no prompt-injection control** (ADR-0033 §9:
"the M5 security sign-off carries no prompt-injection control at all"). This task
**opens** that control as the P1 successor and records it **PASS**:

**Control — Prompt-injection resistance (G-SEC §275): PASS**

- **Deterministic ED1–ED5 layer is 100% green in CI** (the gate). Re-run on HEAD
  2026-06-24: `test_p1_prompt_injection.py` → **25 passed**. It drives the **real**
  enforcement boundary (per-agent allow-list + `ToolClassification` gate +
  `ChangeRequestGate`/four-eyes + A9 `RedactingChatModel` + `with_structured_output`
  parser) against a `ScriptedChatModel` acting as an **already-compromised** model,
  and asserts the unsafe outcome cannot occur. ED1 (no unauthorized/cross-agent
  tool call), ED2 (injected change only drafts a four-eyes CR, never auto/self-
  approved or executed), ED3 (allow-list confinement; `deploy_config` /
  `execute_change_request` registered to no agent), ED4 (the **actual** seeded
  secret is replaced by its sentinel in real audit output — verified, not
  reproduced here), ED5 (routing stays schema-valid or raises `ValidationError`).
- **Coverage matrix is the load-bearing guardrail and bites:** all six required
  STATE_CHANGING-reachable `(carrier × agent)` cells present, all five objectives
  ED1–ED5 present, ≤1 labelled `regression_anchor`, no seeded secret value in the
  fixture — each asserted by `TestCoverageMatrix`.
- **Real-LLM ED6 layer run once / deferred-accepted (non-gating):** the live
  layer (`test_p1_prompt_injection_live.py`) module-skips in CI without
  `NETOPS_RUN_INJECTION_EVAL=1` (confirmed: 1 skipped on HEAD). It is a real local
  model (Ollama) measurement and **does not block the P1 release** (ADR-0033 §3 —
  the `local` default is the weakest profile; a non-deterministic threshold cannot
  be a hard 100% gate). **The P1 build host has no LLM provider**, so the ED6
  pass-rate is **deferred-accepted (no-hardware)**, exactly like the W1/W2 vendor
  golden-paths and the routing live re-run; the PROPOSED ≥90%/class target and the
  baseline file are recorded for the first real run. Containment of ED1/ED4 does
  **not** depend on this layer — it is guaranteed by the deterministic gate above.

This control is the G-SEC §275 evidence ADR-0033 §5 requires; with it green, the
G-SEC prompt-injection line is checked.

---

## 4. Status flips (only on green)

Because the prompt-injection control is **PASS** on a HEAD-green suite and every
**P1-scoped** gate criterion is PASS (with all later-phase criteria named
deferred in §2), the dependent flips are applied in this same atomic commit
(mirrors PR #63 flipping ADR 0025–0032):

- **ADR-0033** `docs/adr/0033-prompt-injection-eval-suite.md`: **Proposed →
  Accepted** — quoted evidence: the deterministic ED1–ED5 suite is 100% green on
  HEAD (25/25, §1/§3) and this readiness doc is the successor G-SEC sign-off
  ADR-0033 §5 requires.
- **P1-PLAN** `docs/roadmap/P1-PLAN.md`: **W7 → Done; P1 → complete** — every wave
  W0–W7 merged/landed; all five §11 gates pass on the P1-scoped slice; the
  later-phase (P2+) criteria are itemised as deferred-accepted in §2, none
  silently.

---

## 5. Deferrals — named explicitly (none silent)

Every item below is **outside P1 scope by design** (P1-PLAN §1/§6, PRODUCTION.md
§1/§3/§5/§6) and is **not** a P1 release blocker:

1. **ED6 real-LLM injection pass-rate** — no LLM provider on the build host;
   deferred-accepted (no-hardware), PROPOSED ≥90%/class recorded; non-gating.
2. **Live-lab golden-paths** — Vendor Wave 1 device golden-paths (W1), OIDC IdP
   matrix (W2), routing live re-run beyond the recorded 23/25 (W7-T3) — same
   no-hardware deferral as M4/M5; code paths fixture/mock-verified in green suites.
3. **G-REL live/scale drills** — 30-day soak, Postgres failover, certified-scale
   Neo4j rebuild, worker-kill idempotency, Celery soak success — **P2** (ADR-0030 §6).
4. **G-SCA entirely** — HA + autoscaling load/scale tests — **P2** (single-replica
   P1, W4 sign-off).
5. **G-OBS dashboards/alerts/MTTD/SIEM** — SLO measurement P2, enforcement P3,
   SIEM export P2 (PRODUCTION.md §6).
6. **G-MNT N-2 → N upgrade rehearsal** on a seeded prod-shaped dataset — **P2**.
7. **G-SEC external pentest** (pre-GA) and the **recurring 6-month break-glass
   drill** (operational) — GA-time / operational, not a P1 code gate.
8. **CI-only gates** (Trivy image scan, cosign sign/verify, KMS emulator) not
   runnable on this host — CI-gated, confirm green on the merge commit; not fabricated.
9. **Vault status note** — the orchestrator's Obsidian vault P1 status note is
   updated outside this in-repo commit (MEMORY.md "P1 build progress"); flagged
   here so the sync is not silently skipped.

---

## 6. Aggregate verdict

| Gate | P1-scope verdict | Blocking? |
|---|---|---|
| **G-SEC** | **PASS** (prompt-injection 100% green on HEAD; four-eyes/redaction/RBAC/secret-handling PASS; K8s posture PASS; KMS no-leak PASS; Trivy CI-gated) | No |
| **G-REL** | **PASS** (backup/DR baseline + from-backups-alone drill green at seeded scale); live/scale drills P2 | No |
| **G-SCA** | **DEFERRED-ACCEPTED** (entirely P2 — HA/scale-out out of P1 scope) | No |
| **G-OBS** | **PASS** (`/metrics` + probes + trace correlation on every container); dashboards/alerts/SIEM P2/P3 | No |
| **G-MNT** | **PASS** (D16 green, ADR currency incl. 0033, plugin onboarding); N-2 rehearsal P2 | No |

**P1 is declared COMPLETE.** All five §11 gates pass on the P1-scoped criteria
simultaneously on the release HEAD, the prompt-injection control is opened and
green, and every later-phase (P2+) criterion is named as deferred-accepted — none
silent (ADR-0033 §1). The CI-only gates (Trivy, cosign, KMS emulator) must be
confirmed green on the merge commit as the standard release action; the vault
status note is synced outside this commit. No P1-scoped criterion is unmet, so
nothing blocks the phase exit.
