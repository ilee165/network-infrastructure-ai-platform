# P1 Build Plan — Production Hardening (Post-MVP)

**Project:** AI Network Operations Platform
**Status:** IN PROGRESS — W0–W2 shipped (PR #50, `5c85eee P1 W0-W2: design gate (ADRs 0025-0032) + Vendor Wave 1 plugins + OIDC/SSO`); later waves ongoing.
**Authority:** Bound by `CLAUDE.md`, `docs/architecture/DECISIONS-BRIEF.md` (D1–D16), and `docs/roadmap/PRODUCTION.md` §1–§11. Entry condition satisfied: MVP exit = M5 merged (PR #25).
**Scope source:** `PRODUCTION.md` Phase **P1** = Vendor Wave 1 + Platform track (K8s/Helm GA, OIDC/SSO, backup/DR baseline, K8s hardening round 1) + the M5-deferred packet-sandbox OS-isolation half.

---

## 1. Scope

| Track | Deliverables | PRODUCTION.md ref |
|---|---|---|
| Vendor Wave 1 | `cisco_nxos`, `junos`, `bluecat` plugins | §2.2 |
| Platform — orchestration | Kubernetes/Helm GA chart + hardening round 1 | §9, §3.1 |
| Platform — identity | OIDC / SSO (pluggable, D10 half) | §4 |
| Platform — resilience | Backup/DR baseline (drills from P2) | §8 |
| M5 carry-in | Packet-sandbox OS-isolation — clears the PARTIAL M5 security sign-off (ADR-0013 §4 / ADR-0023 §1) | STATUS "Next" |
| Security (P1 subset) | KMS-backed master key, CI dep/secret scanning, SBOM + image signing, API rate-limit/login lockout | §5 P1 items |
| Gates | G-SEC / G-REL / G-SCA / G-OBS / G-MNT re-evaluation | §11 |

HA/scale-out (§3), SIEM export (§5), compliance reporting (§7), and Waves 2–4 vendors are **P2+** — out of P1 scope.

---

## 2. Agent capability review

Roles + model tiers from `.claude/agents/README.md`.

| agentType | Model | P1 use |
|---|---|---|
| `wf-implementer` | strong (inherit) | Novel/security-critical **Python**: OIDC handlers, KMS interface, sandbox isolation runtime, DR data-integrity path, Redis rate-limit/lockout |
| `wf-implementer-light` | sonnet | Template-following: NX-OS/JunOS plugins (mirror Wave-0 netmiko), BlueCat (mirror Infoblox/SpatiumDDI write-path), boilerplate Helm manifests |
| `wf-infra` **(new)** | strong (inherit) | Declarative infra/CI: K8s/Helm GA chart, NetworkPolicy/PSS/admission, packet-sandbox pod profile, backup/DR jobs (pgBackRest/Neo4j drill/pcap snapshot), CI supply-chain (SBOM/cosign/gitleaks). Infra gates, not Python-TDD |
| `wf-eval-designer` | strong | AI-output evals: prompt-injection suite, cross-vendor routing re-run |
| `wf-spec-reviewer` | sonnet* | Spec-compliance review per task |
| `wf-quality-reviewer` | sonnet* | Correctness / secret-leak / convention review per task |
| `wf-fixer` | sonnet* | Apply enumerated review findings |
| `wf-verifier` | sonnet | Confirm fix commit resolves findings |

\* **Escalation rule** (README): secret-handling tasks (auth/RBAC, KMS, credential, leak/exit-criteria tests) escalate reviewers + fixer to **strong (`fable`)**. Nothing in a secret pipeline runs on a downgraded model.

**Infra/DevOps gap — RESOLVED (new agent created):** K8s/Helm/Trivy/SBOM/cosign work is declarative YAML + CI, not Python-TDD; the pytest/ruff/mypy gate discipline baked into `wf-implementer` does not apply, and the original "reuse wf-implementer for infra" call left YAML review depth weaker than code. Created **`wf-infra`** (strong, all-tools, `.claude/agents/wf-infra.md`) with policy-as-test discipline and infra gates (helm lint, kubeconform, kube-linter/kubescape, conftest/OPA, trivy, cosign) and secure-by-default-opt-out baked into its standing prompt. It owns the declarative half of W3–W6; `wf-implementer` keeps the Python half (sandbox runtime, KMS interface, rate-limit). Review watch still holds: escalate `wf-quality-reviewer` to **strong (`fable`)** on NetworkPolicy/PSS/admission/supply-chain tasks (secret-surface + security-semantic YAML).

---

## 3. Build waves (dependency-ordered)

Per-task pattern: **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.** Sequential tasks share files; parallelize only within a task (the two reviews). ADRs numbered from 0025.

| Wave | Tasks | Implementer | Review tier | Notes |
|---|---|---|---|---|
| **W0 — ADRs / scaffold** | ADR-0025+ for: NX-OS / JunOS / BlueCat plugins; OIDC; K8s-GA + hardening; backup/DR; packet-sandbox isolation; KMS interface | `wf-implementer` | sonnet | Design gate; unblocks all waves |
| **W1 — Vendor Wave 1** | `cisco_nxos`; `junos`; `bluecat` | `wf-implementer-light` ×3 (parallel, disjoint files) | sonnet spec + **strong quality** (credential hygiene / leak) | Plugin conformance suite + ≥80% cov + normalized-model round-trip (§2.6). Live-lab golden-path **deferred-accepted** (no hardware) |
| **W2 — OIDC / SSO** | Auth-Code + PKCE IdP flow; IdP group→RBAC map (deny-default); break-glass local-admin + four-eyes on IdP subject; token refresh / logout revoke | `wf-implementer` (strong) | **strong** spec + quality (auth-critical) | IdP test matrix (Keycloak + one cloud IdP) **lab-deferred** |
| **W3 — Packet sandbox + K8s hardening R1** | Sandbox OS-isolation (non-root, dropped caps, NET_RAW node-pool, seccomp, default-deny egress); PSS `restricted` + readOnlyRootFS + resource limits + K8s RBAC least-priv | `wf-infra` (pod profile + PSS/RBAC YAML) + `wf-implementer` (sandbox runtime hooks in Python) | **strong** quality | Clears M5 PARTIAL packet-sandbox sign-off |
| **W4 — Helm / K8s GA chart** | Per-service Deployments + NetworkPolicies (§3.1 topology; HA replicas excluded → P2); hardened-default values + cert-manager TLS ingress + admission policy | `wf-infra` (strong — NetworkPolicy/admission) + `wf-implementer-light` (boilerplate manifests) | strong | Secure-by-default = opt-out, never opt-in |
| **W5 — Backup / DR baseline** | pgBackRest (WAL + full/incr to MinIO); Neo4j rebuild-drill job (emits topology-RTO metric); pcap volume snapshot | `wf-infra` (strong — backup jobs/CronJobs; audit-integrity path) | **strong** quality | Drills run from P2; RPO ≤ 5 min / RTO ≤ 1 h PROPOSED targets |
| **W6 — Security hardening (P1 subset)** | Master key → KMS via D11 interface + rotation/re-wrap; CI pip-audit + npm-audit + gitleaks + SBOM (syft) + cosign signing; Redis-backed rate-limit + login lockout | `wf-implementer` (KMS interface + rate-limit, Python) + `wf-infra` (CI supply-chain pipeline) | **strong** spec + quality | All secret-surface → escalated |
| **W7 — Evals + gate verification** | Prompt-injection eval suite (100% no-unauthorized-tool-call); cross-vendor eval re-run (3 new plugins, no regression); G-* gate evidence doc + readiness | `wf-eval-designer` (strong) | sonnet | Phase-exit gate; mirrors M5 T18/T20 |

---

## 4. Sequencing

- **W0 first** — blocks all (ADRs are the design contract).
- **W1** (3 plugins, internal parallel) can run **concurrent with W2** (auth) — disjoint files.
- **W3 → W4** ordered: sandbox profile feeds the chart's PSS deviation.
- **W5, W6** after W4 — need chart deploy targets + namespaces.
- **W7 last** — needs all plugins + auth + infra in place to evaluate.

---

## 5. Per-wave exit criteria

Vendor waves (W1): PRODUCTION.md §2.6 — conformance suite green, raw artifacts stored verbatim, normalized models round-trip, write paths via ChangeRequest, docs + API docs published, ≥80% cov, no cross-vendor eval regression.

Platform waves: relevant §11 gate criteria green (G-SEC for W2/W3/W6, G-REL for W5, G-OBS/G-MNT continuous). Phase P1 complete only when all five gates pass simultaneously on the release HEAD.

---

## 6. Open items (non-blocking, carry forward)

- **Consultant §12 answers** (scale targets, HA/DR expectations, SSO provider, data retention) — PROPOSED defaults hold; re-check at W0 kickoff against `docs/consultant/QUESTIONS.md`.
- **Live-lab deferred-accepted** (no hardware): vendor golden-paths (W1), OIDC IdP matrix (W2). Same posture as M4/M5 — code paths mock/fixture-verified in the green eval suite.
- **DR drills** (restore-from-backup timing): build the baseline in P1; execute drills from P2.
