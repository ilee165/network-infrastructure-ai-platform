# P1 W6 Build-Plan Note — Security Hardening (P1 subset)

**Wave:** P1 W6 (Security hardening) — `docs/roadmap/P1-PLAN.md` §3 row W6.
**Task specs:** `docs/roadmap/p1-tasks/W6-T1..T6` (already on main; this note is the wave-level orchestration over them).
**Design contracts:** ADR-0032 (KMS master-key wrap/unwrap), ADR-0016 (D16 CI pipeline), ADR-0029 (K8s admission), ADR-0028 (OIDC throttling/break-glass), ADR-0010/0008/0011 (auth/Redis/credential-audit).
**Status:** Planned. Entry condition met: W3/W4/W5 merged to main (`dbf1059` = HEAD). W6 needs the W4 chart (admission slot for T5) + the live decrypt path / `device_credentials` schema (KMS track) — all present.
**Authority:** Bound by `CLAUDE.md` (secure-by-default, audit-everything, human-approval), `PRODUCTION.md` §5 / §9 / §11, and the cited ADRs.
**Binding constraint:** every default is the *secure* value (fail-closed KMS, gates that bite, admission on-by-default, login-lockout fail-conservative). Secrets are referenced by indirection, never inlined into code/manifest/log/commit.

> **Read first — strong-model escalation (corrected):** `fable` is UNAVAILABLE. Every secret-surface escalation in this wave runs on **`opus`** (the session strong model), tracked as one session-scoped `STRONG` constant in the workflow script — never inline `model: 'fable'`. A dead-model escalation returns a silently "clean" review (P1 W0 false-clean root cause). See `.claude/agents/README.md` → Escalation rule (fixed this session).

---

## 1. Scope

In scope (PRODUCTION.md §5 security-hardening subset):

- **KMS track (ADR-0032):** narrow `KeyProvider` to a wrap/unwrap (KMS-envelope) contract with a fail-closed credential service (T1); three production backends — AWS KMS / Azure Key Vault / Vault Transit — with prod-grade gating + health→readiness (T2); master-key rotation as a KEK-bump + idempotent DEK re-wrap job with key-access audit (T3). **No Alembic migration** — `wrapped_dek`/`kek_version` already exist.
- **CI supply-chain track (PRODUCTION.md §5, ADR-0016):** pip-audit + npm audit + gitleaks (working tree **and** history) as gating jobs with reviewed/expiring allowlists (T4); syft SBOM + cosign signing + admission signature-verification + Trivy gate raised to CRITICAL+HIGH at release (T5).
- **Auth track (PRODUCTION.md §5, ADR-0028):** Redis-backed per-user/per-token API rate-limit (429 + `Retry-After`) + local break-glass login throttle/lockout + OIDC-callback per-source throttle, audited, no account-existence leak (T6).

Explicitly OUT of scope (do not pull forward):

- **`Pkcs11KeyProvider` / HSM backend → out of P1** (ADR-0032 §2 / Alt #4); the interface admits it with no schema change.
- **Real cloud-KMS validation → customer-environment / lab-deferred** (ADR-0032 Negative); CI validates against LocalStack KMS / Azurite-fake / dev Vault Transit + a deterministic in-memory fake.
- **KEK escrow / key-recovery drill → PRODUCTION.md §8 (separate).**
- **Per-credential device-secret rotation** (`rotate_secret`, changes `ciphertext`/`nonce`) — exists; T3 must NOT disturb it. T3 rotates the *wrapper*, not the secret.
- **WAF / edge rate-limiting** (infra concern) and the **four-eyes/RBAC** logic (M5/W2, unchanged).

---

## 2. Task decomposition

Per-task workflow pattern (P1-PLAN §3): **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.** Reviews parallelize *within* a task; file-sharing tasks are *sequential*.

| Task | Deliverable | Owner | Depends on |
|---|---|---|---|
| **W6-T1 — KeyProvider wrap/unwrap interface + fail-closed credential service** | Replace the `KeyProvider` Protocol with the ADR-0032 §1 `kek_version`/`wrap_dek`/`unwrap_dek`/`health` contract (no KEK byte-export on the network path); re-home `Env`/`File` providers as in-process wrap/unwrap implementers; bind row-id AAD at the KEK→DEK layer; fail-closed `KeyProviderUnavailable` (503-class) on writes + CR→`failed` on unwrap failure, no plaintext-DEK cache; `kek.wrap/unwrap/provider.unavailable/provider.select` audit; redactors + typed `KeyProviderError`; `test_no_key_material_leak`. **No migration.** | `wf-implementer` (strong) | — (foundation) |
| **W6-T2 — KMS backends + prod-grade gating** | `AwsKmsKeyProvider` (native `EncryptionContext`, IRSA), `HashiCorpVaultTransitKeyProvider` (native `context`, k8s-auth/AppRole short-lived token), `AzureKeyVaultKeyProvider` (no native AAD → local AESGCM inner layer binding row-id); config-only selection (`VAULT_KEY_PROVIDER`), credential service never branches on backend; prod flag **refuses local providers in production** (surfaced on banner + `vault_key_provider_production_grade` metric + evidence doc); `health()`→readiness probe; LocalStack/Azurite-fake/dev-Vault + deterministic in-memory fake for CI. | `wf-implementer` (strong) | T1 |
| **W6-T3 — Master-key rotation / DEK re-wrap job + key-access audit** | `re_wrap_keys` worker job: stream rows where `kek_version != active`, `unwrap` under old → `wrap` under active → **compare-and-set** UPDATE → zeroize DEK; `ciphertext`/`nonce` byte-identical (proven); idempotent + resumable; mixed-version corpus decrypts online (no maintenance window); `kek.rotate.start/complete` audit (versions/counts only); rotation-status endpoint (`{from_version,to_version,rows_pending}`, no blobs, RBAC engineer+). | `wf-implementer` (strong) | T1 (T2 for KMS-version semantics + the deterministic fake; no hard import) |
| **W6-T4 — CI dependency + secret scanning** | `pip-audit` (backend) + `npm audit` (frontend, fail on high+) + `gitleaks` (tree **and** history) as gating jobs in `.github/workflows/ci.yml`; reviewed allowlists with justification+expiry (`.gitleaks.toml`, pip/npm ignore lists) mirroring the `.trivyignore` convention; pinned action SHAs; `docs/security/supply-chain-scanning.md`. Each gate demonstrably BITES (planted negative) then reverted. | `wf-infra` | — (independent CI slice; lands before T5) |
| **W6-T5 — SBOM + cosign signing + admission verify + Trivy raise** | syft SBOM per image (artifact, PROPOSED cosign attestation); cosign-sign both images on main/tags (keyless OIDC or external key-ref, never inlined); admission policy (cosign policy-controller / Kyverno verifyImages) under `security.imageVerification.enabled` (default true) so the cluster admits **only signed images**; **Trivy gate raised to CRITICAL+HIGH at release** (extend, don't drop, the reviewed `.trivyignore`); `docs/security/image-supply-chain.md`. Policy test: signed admits / unsigned rejects; cosign `verify` proves the chain. | `wf-infra` | T4 (same `ci.yml` docker job), W4 (admission controller in chart) |
| **W6-T6 — Redis-backed API rate-limit + login throttle/lockout** | Redis-backed per-user **and** per-token rate-limit dependency/middleware (429 + `Retry-After`, holds across replicas); local break-glass progressive throttle → temporary lockout (per-account + per-source, audited, alerting-friendly); OIDC-callback per-source throttle (coordinate with ADR-0028 §63 JWKS-refresh limiter, don't duplicate); `auth.rate_limited`/`auth.login_locked` audit (ids/source/outcome only); **explicit fail-modes: API limiter fail-open, login lockout fail-conservative**; no account-existence leak; O(1)/non-contended (G-SCA-safe). | `wf-implementer` (strong) | — (independent; auth/middleware files) |

**Reviewer escalation (P1-PLAN §2/§3 + `.claude/agents/README.md`):**
- **T1, T2, T3, T6 — secret/auth surface → strong (`opus`) spec + strong (`opus`) quality + strong (`opus`) fixer.** Nothing in the KMS/auth pipeline runs downgraded.
- **T4, T5 — sonnet spec + strong (`opus`) quality** (supply-chain config is security-semantic CI but not a live secret path; the spec side is mechanical, the quality side is escalated). Fixer escalates to `opus` only if findings touch secret/signing material.
- Verifier (`wf-verifier`, sonnet) confirms each fix commit — read-only, behind the implementer's gates.

---

## 3. Streams & sequencing

Three **disjoint streams** run concurrently across owners; only the two reviews inside a task serialize.

```text
KMS stream  (wf-implementer, Python, crypto.py + credentials/service.py — SHARED files ⇒ serial):
    T1  ──►  T2  ──►  T3
            (T3 needs T2's deterministic fake + kek_version model; run T2 then T3)

CI  stream  (wf-infra, .github/workflows/ci.yml + chart admission — SHARED ci.yml ⇒ serial):
    T4  ──►  T5

Auth stream (wf-implementer, Python, api/deps + api/v1/auth.py — independent):
    T6  (standalone)
```

- **KMS:** T1 is the foundation (T2 + T3 build on its contract). T2 and T3 both edit the crypto/credentials modules, so run **T1 → T2 → T3 serial** (file-sharing). T3 reads T2's `kek_version` version-shape + uses its deterministic fake provider in tests, but does not import the concrete backends.
- **CI:** T4 (scanning jobs) before T5 (SBOM/signing/Trivy-raise extends the same `ci.yml` docker stage and the W4 admission slot).
- **Auth:** T6 touches only auth/middleware — independent of both other streams; can run any time.
- **Cross-stream:** none of the three streams share files, so they may launch in parallel (subject to the session/token budget — see §6).

---

## 4. Agent / model assignment

| Agent | Model | W6 tasks | Rationale |
|---|---|---|---|
| `wf-implementer` | strong (inherit) | T1, T2, T3, T6 | Core/novel Python: KMS envelope crypto, fail-closed credential service, rotation/re-wrap concurrency, Redis rate-limit/lockout auth logic. The README role table lists "crypto, auth" as exactly this role's remit. T2 has a small infra surface (readiness-probe Helm delta + emulator compose) but is Python-dominant — kept as one task, all-tools strong implementer. |
| `wf-infra` | strong (inherit) | T4, T5 | Declarative CI / supply-chain + admission policy; policy-as-test, not Python-TDD. The role's description explicitly covers "SBOM, image signing, dependency/secret scanning" and the `cosign verify` gate. **Improved this session** with new-gate "prove-it-passes + prove-it-bites, locally-first" discipline (W4 L1/L2) — directly the T4/T5 risk. |
| `wf-spec-reviewer` | **T1/T2/T3/T6: strong (`opus`)**; T4/T5: sonnet | every task | Spec-compliance review. Escalated on the secret/auth surfaces. |
| `wf-quality-reviewer` | **strong (`opus`)** | every task | Correctness/secret-leak/async/error-handling review; its description already centers "secret leakage". Escalated on all six (supply-chain quality is security-semantic). |
| `wf-fixer` | T1/T2/T3/T6: **strong (`opus`)**; T4/T5: sonnet→`opus` if secret-touching findings | conditional | Applies enumerated must-fix findings only. |
| `wf-verifier` | sonnet | per fixed task | Confirms the fix commit resolves findings; read-only behind the gates. |

**New agent required? No.** The existing roster covers all six W6 tasks — `wf-implementer` owns the Python KMS/auth work (its remit names crypto + auth), `wf-infra` owns the CI/admission supply-chain (its remit names SBOM + signing + dep/secret scanning), and the four review/fix/verify roles complete the per-task pattern. Inventing a new agent would add surface without new capability. Two **improvements** were made instead (see §7).

---

## 5. Gates

Two gate disciplines in this wave — Python-TDD (KMS + auth) and infra policy-as-test (CI supply-chain).

| Track | Gate set (per task, before its atomic commit) | Pass condition |
|---|---|---|
| KMS / Auth (T1,T2,T3,T6) | ruff (check + format), mypy strict, import-linter, pytest ≥80% on touched modules | all green; `test_no_key_material_leak` green on the **strong** tier (T1→T2→T3); fail-closed / wrong-AAD-replay / byte-identical-ciphertext / fail-mode tests present and green |
| CI supply-chain (T4,T5) | the new scanners + signing run green on the tree (or with justified/expiring allowlist); each gate **bites** on a planted negative then reverts; `helm lint` / `kubeconform` / `conftest` render clean with verify-images on-by-default; cosign `verify` succeeds on signed / fails on unsigned; actions pinned | gates RED on a real finding, GREEN clean; conftest asserts verify-images policy present + not disabled |

**PRODUCTION.md §11 gate mapping:** **G-SEC** (KMS no-leak + signed-image admission + fail-closed — primary), **G-SCA** (T6 rate-limit holds under 100-concurrent / p95<300 ms; supply-chain scanning), **G-MNT** (dep/secret scanning maintainability). G-OBS continuous (health→readiness + `/metrics` gauges from T2).

**Host-tooling honesty (carry-forward):** trivy / cosign / helm / syft / gitleaks are NOT on this build host. Per W4 L1, T4/T5 must say so explicitly and lean on CI / rendered / emulated equivalents — do not assume a CI run passes. KMS emulators (LocalStack/Azurite-fake/dev-Vault) run in CI compose; the deterministic in-memory fake is what unit tests use locally.

---

## 6. Carry-forward from W4/W5 (apply up front)

From `P1-W4-LESSONS.md` + `p1-tasks/README.md` carry-forward table — these recur in W6:

- **L1 (new gating tool):** run it locally where it installs; prove it bites; local gate set ≠ CI gate set. → **T4, T5.** (Now baked into the `wf-infra` definition.)
- **L2 (sanctioned deviations):** raise Trivy by scope-suppressing only sanctioned findings on the one step + a stronger conftest rule; never globalize/weaken. → **T5.**
- **L4 (helm secret idempotency):** KMS dev secrets reuse-or-generate via `lookup` (empty in CI, reused on upgrade). → **T2** chart wiring.
- **L5 (CI pipe masks exit):** `set -o pipefail` + `test -s` on any `cmd | filter > file`. → **T4/T5** piped CI steps.
- **L6 (`gh pr merge` fatal):** local-checkout fatal under sibling worktrees is harmless — verify `gh pr view --json state` MERGED, then `git push origin --delete`. → merge step.
- **L7 (session windows):** one-atomic-commit-per-task survives session-limit kills; resume via `resumeFromRunId`. KMS is 3 serial Python tasks + 2 CI + 1 auth = a multi-window run; commit per task.
- **L8 (agent registry):** confirm `wf-implementer` + `wf-infra` are in the LIVE registry before launch (W4 hit `wf-infra` on-disk-but-unloaded; it is loaded now — re-confirm at launch).
- **Backend gates run from `backend/`**, tools at `backend/.venv/Scripts/*.exe` (not on PATH); run ruff/format AND pytest. App-level pytest needs `authlib` (pre-existing env gap noted in W5).

---

## 7. Agent review outcome (this session)

Reviewed all roles the W6 specs assign against the six tasks. **No new agent needed**; two improvements made to prevent known failure modes:

1. **`.claude/agents/README.md` — Escalation rule:** removed the dead `model: 'fable'` literal; replaced with a session-scoped `STRONG` constant + an explicit "fable is unavailable → use `opus`; a dead-model escalation silently returns a clean review (P1 W0 root cause); stop if STRONG can't resolve to a live model." This is the single highest-impact fix — W6 escalates 4 secret-surface tasks, and the old example pointed every one of them at a dead model.
2. **`.claude/agents/wf-infra.md` — discipline:** added the new-gating-tool rule (prove-it-passes-clean **and** prove-it-bites on a planted negative, locally-first where the tool installs, say-so where it doesn't) and the raise/scope rule (suppress only sanctioned deviations + back with a stronger conftest rule). Directly the T4/T5 risk surface (W4 L1/L2), now standing discipline rather than per-prompt boilerplate.

Also corrected the live W6 task index (`p1-tasks/README.md`) escalation note `fable` → session strong (`opus`). The historical `P1-W4-PLAN.md` `fable` references are left as a completed-wave artifact.

The `wf-implementer`, `wf-quality-reviewer`, `wf-spec-reviewer`, `wf-fixer`, `wf-verifier` definitions need no change: they are model-agnostic (escalation via `opts.model`), and the quality reviewer already centers secret-leakage review.

---

## 8. Exit criteria

W6 is complete when **all** hold on the wave HEAD:

1. **KMS interface (T1):** `KeyProvider` is the wrap/unwrap/health contract; Env/File re-homed; **no migration**; AAD bound at KEK→DEK (interface requires `aad`, non-supporting provider rejects it); DEK still generated locally (no `GenerateDataKey`, no byte-export); vault fails closed on unreachable provider (writes + reads + CR→failed, no DEK cache); `kek.*` audited (ids/versions only); `test_no_key_material_leak` green (strong tier).
2. **KMS backends (T2):** AWS/Azure/Vault implement the contract; row-id AAD bound on each (native / inner-AESGCM), cross-row replay blocked on all three; selection config-only, service never branches on backend; prod flag refuses local providers (banner + metric + evidence); `health()` drives readiness + `/metrics`; CI green on emulators + the deterministic fake; real-KMS lab-deferred + documented; no-leak gate extended.
3. **Rotation (T3):** `re_wrap_keys` migrates DEKs to active KEK with `ciphertext`/`nonce` **byte-identical** (proven); idempotent, resumable, compare-and-set; mixed-version corpus decrypts online; `kek.rotate.*` audited (versions/counts only); status endpoint exposes no blobs; per-credential rotation untouched; no-leak gate extended; procedure documented (rehearsed-ready, PRODUCTION.md §5).
4. **CI dep/secret scan (T4):** pip-audit + npm audit + gitleaks are **gating** in the D16 pipeline; gitleaks scans tree **and** history; allowlists reviewed with justification/expiry; each gate demonstrably bites then reverts; tool/action versions pinned; thresholds + triage documented.
5. **Image supply-chain (T5):** syft SBOM generated + retained (PROPOSED attested) per image; images cosign-signed on publish (key/identity referenced, never inlined); admission admits **only signed images**, on by default, unsigned rejected (proven); Trivy raised to zero CRITICAL+HIGH at release (accepted findings only via reviewed `.trivyignore`); cosign `verify` proves the chain; infra + CI gates green; documented.
6. **Rate-limit/lockout (T6):** Redis-backed per-user **and** per-token limit (429 + `Retry-After`, holds across replicas); break-glass throttle + temporary lockout (audited, alerting-friendly); OIDC-callback per-source throttle; no account-existence leak; no token material in logs/audit; explicit fail-modes (API fail-open, lockout fail-conservative) both tested; O(1)/non-contended (G-SCA-safe); documented.
7. **Gates green:** D16 (ruff/mypy/import-linter/pytest) + infra (helm lint/kubeconform/conftest/trivy/cosign) + the new scanners all green in CI; **G-SEC** evidence produced (KMS no-leak + signed-image admission + fail-closed); G-SCA/G-MNT green.
8. **Escalation honored:** every secret/auth-surface review ran on the live strong model (`opus`), not `fable`; no escalated review silently fell through to a dead/weaker model.
9. Each of T1–T6 landed as **one atomic commit**, spec+quality review resolved at the assigned tier, verifier-confirmed.

---

## 9. Risks & carry-forward

- **Dead-model escalation (the carried W0 trap):** the original escalation example pointed at `fable` (unavailable); a dead-model review returns silently "clean". **Mitigated** by the §7 README/index fixes; verify at launch that `STRONG` resolves to a live model and that escalated reviews actually ran (not cache-replayed stale verdicts — W5 gotcha: `resumeFromRunId` can mark a stale "needs-attention").
- **KMS becomes a hard runtime dependency** (ADR-0032 Negative): a KMS outage halts credentialed device ops. Mitigated by T1 fail-closed + Celery retry + T2 readiness gating; the local fallback that would soften it is barred from prod by design.
- **Azure inner-AESGCM AAD layer** is the subtlest correctness point (no native AAD) — a bug silently drops the cross-row replay guard. The wrong-row-id test on the Azure path is mandatory (T2).
- **Re-wrap touching `ciphertext`/`nonce`** would silently corrupt the credential corpus — the byte-identical assertion is the guardrail (T3); compare-and-set guards the per-credential-rotation race.
- **Admission verify on-by-default can self-inflict a deploy outage** if signing/verify is mis-wired — the signed-admits/unsigned-rejects policy test + a documented break-glass for the bootstrap window guard against it, without making verification opt-in (T5).
- **Raising Trivy to HIGH surfaces base-image OS CVEs** (cf. `docs/security/2026-06-14-trivy-baseimage-cves.md`) — triage via reviewed `.trivyignore`, never by lowering the gate (T5, W4 L2).
- **Rate-limit fail-mode footgun:** wrong choice = lockout-bypass or API outage on a Redis blip — the explicit fail-open-API / fail-conservative-lockout split + its tests are the guardrail; a global hot key would make the limiter a G-SCA bottleneck, so key by principal/token (T6).
- **Host tooling absent** (trivy/cosign/helm/syft/gitleaks): CI is the real gate for T4/T5; state it, don't fake-green (W4 L1).
- **Live-cluster + real-KMS apply deferred-accepted** (same posture as prior waves): render/lint/conftest/emulator-verified in CI; real `helm install` + real cloud-KMS run from P2 / customer environment.
