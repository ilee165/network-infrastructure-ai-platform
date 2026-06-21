# W6-T2 — KMS Backends (AWS / Azure / Vault Transit) + Prod-Grade Gating

| | |
|---|---|
| **Wave** | P1 W6 — Security hardening (P1 subset) |
| **Owner** | `wf-implementer` (strong — Python, secret-surface) |
| **Review tier** | **strong** spec + **strong** quality |
| **Depends on** | W6-T1 (wrap/unwrap interface) |
| **ADRs** | ADR-0032 §2, §1 (AAD per backend), §4 (health/readiness) |
| **PRODUCTION.md** | §5 (KMS — Vault/cloud KMS/HSM customer choice), §9 (external-secrets/CSI), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement the three first-class production KMS backends behind the W6-T1 `KeyProvider` contract —
`AwsKmsKeyProvider`, `AzureKeyVaultKeyProvider`, `HashiCorpVaultTransitKeyProvider` — selectable by
config only, with the local Env/File providers barred from production. Wire `health()` to the K8s
readiness probe and `/metrics`. CI validates against local emulators/fakes; real-KMS validation is
customer-environment / lab-deferred.

## Scope

**In**
- `AwsKmsKeyProvider` — `kms:Encrypt`/`Decrypt`; row-id via **native `EncryptionContext={row_id}`**;
  IAM role / IRSA auth (no static keys); `key_arn` config only.
- `HashiCorpVaultTransitKeyProvider` — `transit/encrypt|decrypt/<key>`; row-id via native
  `context={row_id}`; Kubernetes-auth/AppRole → short-lived token via `credential_ref`, auto-renew;
  `kek_version = <key>:vN`; decrypt accepts old versions.
- `AzureKeyVaultKeyProvider` — `wrapKey`/`unwrapKey` (RSA-OAEP / AES-KW) has **no native AAD**, so
  bind row-id via a **local AESGCM inner layer** (`aad=row_id`, fresh 96-bit nonce, DEK as
  plaintext), then `wrapKey` the inner key; `unwrapKey` reverses and the AESGCM open **fails** on a
  row-id mismatch. `WrappedDek.ciphertext` carries `(inner-nonce ‖ wrapped-inner-key ‖
  inner-ciphertext)`; the single-blob schema is unchanged (ADR-0032 §1).
- Config-only selection: `VAULT_KEY_PROVIDER` + provider-scoped settings; credential service stays
  **provider-agnostic, never branches on backend** (ADR-0032 §2). All auth referenced indirectly
  (IAM role / managed identity / `credential_ref`) — **no token/key/secret inlined**.
- **Prod-grade gating** (ADR-0032 §2, secure-by-default-opt-out): a `production`/`is_prod` flag
  makes the credential service **refuse to start** on a local provider —
  `RuntimeError("local KeyProvider '<name>' is not permitted in production; configure a KMS backend
  (D11/ADR-0032 §2)")`. Provider self-reports `is_production_grade`; surfaced on the startup banner,
  `/metrics` (`vault_key_provider_production_grade`), and the G-SEC evidence doc.
- **Health → readiness** (ADR-0032 §4): `provider.health()` feeds the K8s readiness probe (a
  replica that can't reach its KMS is pulled from rotation, stays *live*, alerts fire) and
  `/metrics`.
- CI fakes/emulators (ADR-0032 Negative): LocalStack KMS, an Azurite-style fake, a dev Vault Transit
  container, plus a deterministic in-memory fake provider for unit tests.

**Out**
- The wrap/unwrap interface + fail-closed credential-service semantics (W6-T1).
- The `re_wrap_keys` rotation job (W6-T3) — though each provider's `kek_version` rotation *model*
  (the §2 table column) is implemented here so T3 can drive it.
- `Pkcs11KeyProvider` / HSM — explicitly out of P1 (ADR-0032 §2 / Alt #4); the interface admits it
  with no schema change.

## Requirements (grounded in ADR-0032 §2, §1)

1. **Backend-agnostic AAD binding** (ADR-0032 §1): row-id bound on **every** backend — natively via
   `EncryptionContext`/`context` (AWS/Vault), via the local AESGCM inner layer (Azure). The
   cross-row-replay guarantee must hold identically across all three (assert it in tests).
2. **No KEK export, no `GenerateDataKey`** (carried from W6-T1): providers wrap/unwrap a
   *locally-generated* DEK; the KEK never leaves the KMS.
3. **Local fallback is explicitly NOT production** (ADR-0032 §2): the prod flag bars Env/File; the
   non-prod-grade status can never hide behind a green deploy (banner + metric + evidence doc).
4. **Config swap, not code swap** (ADR-0032 Consequences): switching AWS↔Azure↔Vault is
   `VAULT_KEY_PROVIDER` + scoped settings only; the credential service does not change.
5. **Errors wrapped** (carried from W6-T1 §6): a raw boto3/azure/hvac exception (which can echo
   request context) never surfaces verbatim — only typed `KeyProviderError(reason_class)`.
6. **Real-KMS lab-deferred** (ADR-0032 Negative / P1-PLAN.md §6): CI green against emulators/fakes;
   real-cloud-KMS validation is the customer environment.

## Contracts / artifacts

- `backend/app/core/crypto.py` (or a `crypto/providers/` package) — the three providers + the fake;
  `get_key_provider(settings)` extended to select by `VAULT_KEY_PROVIDER`.
- Settings additions (`app/core/config.py`): `VAULT_KEY_PROVIDER`, `key_arn` / `vault_uri`+`key_name`
  / Vault `transit` settings, `is_prod`; all secret-material referenced, never inlined.
- `/metrics` gauges: `vault_key_provider_production_grade`, `vault_key_provider_healthy`.
- Helm wiring delta: readiness probe consults provider health; prod flag set in-chart, off in compose.
- Dev/CI compose for LocalStack KMS / Azurite-fake / dev Vault Transit.

## Test & gate plan (Python TDD + emulators)

- ruff / mypy strict / import-linter / pytest ≥80% on touched modules.
- Per backend (against emulator + the deterministic fake): wrap→unwrap round-trip; **wrong row-id
  `aad` fails** (replay guard) — including the Azure inner-AESGCM path; old-version decrypt accepted
  (AWS/Vault); `kek_version` shape matches the §2 table.
- Prod-grade gating: `is_prod=true` + local provider ⇒ refuse-to-start `RuntimeError`; KMS provider
  ⇒ starts; `is_production_grade`/metric correct for each.
- Health/readiness: unreachable emulator ⇒ `health()` unhealthy ⇒ readiness fails, replica stays
  live; reachable ⇒ healthy.
- No-leak: provider client repr scrubbed; raw SDK exceptions never re-raised; `credential_ref` value
  never logged (extends W6-T1 `test_no_key_material_leak`).

## Exit criteria

- [ ] Three KMS providers implement the wrap/unwrap contract; row-id AAD bound on each (native /
      inner-AESGCM), cross-row replay blocked on all three (G-SEC).
- [ ] Selection is config-only; credential service never branches on backend.
- [ ] Prod flag refuses local providers in production; non-prod-grade surfaced on banner + metric +
      evidence doc.
- [ ] `health()` drives readiness + `/metrics`; unreachable KMS ⇒ not-ready, stays live.
- [ ] CI green against LocalStack / Azurite-fake / dev Vault + the deterministic fake; real-KMS
      lab-deferred and documented.
- [ ] No-leak gate extended and green; D16 gates green.

## Workflow (P1-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** in parallel → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- A new **hard runtime dependency on the KMS** for every credential read/write (ADR-0032 Negative):
  KMS outage halts credentialed device ops — mitigated by W6-T1 fail-closed + retry + this task's
  readiness gating; the local-fallback that would soften it is barred from prod by design.
- The Azure inner-AESGCM AAD layer is the subtlest correctness point — a bug there silently drops
  the replay guard; the wrong-row-id test on the Azure path is the guardrail and must be present.
