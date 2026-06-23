# P1 W6 — G-SEC Evidence: KMS backends + prod-grade gating (W6-T2)

| | |
|---|---|
| **Gate** | G-SEC — KMS no-leak + fail-closed + non-prod-KEK-cannot-hide (PRODUCTION.md §11) |
| **Wave / task** | P1 W6-T2 (builds on W6-T1 wrap/unwrap contract) |
| **ADRs** | ADR-0032 §1 (per-backend AAD), §2 (config-only swap + prod gate), §4 (health→readiness), §6 (no-leak) |
| **Status** | Offline unit + emulator validation **GREEN**; real-cloud-KMS validation **lab-deferred** |

## What was proven (P1)

Three first-class production KMS backends implement the **same** W6-T1
`KeyProvider` wrap/unwrap/health contract, selectable by config alone, with the
local Env/File providers barred from production:

1. **`AwsKmsKeyProvider`** — `kms:Encrypt`/`Decrypt`; the credential **row-id is
   bound natively** via `EncryptionContext={row_id}`. Auth is IRSA/IAM role from
   the pod's ambient credentials (no static keys); the key is referenced by ARN
   only. `kek_version` is the key ARN.
2. **`HashiCorpVaultTransitKeyProvider`** — `transit/encrypt|decrypt`; row-id
   bound natively via `context={row_id}`. The short-lived token comes from a
   k8s-auth/AppRole login keyed by an **indirect `credential_ref`** (never a
   token value); `kek_version = <key>:vN` and **decrypt accepts old versions**.
3. **`AzureKeyVaultKeyProvider`** — `wrapKey`/`unwrapKey` has **no native AAD**,
   so the row-id is bound by a **local AESGCM inner layer**: a fresh inner key
   seals the DEK with `aad=row_id` (fresh 96-bit nonce), then the inner key is
   `wrapKey`-wrapped. `WrappedDek.ciphertext = inner-nonce ‖ wrapped-inner-key ‖
   inner-ciphertext`; the single-blob schema is unchanged (ADR-0032 §1). The
   AESGCM open **fails on a row-id mismatch**, giving the identical cross-row
   replay guard the native backends get.

### Cross-row replay guard holds identically on ALL THREE

The W6-T1 guarantee — a wrapped DEK lifted from row A cannot be unwrapped under
row B's AAD — is asserted per backend, **including the Azure inner-AESGCM path**:
`tests/core/test_kms_providers.py::test_wrong_row_id_aad_fails_cross_row_replay_guard`
is parametrized over `aws`, `vault`, and `azure`, plus a dedicated
`test_azure_tampered_inner_ciphertext_fails` for the inner layer (the subtlest
correctness point — a bug there silently drops the guard).

### Config-only selection; service never branches on backend (ADR-0032 §2)

`get_key_provider(settings)` selects the backend from `NETOPS_VAULT_KEY_PROVIDER`
alone; the credential service (`app/services/credentials/service.py`) is
unchanged and provider-agnostic — it composes `KeyProvider` and never inspects
which backend is configured. Switching AWS↔Azure↔Vault is a values/env edit, not
a code edit.

### Prod-grade gating: a non-production KEK cannot hide behind a green deploy

`require_production_grade(provider, is_prod=...)` refuses to start the credential
service on a local Env/File provider in production:

```
RuntimeError: local KeyProvider 'EnvKeyProvider' is not permitted in production;
configure a KMS backend (D11/ADR-0032 §2)
```

The provider self-reports `is_production_grade` (True for AWS/Azure/Vault/the
deterministic fake; False for Env/File). The posture is surfaced on **three**
independent surfaces so it can never silently regress:

- **Startup banner** — `kek.provider.banner` log line carries `provider`,
  `kek_version`, `production_grade`, `is_prod`.
- **`/metrics`** — `vault_key_provider_production_grade` (1/0) and
  `vault_key_provider_healthy` (1/0) gauges (`app/core/metrics.py`).
- **This evidence doc** + the `kek.provider.select` audit row (ids/versions only).

### health() drives the K8s readiness probe (ADR-0032 §4)

`/api/v1/health/ready` adds a `kek_provider` dependency (only when a provider is
configured) driven by `provider.health()`. An unreachable KMS makes readiness
**degraded** — the replica is pulled from rotation — while **liveness stays
green**, so the replica stays *live* and alerts fire instead of the pod being
killed. The 0/1 `vault_key_provider_healthy` gauge is refreshed from each probe.
Asserted by `tests/test_health.py::test_ready_degrades_when_kek_provider_unreachable`.

### No-leak (ADR-0032 §6) — extended to the KMS backends

- Raw boto3/azure/hvac exceptions are **never re-raised verbatim**: every backend
  call is wrapped as a typed `KeyProviderUnavailable` (unreachable) or
  `KeyProviderError` (other) carrying only the exception's **class name** —
  proven by `test_raw_sdk_exception_never_surfaces_verbatim` (the raw
  "unreachable" message must not appear in `str`/`repr`).
- Provider `__repr__` is `<ClassName:kek_version>` — no key handle, ARN, vault
  URI, or `credential_ref` value.
- The `credential_ref` value never appears in `repr`, `health().detail`, or any
  exception — `test_vault_credential_ref_value_never_in_health_or_errors`.
- `test_crypto.py::test_no_key_material_leak_kms_backends` extends the W6-T1 §6
  exit gate across all three backends + the fake.

### No KEK export, no GenerateDataKey (carried from W6-T1)

The DEK is generated locally (`AESGCM.generate_key` in `envelope_encrypt`); the
providers only wrap/unwrap it. There is no `get_kek()`/`export()` on the
contract, and no provider calls KMS `GenerateDataKey` — the KEK never leaves the
KMS.

## How it was validated (and what is deferred)

| Layer | Status | Notes |
|---|---|---|
| **Deterministic in-memory fake** (`FakeKmsKeyProvider`) + per-backend fake clients | ✅ GREEN | The offline unit suite drives the real wrap/unwrap logic (incl. the Azure inner-AESGCM layer) at full coverage with NO cloud SDK installed. |
| **LocalStack KMS / Azurite-fake / dev Vault Transit** | 🧪 emulator-ready | `deploy/docker/docker-compose.kms-emulators.yml` brings up backend-shaped emulators for optional integration validation. boto3/azure/hvac are OPTIONAL extras (`pyproject.toml [project.optional-dependencies] kms-aws/kms-azure/kms-vault`); not installed on the offline build host. |
| **Real cloud KMS** (AWS KMS / Azure Key Vault / HashiCorp Vault) | ⏳ **lab-deferred** | Per ADR-0032 Negative / P1-PLAN.md §6, real-cloud-KMS validation is the customer environment — the unit fakes + emulators prove the mechanism, not a specific cloud account. |

> **Host-tooling honesty (carry-forward W4 L1).** boto3 / the azure SDK / hvac
> are NOT on the offline build host, so the AWS/Azure/Vault `_build_*_client`
> paths (lazy SDK imports) are `# pragma: no cover` and exercised only where the
> extra is installed. The providers' crypto/AAD/no-leak logic is fully covered by
> the in-memory fakes. The CI emulator job validates the network shape; the real
> clouds are lab.

## Reproduce locally (offline, no cloud)

```
cd backend
.venv/Scripts/python.exe -m pytest tests/core/test_kms_providers.py \
  tests/core/test_crypto.py tests/test_health.py tests/test_main.py -q
```

## Gate status & carry-forward

- ✅ **P1 (this task):** three backends implement the contract; row-id AAD bound
  on each (native / inner-AESGCM); cross-row replay blocked on all three;
  config-only selection; prod gate refuses local providers (banner + metric +
  this doc); `health()` drives readiness + `/metrics`; no-leak gate extended;
  D16 gates (ruff/format/mypy-strict/import-linter/pytest ≥80%) green.
- ⏳ **Deferred:** real-cloud-KMS validation (AWS/Azure/Vault accounts) and the
  HSM/PKCS#11 backend (ADR-0032 §2 Alt #4, explicitly out of P1 — the interface
  admits it with no schema change). Rotation across versions is W6-T3.
