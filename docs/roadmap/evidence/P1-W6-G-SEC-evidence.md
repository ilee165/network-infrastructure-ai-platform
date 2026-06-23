# P1 W6 — G-SEC Evidence: KMS backends + prod-grade gating (W6-T2)

| | |
|---|---|
| **Gate** | G-SEC — KMS no-leak + fail-closed + non-prod-KEK-cannot-hide (PRODUCTION.md §11) |
| **Wave / task** | P1 W6-T2 (builds on W6-T1 wrap/unwrap contract) |
| **ADRs** | ADR-0032 §1 (per-backend AAD), §2 (config-only swap + prod gate), §4 (health→readiness), §6 (no-leak) |
| **Status** | Offline unit + **contract tests** + **CI emulator gate** GREEN; real-cloud-KMS validation **lab-deferred** |

## What was proven (P1)

Three first-class production KMS backends implement the **same** W6-T1
`KeyProvider` wrap/unwrap/health contract, selectable by config alone, with the
local Env/File providers barred from production:

1. **`AwsKmsKeyProvider`** — `kms:Encrypt`/`Decrypt`; the credential **row-id is
   bound natively** via `EncryptionContext={row_id}`. Auth is IRSA/IAM role from
   the pod's ambient credentials (no static keys); the key is referenced by ARN
   only. `kek_version` is the key ARN.
2. **`HashiCorpVaultTransitKeyProvider`** — `transit/encrypt|decrypt`; row-id
   bound natively via `context={row_id}`. The hvac calls go through the
   `_VaultTransitClient` adapter, which base64-encodes plaintext/context, passes
   `mount_point`, and reads the active version via
   `secrets.transit.read_key(...)["data"]["latest_version"]` — so `kek_version =
   <key>:vN` reflects a **real** rotation (the T3 worklist predicate fires), not a
   hardcoded v1. The short-lived token comes from a k8s-auth/AppRole login keyed
   by an **indirect `credential_ref`** (never a token value), auto-renewed; and
   **decrypt accepts old versions**.
3. **`AzureKeyVaultKeyProvider`** — `wrapKey`/`unwrapKey` has **no native AAD**,
   so the row-id is bound by a **local AESGCM inner layer**: a fresh inner key
   seals the DEK with `aad=row_id` (fresh 96-bit nonce), then the inner key is
   wrapped via `CryptographyClient.wrap_key(KeyWrapAlgorithm.rsa_oaep_256,
   key).encrypted_key` (the `_AzureKeyClient` adapter); `unwrap_key(...).key`
   reverses it. `WrappedDek.ciphertext = inner-nonce ‖ wrapped-inner-key ‖
   inner-ciphertext`; the single-blob schema is unchanged (ADR-0032 §1). The
   AESGCM open **fails on a row-id mismatch**, giving the identical cross-row
   replay guard the native backends get. `kek_version = <key>:<key.properties.
   version>` so a Key Vault key rotation is visible to T3.

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

```text
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

The provider is built **once** in the lifespan, gated, and stashed on
`app.state.key_provider`; the startup `health()` read and the readiness probe both
offload the blocking SDK round-trip via `asyncio.to_thread` (the event loop is
never stalled at boot or per poll). `/api/v1/health/ready` adds a `kek_provider`
dependency (only when a provider is cached) that calls `health()` on the **cached**
instance — never rebuilding the SDK client per poll (which on Azure/Vault would
re-run `DefaultAzureCredential` / re-login each `/ready` and risk `PROBE_TIMEOUT`
flapping). An unreachable KMS makes readiness **degraded** — the replica is pulled
from rotation — while **liveness stays green**. The 0/1 `vault_key_provider_healthy`
gauge is refreshed from each probe. Asserted by
`test_ready_degrades_when_kek_provider_unreachable` +
`test_ready_kek_probe_reuses_cached_provider_not_rebuilt`.

The startup gate is **fail-loud**: when a production KMS backend
(`VAULT_KEY_PROVIDER=aws|azure|vault`) is selected but its build fails (missing
ARN, absent SDK extra, unreachable backend at boot), the lifespan **re-raises**
rather than degrading to `provider=None` — so a non-functional prod KEK can never
start behind a green deploy (`test_startup_crashes_when_kms_backend_unbuildable_in_prod`).
Only an unset/local selector in a non-prod run degrades to no provider.

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
| **Deterministic in-memory fake** (`FakeKmsKeyProvider`) + per-backend adapter doubles | ✅ GREEN | The offline unit suite (`test_kms_providers.py`) drives the real wrap/unwrap logic (incl. the Azure inner-AESGCM layer) at full coverage with NO cloud SDK installed — the doubles mirror the **adapter** contract, not a raw SDK. |
| **Real-SDK contract tests** (`test_kms_contract.py`) | ✅ GREEN | Pin the EXACT real call shape against mock SDK clients so the prod path is no longer vacuous-`# pragma: no cover`: Vault `secrets.transit.encrypt_data(name=, plaintext=<b64>, context=<b64>, mount_point=)` / `read_key(...)["data"]["latest_version"]` + k8s-auth/AppRole login; Azure `wrap_key(KeyWrapAlgorithm.rsa_oaep_256, key).encrypted_key` / `unwrap_key(...).key`; AWS `encrypt/decrypt` with `EncryptionContext`. |
| **CI emulator job** `kms-emulators` (LocalStack KMS + dev Vault Transit) | ✅ GREEN — **required gate** | `deploy/docker/docker-compose.kms-emulators.yml` is brought up by the `kms-emulators` CI job, which installs the `kms-aws`/`kms-vault` extras, creates the keys, and runs `tests/integration/test_kms_emulators.py` against the REAL boto3/hvac adapters end-to-end. The job is a `needs:` of `all-gates`, so it blocks merge — NOT optional. |
| **Azure local emulator** | ⚠️ documented exception | No first-party local `wrapKey`/`unwrapKey` emulator exists for Azure Key Vault. Its real call shape is covered by the contract test; the live integration is the lab Key Vault. The inner-AESGCM row-id binding is backend-independent and fully covered offline. |
| **Real cloud KMS** (AWS KMS / Azure Key Vault / HashiCorp Vault) | ⏳ **lab-deferred** | Per ADR-0032 Negative / P1-PLAN.md §6, real-cloud-KMS validation is the customer environment — the unit fakes + contract tests + emulator job prove the mechanism, not a specific cloud account. |

> **Host-tooling honesty (carry-forward W4 L1).** boto3 / the azure SDK / hvac
> are NOT on the offline build host, so only the `_build_*_client` **lazy SDK
> import** lines keep a `# pragma: no cover` (they cannot run without the extra
> installed — an honest, narrow pragma, not a wrapper hiding a broken path). The
> adapter call shapes (`_VaultTransitClient` / `_AzureKeyClient` / the AWS
> provider) and `_vault_login` are now covered by the contract tests, and the CI
> emulator job exercises boto3/hvac end-to-end against backend-shaped emulators.
> The real clouds are lab.

## Reproduce locally (offline, no cloud)

```console
cd backend
.venv/Scripts/python.exe -m pytest tests/core/test_kms_providers.py \
  tests/core/test_kms_contract.py tests/core/test_crypto.py \
  tests/test_health.py tests/test_main.py -q
```

The CI `kms-emulators` job runs the live integration layer (not reproducible on a
host without Docker + the SDK extras):

```console
docker compose -f deploy/docker/docker-compose.kms-emulators.yml up -d
pip install -e "./backend[dev,kms-aws,kms-vault]"
# (create a LocalStack KMS key + the dev Vault transit key — see ci.yml)
KMS_EMULATOR_TEST=1 pytest backend/tests/integration/test_kms_emulators.py -v
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
