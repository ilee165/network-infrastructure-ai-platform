# ADR-0032: KMS-Backed Master Key and Rotation

**Status:** Accepted | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

ADR-0011 (D11) shipped the credential vault as **AES-256-GCM envelope encryption**: every `device_credentials` row carries its own random 256-bit DEK, the secret is sealed under that DEK (96-bit nonce, AAD = credential row id), and the DEK is wrapped by a platform **KEK** (master key) selected through a `KeyProvider` interface. MVP shipped only the two **local** providers `EnvKeyProvider` (env var) and `FileKeyProvider` (mounted file / K8s Secret), and ADR-0011 §1 / its Negative consequences explicitly flagged the upgrade path: *"AWS KMS / Azure Key Vault providers implement the same interface on the production roadmap,"* and *"Env-based KEK is only as safe as the host's env hygiene."*

`PRODUCTION.md` §5 makes that upgrade a P1 security-hardening line item:

> *"Master key moved from env/file to a real KMS via the D11 KMS-compatible interface (Vault, cloud KMS, or HSM — customer choice); key rotation procedure with re-wrap of data keys, rehearsed."*

`P1-PLAN.md` §3 schedules it in **W6 — Security hardening (P1 subset)**: *"Master key → KMS via D11 interface + rotation/re-wrap"*, a strong-tier, secret-surface task. This ADR is the **design gate** for that wave: it does not change the envelope schema (`device_credentials(ciphertext, nonce, wrapped_dek, kek_version, …)` from ADR-0011 §1) and it does not touch DEK derivation or per-credential blast-radius. It **extends the ADR-0011 `KeyProvider` interface** so the KEK can live in a real KMS, and it pins the rotation/re-wrap procedure, the failure-closed behavior when the KMS is unreachable, the key-access audit, and the absolute no-key-material-in-logs/responses rule.

The crypto posture of ADR-0011 (`cryptography` AESGCM, per-credential DEK, no API ever returns a secret, decryption only inside the device-connectivity layer) is **kept verbatim**. Nothing here re-decides D11 — it fills in the KMS provider half D11 deliberately left open and is consistent with `PRODUCTION.md` §8 ("Secrets/master key — KMS-managed; key escrow procedure documented") and §9 (platform secrets / master-key reference via external-secrets/CSI backed by the customer KMS/Vault).

## Decision

**The KEK (master key) is never held as raw bytes by the platform. The ADR-0011 `KeyProvider` interface is narrowed to a wrap/unwrap (KMS envelope) contract: providers wrap and unwrap DEKs by reference to a key the KMS owns, never by exporting key material into the process. AWS KMS, Azure Key Vault, and HashiCorp Vault Transit are first-class production backends; the env/file providers are retained only as a clearly-marked, non-production local fallback. Master-key rotation is a KEK-version bump plus a DEK re-wrap pass — no vault secret is ever re-encrypted. When the KMS is unreachable, the vault fails closed. Every wrap/unwrap and rotation is recorded in the ADR-0011 append-only `audit_log`, and no key material ever appears in a log line, exception, trace, or API response.**

### 1. `KeyProvider` interface — extend ADR-0011, don't replace it

ADR-0011 §1 named a `KeyProvider` interface but only its local providers (`EnvKeyProvider`, `FileKeyProvider`) held the KEK *as bytes in-process* and wrapped DEKs locally. A network KMS cannot and must not export its key. We therefore split the contract so the **wrap/unwrap operation itself** is the interface boundary — for local providers it runs in-process; for KMS providers it is a remote call against a key the KMS retains:

```python
class KeyProvider(Protocol):
    """ADR-0011 D11 master-key (KEK) provider. Extended for KMS backends:
    the provider wraps/unwraps DEKs; it never returns KEK bytes."""

    @property
    def kek_version(self) -> str:
        """Stable id of the *active* wrapping key (KEK). Stored on each row
        as device_credentials.kek_version. Opaque; e.g. an AWS KMS key-id +
        rotation tag, an Azure key version URI, or a Vault Transit key name+version."""

    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek:
        """Encrypt a 256-bit DEK under the active KEK. Returns (ciphertext,
        kek_version). For KMS backends this is a remote Encrypt/WrapKey call;
        the plaintext DEK is supplied by us and the KEK never leaves the KMS."""

    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes:
        """Decrypt a wrapped DEK. For KMS backends this is a remote
        Decrypt/UnwrapKey call. Returns plaintext DEK bytes that live only
        transiently in the api/worker process, zeroized after the AESGCM op."""

    def health(self) -> ProviderHealth:
        """Liveness probe used by the fail-closed gate (§4) and /metrics."""
```

Key properties this preserves and adds:

- **Schema unchanged.** `wrapped_dek` and `kek_version` already exist on `device_credentials` (ADR-0011 §1). `WrappedDek = (ciphertext: bytes, kek_version: str)` maps onto those two columns 1:1. No Alembic migration is required for the column shape; only the *contents* of `kek_version` become KMS-meaningful.
- **AAD continuity.** The credential row-id AAD that ADR-0011 binds at the *DEK→secret* layer is also bound at the *KEK→DEK* wrap layer, so a wrapped DEK cannot be lifted from one row and replayed onto another even with KMS access. **This binding is mandatory on every backend, but the mechanism is backend-specific** because not all KMS wrap primitives accept additional-authenticated-data:
  - **AWS KMS** (`Encrypt`/`Decrypt`) and **Vault Transit** (`encrypt`/`decrypt`) take an `EncryptionContext` / `context` parameter; we pass the row-id there directly and the KMS authenticates it on unwrap.
  - **Azure Key Vault** `wrapKey`/`unwrapKey` (RSA-OAEP / AES-KW) have **no `EncryptionContext`/AAD parameter**. To honor the same contract, `AzureKeyVaultKeyProvider` does not hand the bare DEK to `wrapKey`. It first seals the DEK in a **local AESGCM inner layer with `aad = row_id`** (a fresh 96-bit nonce, the DEK as plaintext), then `wrapKey`s the *small AESGCM key* for that inner layer; `unwrapKey` reverses it and the AESGCM open **fails** if the stored row-id does not match. The row-id is thus cryptographically bound inside the wrapped plaintext, giving the identical cross-row-replay guarantee without relying on a KMS AAD parameter. The `WrappedDek.ciphertext` for this backend carries (inner-nonce ‖ wrapped-inner-key ‖ inner-ciphertext); the schema (a single `wrapped_dek` blob) is unchanged.

  Because the row-id is bound on **every** backend (natively where the primitive supports it, via the local AESGCM inner layer where it does not), the `wrap_dek(dek, *, aad)` / `unwrap_dek(wrapped, *, aad)` contract is satisfiable uniformly and the replay invariant is genuinely backend-agnostic. A provider that can neither pass `aad` to its primitive nor wrap an inner AAD layer MUST reject a non-empty `aad` at construction rather than silently dropping it.
- **DEK generation stays ours.** We generate the 256-bit DEK with `os.urandom`/`AESGCM.generate_key` (ADR-0011) and ask the KMS only to *wrap* it. We deliberately do **not** use KMS `GenerateDataKey` server-side DEK minting, so the envelope/DEK lifecycle is identical across local and KMS backends and the per-credential blast-radius story from ADR-0011 is untouched.
- **No export path.** There is no `get_kek()`/`export()` method on the interface for KMS providers — the only way to use the KEK is to send a DEK through `wrap_dek`/`unwrap_dek`. This is the structural guarantee behind "no key material is ever logged or returned" (§6).

### 2. Pluggable backends

Selection is config-only (`VAULT_KEY_PROVIDER` + provider-scoped settings); the credential service is provider-agnostic and never branches on backend. All credential material below is referenced **indirectly** — IAM role, managed identity, or a `credential_ref` resolved at startup (matching ADR-0011 §1 / ADR-0024 §2). No token, key, or secret value is ever inlined in config or code.

| Provider | KEK lives in | Wrap / unwrap primitive | Auth (referenced, never inlined) | Rotation model |
|---|---|---|---|---|
| `AwsKmsKeyProvider` | AWS KMS CMK | `kms:Encrypt` / `kms:Decrypt`, row-id via native `EncryptionContext={row_id}` | IAM role / IRSA (no static keys); `key_arn` config only | KMS **automatic annual** or manual; new backing key, same ARN — re-wrap on bump (§3) |
| `AzureKeyVaultKeyProvider` | Azure Key Vault key | `wrapKey` / `unwrapKey` (RSA-OAEP or AES-KW) — **no native AAD**, so row-id is bound by a local AESGCM(`aad=row_id`) inner layer and `wrapKey` wraps that inner key (§1) | Workload Identity / managed identity; `vault_uri`+`key_name` config | New **key version**; `kek_version` = version URI; re-wrap on bump |
| `HashiCorpVaultTransitKeyProvider` | Vault Transit key (never exportable) | `transit/encrypt/<key>` / `transit/decrypt/<key>`, row-id via native `context={row_id}` | Kubernetes auth / AppRole → short-lived Vault token via `credential_ref`; auto-renew | `transit/keys/<key>/rotate`; `kek_version` = `<key>:vN`; decrypt accepts old versions, re-wrap migrates to `min_decryption_version` |
| `EnvKeyProvider` / `FileKeyProvider` | **process env / mounted file (local KEK bytes)** | in-process AES-256-GCM key-wrap | the KEK material itself (host/K8s-Secret hygiene only) | manual KEK swap + full re-wrap pass |

**Local fallback is explicitly NOT production.** `EnvKeyProvider`/`FileKeyProvider` are retained for `docker-compose`, local dev, and CI, exactly as ADR-0011 shipped them. To prevent silent misuse:

- A `production`/`is_prod` runtime flag (set in the Helm chart, off in compose) makes the credential service **refuse to start** on a local provider — `RuntimeError("local KeyProvider '<name>' is not permitted in production; configure a KMS backend (D11/ADR-0032 §2)")`. Secure-by-default-opt-out per `P1-PLAN.md` W4 / CLAUDE.md "Secure by default."
- The provider self-reports `is_production_grade = False`; this surfaces on the startup banner, `/metrics` (`vault_key_provider_production_grade`), and the G-SEC evidence doc so a non-prod KEK can never hide behind a green deploy.
- The local KEK is still only as safe as host env/Secret hygiene (the ADR-0011 Negative consequence) — which is exactly why it is barred from prod.

`PRODUCTION.md` §1 names HSM as a customer choice; an `Pkcs11KeyProvider` (HSM/KMIP) is a future addition implementing the **same** interface — explicitly out of P1 scope, listed in Alternatives #4, and requiring no schema or interface change to add.

### 3. Master-key rotation and re-wrap — rotate the wrapper, not the secrets

This is the core operational win ADR-0011 §1 promised (*"`kek_version` enables rotation: a rotation job re-wraps DEKs (cheap — no payload re-encryption)"*). The vault secret (the device credential) is **never** re-encrypted on a master-key rotation; only the thin per-row wrapped DEK is re-sealed under the new KEK.

**Procedure (`re_wrap_keys` job, run by the worker, audited):**

1. Operator (or the KMS auto-rotation hook) advances the KEK to a new version → `provider.kek_version` now reports `vN+1`. Both the old and new KEK are temporarily resolvable by the provider (KMS keeps prior versions for decrypt; for local providers, the old KEK file is supplied alongside the new during the window).
2. The re-wrap job streams `device_credentials` rows **where `kek_version != active`**, in batches, and for each row:
   - `dek = provider.unwrap_dek(row.wrapped_dek, aad=row_id)` — using the **old** version recorded on the row (the wrapped blob self-identifies its version).
   - `new = provider.wrap_dek(dek, aad=row_id)` — under the **active** KEK.
   - `UPDATE device_credentials SET wrapped_dek = new.ciphertext, kek_version = new.kek_version WHERE id = row_id AND kek_version = <old>` (compare-and-set so a concurrent credential rotation can't be clobbered), then zeroize `dek`.
   - **The `ciphertext`/`nonce` columns are never read or written** — the secret payload is untouched, proving "no plaintext re-encryption of every secret."
3. The job is **idempotent and resumable**: `kek_version != active` is the worklist predicate, so a crash mid-pass just leaves un-migrated rows for the next run; re-running is a no-op once all rows match `active`.
4. **Mixed versions are valid at rest.** Decryption reads `row.kek_version` and asks the provider to unwrap under that specific version, so the platform keeps serving credentials throughout the migration — no maintenance window, no big-bang re-encrypt. Cutover/teardown of the old KEK version happens only after the job confirms zero rows reference it (and, for Vault Transit, after raising `min_decryption_version`).

| Event | What changes | What does NOT change |
|---|---|---|
| Master-key (KEK) rotation | `wrapped_dek`, `kek_version` per row (re-wrap) | DEK value, `ciphertext`, `nonce`, the device secret |
| Per-credential rotation (D11, device re-issue) | `ciphertext`, `nonce`, new DEK + its `wrapped_dek` | the KEK / `kek_version` semantics |

Rotation is recommended on a schedule (KMS auto-annual where supported) and is **mandatory on suspected KEK compromise**; because no secret is re-encrypted, even a full-corpus re-wrap is cheap and online.

### 4. Failure-closed behavior when the KMS is unreachable

Per CLAUDE.md "Secure by default": an unreachable KMS must **never** degrade to plaintext, a cached KEK on disk, or a skipped decrypt. The vault **fails closed**.

- **Writes (credential create / per-credential rotation):** require a live `wrap_dek`. If the KMS is down, the create/rotate operation returns a `503`-class `KeyProviderUnavailable` and the row is **not** written. No credential is ever stored unwrapped or DEK-in-cleartext.
- **Reads (decrypt before opening a device session — ADR-0011 §1):** require a live `unwrap_dek`. If the KMS is down, the device-connectivity layer raises `KeyProviderUnavailable`; the dependent discovery/config/automation task **fails and retries** (Celery `acks_late`, idempotent — `PRODUCTION.md` §3.2) rather than proceeding without the credential. A ChangeRequest execution that cannot unwrap its target credential goes to `failed` (ADR-0011 §3 lifecycle), never silently to `completed`.
- **No plaintext DEK cache.** Unwrapped DEKs live only transiently for the single AESGCM operation and are zeroized; we do **not** keep a warm DEK cache to "ride out" a KMS outage, because that cache would be exactly the key-material-at-rest the KMS design removes. (A short-TTL, in-memory, per-process unwrap cache is an explicit Alternative — #3 — and is rejected for P1.)
- **Health-gated readiness.** `provider.health()` feeds the K8s **readiness** probe: a replica that cannot reach its KMS is pulled from rotation (no new credential traffic routed to it) and alerts fire (G-OBS fault-injection: "LLM/dep down detected < 5 min"). It stays *live* (not killed) so it recovers when the KMS returns.
- **Bound to existing gates.** This satisfies `PRODUCTION.md` §11 G-SEC "no plaintext device credential in any API response, log, trace, or backup sample" under the failure path, and the G-REL "worker node kill / dependency down → retry, no duplicate side effects" expectation.

### 5. Key-access audit (ADR-0011 append-only)

Every KEK operation is an audited event in the ADR-0011 §2 append-only `audit_log` (INSERT/SELECT-only grant + `BEFORE UPDATE OR DELETE` trigger — unchanged). ADR-0011 §2 already audits "credential create/rotate"; this ADR adds the **KEK-level** events and pins their shape:

| `audit_log` action | Emitted when | `target` / `before/after` (JSONB) |
|---|---|---|
| `kek.wrap` | a DEK is wrapped (credential create / rotate / re-wrap) | target = `device_credentials:{id}`, vendor/device; after = `{kek_version}` |
| `kek.unwrap` | a DEK is unwrapped to open a device session | target = `device_credentials:{id}`; reasoning-trace link when an agent triggered it (ADR-0011 §2/§4) |
| `kek.rotate.start` / `kek.rotate.complete` | re-wrap job begins / finishes | before = `{from_version, row_count}`, after = `{to_version, rows_migrated}` |
| `kek.provider.unavailable` | fail-closed gate trips (§4) | target = provider name, reason class — **no key bytes, no `credential_ref` value** |
| `kek.provider.select` | active provider/backend chosen at startup | after = `{provider, kek_version, is_production_grade}` |

The audit record carries **identifiers and versions only** — never DEK bytes, never KEK bytes, never the wrapped blob, never the `credential_ref` value. KMS-side access (who called Encrypt/Decrypt) is *additionally* logged by the KMS itself (CloudTrail / Key Vault diagnostics / Vault audit device); the customer SIEM export (`PRODUCTION.md` §5, P2) carries both streams, and the §7 audit-integrity report covers our half.

### 6. No key material is ever logged or returned

Restating ADR-0011 §1 ("No API ever returns a secret … redacted in logs, traces, and serialized schemas") and extending it to the KEK/DEK layer — this is the secret-critical invariant of the ADR:

- **No API path** exposes a KEK, a DEK, a wrapped DEK, or a `credential_ref` value. The credential schemas remain write-only/redacted (ADR-0011); `wrapped_dek`/`kek_version` are **internal columns**, never fields on any response model. A "rotation status" endpoint returns counts and versions only (`{from_version, to_version, rows_pending}`), never blobs.
- **No log/trace line** prints key material. `WrappedDek`, DEK `bytes`, and the provider's client objects carry a `__repr__`/structlog redactor that emits `"<redacted dek>"` / `"<wrapped:vN>"` — the ADR-0024 §2 / ADR-0011 "never logged" posture. Provider errors are wrapped so a raw boto3/azure/hvac exception (which can echo request context) is never surfaced verbatim; only a typed `KeyProviderError(reason_class)` propagates.
- **Transient-only plaintext.** A plaintext DEK exists only for the duration of one AESGCM call inside `api`/`worker` and is zeroized; it is never serialized, cached to disk, put on a queue, or attached to an audit/trace record.
- **Tested as an exit criterion.** A `test_no_key_material_leak` gate (parity with G-SEC "credential leak tests green") asserts: provider repr/log scrub, no key bytes in any serialized schema, KMS exceptions never re-raised raw, and that an unwrapped DEK never reaches an `audit_log`/`reasoning_traces` row. Per `P1-PLAN.md` §3/§2, this whole task and its reviewers run on the escalated **strong** tier (secret-surface).

## Consequences

**Positive**
- The platform process holds **no KEK bytes** in production: a full host/memory compromise of `api`/`worker` yields wrapped DEKs whose unwrap requires a live, audited KMS call — strictly stronger than the ADR-0011 env/file KEK, and closes that ADR's "env hygiene" Negative.
- Master-key rotation is **online and cheap**: re-wrapping per-row DEKs touches no `ciphertext`, needs no maintenance window, is idempotent/resumable, and is mandatory-on-compromise without a corpus re-encrypt — delivering the ADR-0011 §1 promise concretely.
- **Zero schema change and zero engine change.** `wrapped_dek`/`kek_version` already exist; only their contents and the provider implementation change. The credential service is backend-agnostic, so AWS/Azure/Vault are a config swap.
- Fail-closed + readiness-gating means a KMS outage degrades to "credential ops pause and retry," never to plaintext or a wrong-credential session — auditable and gate-aligned (G-SEC/G-REL/G-OBS).
- Key access is auditable end-to-end (append-only `audit_log` + KMS-native logs), feeding the §7 audit-integrity report and SIEM export.

**Negative**
- A new **hard runtime dependency on the KMS** for every credential read/write: a KMS outage halts new discovery/config/automation against credentialed devices (mitigated by retry + readiness, but real). The local fallback that would soften this is barred from prod by design.
- **Per-decrypt KMS latency and cost.** Every device session opens with an unwrap round-trip; high-fanout discovery multiplies KMS calls. We accept this (no DEK cache for P1) for the security guarantee; a bounded in-memory unwrap cache is a future, separately-decided knob (Alternative #3).
- **Operator burden moves to KMS key lifecycle**: key policies/IAM, rotation cadence, version retention for online re-wrap, and a documented **key-escrow/recovery** procedure (`PRODUCTION.md` §8 "Secrets/master key — key escrow procedure documented; key-recovery drill annually"). Losing the KEK still loses the corpus (ADR-0011 Negative) — now it is the customer-KMS's escrow, not ours.
- Three live KMS backends widen the integration test surface; CI verifies against **local emulators/fakes** (LocalStack KMS, Azurite-style fake, a dev Vault Transit container) and a deterministic fake provider, with real-KMS validation deferred to the customer environment — same lab-deferred posture as `P1-PLAN.md` §6.

## Alternatives considered

1. **Keep env/file KEK; declare it "good enough" for production.** Rejected: `PRODUCTION.md` §5 mandates a real KMS, and ADR-0011 itself flagged env-KEK hygiene as a Negative. A KEK readable from process env or a mounted file is recoverable by anyone with host/pod access, defeating the envelope's separation-of-duties. **Chosen instead:** KMS providers hold the KEK; local providers are non-prod fallback only (§2).

2. **Use KMS server-side `GenerateDataKey` to mint DEKs (KMS owns DEK lifecycle).** Rejected for P1: it would diverge the DEK lifecycle between local and KMS backends, make the ADR-0011 per-credential-DEK/blast-radius model backend-dependent, and add a second DEK-provenance path to reason about. **Chosen:** we generate the DEK locally (`AESGCM.generate_key`) and the KMS only wraps/unwraps it — one envelope model across all backends, ADR-0011 §1 unchanged.

3. **Cache unwrapped DEKs (or the KEK) in-process to survive KMS outages and cut latency.** Rejected for P1: a warm DEK/KEK cache reintroduces exactly the key-material-at-rest the KMS design removes, and would let a memory-compromised replica decrypt without a fresh KMS call or audit event. We fail closed and retry instead (§4). A bounded, short-TTL, audited unwrap cache may be revisited as a performance knob in a later ADR if KMS latency/cost proves prohibitive — it is a deliberate, separate decision, not a default.

4. **Require an external HSM/PKCS#11 (or HashiCorp Vault as a mandatory service) as the only backend.** Rejected as the P1 baseline: ADR-0011 Alternative #1 already rejected mandating an external secret service for the self-hosted single-compose target, and HSM is one *customer choice* among several in `PRODUCTION.md` §1, not a universal requirement. **Chosen:** a pluggable interface where AWS KMS, Azure Key Vault, and Vault Transit are first-class and an `Pkcs11KeyProvider` (HSM) drops in later with **no** schema or interface change — maximal customer choice, minimal lock-in.

5. **Per-tenant / per-site KEKs instead of one platform KEK.** Rejected for P1 as out of scope: multi-tenancy is a backlog item pending a Consultant answer (`PRODUCTION.md` §12) and would complicate the rotation/re-wrap worklist before there is a requirement. The `kek_version`/provider model here does not preclude a future scoped-KEK design (the row-id is already bound into every wrap per §1 — natively via `EncryptionContext`/`context` on AWS/Vault, via the local AESGCM inner layer on Azure), so this stays a clean future extension rather than a contradicted decision.
