# W6-T1 — `KeyProvider` Wrap/Unwrap Interface + Fail-Closed Credential Service

| | |
|---|---|
| **Wave** | P1 W6 — Security hardening (P1 subset) |
| **Owner** | `wf-implementer` (strong — Python, secret-surface) |
| **Review tier** | **strong** spec + **strong** quality (secret-surface escalation, P1-PLAN.md §2/§3) |
| **Depends on** | — (foundation for W6-T2, W6-T3) |
| **ADRs** | ADR-0032 §1, §4, §6; ADR-0011 §1 (envelope), §2 (audit) |
| **PRODUCTION.md** | §5 (KMS via D11 interface), §11 G-SEC |
| **Status** | Proposed |

## Objective

Narrow the ADR-0011 `KeyProvider` interface to a **wrap/unwrap (KMS-envelope) contract** so the
KEK can live in a real KMS that never exports key material, refactor the local `Env`/`File`
providers and the credential service onto it, and make the vault **fail closed** when the provider
is unreachable. This is the interface foundation; KMS backends are W6-T2 and rotation is W6-T3.
**No schema change** — `wrapped_dek`/`kek_version` already exist (ADR-0032 §1).

## Scope

**In** (`backend/app/core/crypto.py`, `backend/app/services/credentials/service.py`)
- Replace the current `KeyProvider` Protocol (`current_version`, `key(version) -> bytes`) with the
  ADR-0032 §1 wrap/unwrap contract: `kek_version`, `wrap_dek(dek, *, aad) -> WrappedDek`,
  `unwrap_dek(wrapped, *, aad) -> bytes`, `health() -> ProviderHealth`. **No `get_kek()`/`export()`
  for the network path** — the structural guarantee behind "no key material logged/returned" (§6).
- `WrappedDek = (ciphertext: bytes, kek_version: str)` mapping 1:1 onto the existing two columns —
  **no Alembic migration** (ADR-0032 §1).
- Re-home `EnvKeyProvider`/`FileKeyProvider` as **in-process** wrap/unwrap implementers (local KEK
  bytes; same crypto as today), keeping `envelope_encrypt`/`decrypt`/`rewrap` semantics intact.
- **AAD continuity** (ADR-0032 §1): bind the credential row-id AAD at the KEK→DEK wrap layer (not
  just DEK→secret). Local providers bind it in-process; the per-backend mechanism (native vs inner
  AESGCM layer) is W6-T2, but the **interface must accept and require `aad`**, and a provider that
  can neither pass nor inner-wrap `aad` MUST reject a non-empty `aad` at construction.
- **DEK generation stays ours** (`AESGCM.generate_key`); the provider only wraps/unwraps — no KMS
  `GenerateDataKey` (ADR-0032 §1 / Alt #2).
- **Fail-closed gate** (ADR-0032 §4): typed `KeyProviderUnavailable` (503-class) on writes (no row
  written unwrapped); on reads (decrypt before a device session), raise so the dependent task
  fails+retries (Celery `acks_late`) and a CR that can't unwrap goes to `failed`, never `completed`.
  **No plaintext DEK cache** — DEK transient, zeroized after the AESGCM op.
- **Audit events that fire on the core path** (ADR-0032 §5): `kek.wrap`, `kek.unwrap`,
  `kek.provider.unavailable`, `kek.provider.select` into the ADR-0011 append-only `audit_log`
  (identifiers/versions only — no key bytes, no `credential_ref` value).
- **No-key-material-leak invariant** (ADR-0032 §6): `WrappedDek`/DEK `bytes`/provider client carry
  a `__repr__`/structlog redactor (`<redacted dek>` / `<wrapped:vN>`); provider errors wrapped as
  typed `KeyProviderError(reason_class)` so a raw boto3/azure/hvac exception never surfaces verbatim.

**Out**
- Concrete AWS/Azure/Vault backends + prod-grade gating → **W6-T2**.
- `re_wrap_keys` rotation job + rotation audit + rotation-status endpoint → **W6-T3** (note:
  `rotate_kek`/`rewrap` exist today and are adapted to the new contract here, but the *batch job* is T3).
- `ProviderHealth` → readiness-probe / `/metrics` wiring lands with the providers in **W6-T2**.

## Requirements (grounded in ADR-0032 §1, §4, §6)

1. **Crypto posture kept verbatim** (ADR-0032 Context): `cryptography` AESGCM, per-credential DEK,
   no API returns a secret, decrypt only inside the device-connectivity layer. This task changes
   the *KEK-wrap boundary*, nothing else about D11.
2. **No export path** for the network case — the only way to use the KEK is `wrap_dek`/`unwrap_dek`.
   Local providers may still hold KEK bytes in-process (they wrap locally), but the Protocol exposes
   no byte-export method that a KMS provider would have to violate.
3. **Fail closed, never degrade** (ADR-0032 §4 / CLAUDE.md secure-by-default): unreachable provider
   ⇒ `KeyProviderUnavailable`; never plaintext, never a disk-cached KEK, never a skipped decrypt.
4. **Transient-only plaintext DEK**, zeroized; never serialized, queued, cached, or put on an
   audit/trace row (ADR-0032 §6).
5. **`test_no_key_material_leak` is an exit criterion** (ADR-0032 §6): provider repr/log scrub, no
   key bytes in any serialized schema, KMS exceptions never re-raised raw, unwrapped DEK never
   reaches an `audit_log`/`reasoning_traces` row.

## Contracts (ADR-0032 §1)

```python
class KeyProvider(Protocol):
    @property
    def kek_version(self) -> str: ...
    def wrap_dek(self, dek: bytes, *, aad: bytes) -> WrappedDek: ...
    def unwrap_dek(self, wrapped: WrappedDek, *, aad: bytes) -> bytes: ...
    def health(self) -> ProviderHealth: ...
```

`WrappedDek = (ciphertext: bytes, kek_version: str)` → existing `device_credentials.wrapped_dek` /
`.kek_version` columns. `get_key_provider(settings)` keeps selecting Env/File for local/CI.

## Test & gate plan (Python TDD — ADR-0016 / D16)

- ruff (check + format), mypy strict, import-linter, pytest ≥80% on touched core modules.
- Round-trip: `wrap_dek`→`unwrap_dek` with matching `aad` returns the DEK; **wrong `aad` fails**
  (cross-row replay guard). Existing envelope encrypt/decrypt/rewrap tests stay green on the
  re-homed local providers.
- Fail-closed: a stub provider raising on wrap/unwrap ⇒ create returns 503-class, no row written;
  decrypt raises and the dependent path surfaces a retryable error; no plaintext anywhere.
- `test_no_key_material_leak` (the §6 gate) green, run on the **strong** tier.

## Exit criteria

- [ ] `KeyProvider` is the wrap/unwrap/health contract; Env/File re-homed onto it; **no migration**.
- [ ] AAD bound at the KEK→DEK layer; interface requires `aad`; non-supporting provider rejects `aad`.
- [ ] DEK still generated locally; no `GenerateDataKey`; no KEK byte-export on the Protocol.
- [ ] Vault fails closed on unreachable provider (writes + reads + CR→failed); no DEK cache.
- [ ] `kek.wrap`/`unwrap`/`provider.unavailable`/`provider.select` audited (ids/versions only).
- [ ] `test_no_key_material_leak` green; redactors + typed errors in place; D16 gates green.

## Workflow (P1-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** in parallel (both escalated — secret pipeline) → `wf-fixer` (strong) if findings →
`wf-verifier` → **one atomic commit**.

## Risks

- The current `KeyProvider` (`key(version) -> bytes`) is used by `envelope_encrypt/decrypt/rewrap`
  and the credential service — the refactor touches the live decrypt path; the existing envelope
  tests are the regression guard and must stay green.
- This is the interface every W6-T2 backend and the W6-T3 job build on — getting the `aad` contract
  and fail-closed semantics exactly right here prevents drift downstream.
