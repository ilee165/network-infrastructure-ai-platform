# Runbook — Master-key (KEK) rotation / DEK re-wrap (W6-T3)

> Operator procedure for the ADR-0011 §1 / ADR-0032 §3 "rotate the wrapper, not the secrets" master-key rotation. The re-wrap pass is online and cheap because **no secret payload is ever re-encrypted** — only each credential's wrapped DEK and its `kek_version` change. Rehearsed-ready for PRODUCTION.md §5.

## Objective

Advance the active KEK version and re-wrap every credential's data-encryption key (DEK) under the new KEK, leaving the AES-256-GCM payload `ciphertext`/`nonce` byte-for-byte untouched. Because the secrets are not re-encrypted, a full-corpus re-wrap is online (no maintenance window) and is the rehearsed procedure for a suspected KEK compromise.

## Facts

| Field | Value |
|---|---|
| ADR | ADR-0032 §3 (rotation/re-wrap), §5 (key-access audit), §6 (no-leak); ADR-0011 §1 |
| Worker task | `credentials.re_wrap_keys` (system queue; operator/KMS-triggered, NOT beat-coupled) |
| Service | `app.services.credentials.re_wrap_keys` (batched compare-and-set) |
| Worklist predicate | `device_credentials WHERE kek_version != active` |
| Status endpoint | `GET /api/v1/credentials/rotation-status` (engineer+; `{from_version, to_version, rows_pending}`) |
| Audit events | `kek.rotate.start` (before `{from_version, row_count}`) / `kek.rotate.complete` (after `{to_version, rows_migrated}`) |

## Procedure

1. **Advance the active KEK.** Either bump the KMS key version (AWS KMS / Azure Key Vault / Vault Transit auto-rotation hook) or, for the local fallback, bump `NETOPS_KEK_VERSION` with the new key. The provider reads the REAL active version at build, so the worklist predicate fires once the active version differs from the rows' stored versions.
2. **Check pending count.** `GET /api/v1/credentials/rotation-status` — confirm `to_version` is the new active KEK and `rows_pending > 0`.
3. **Trigger the re-wrap pass.** Enqueue `credentials.re_wrap_keys` (operator action or the KMS auto-rotation hook). The pass streams the worklist in batches and, per row, unwraps the DEK under its recorded old version, re-wraps under the active KEK, then commits a compare-and-set `UPDATE … WHERE id=:id AND kek_version=:old`. Each batch commits durably.
4. **Watch it drain.** Re-poll `rotation-status` until `rows_pending == 0` and `from_version` is `null`. The `kek.rotate.complete` audit row records `rows_migrated`.
5. **Cut over the old key version (only after `rows_pending == 0`).** For Vault Transit, raise `min_decryption_version` so the old key version can no longer decrypt. Never retire the old version while any row still references it.

## Invariants (proven by the test suite)

- **Payload untouched** — `ciphertext`/`nonce` are byte-identical before and after a re-wrap (the mandatory guardrail; a touch would silently corrupt the corpus).
- **Idempotent + resumable** — a crash mid-pass leaves un-migrated rows for the next run; re-running on a fully-migrated corpus migrates ZERO rows.
- **Online / no maintenance window** — mixed-`kek_version` rows decrypt correctly throughout (decrypt reads `row.kek_version` and unwraps under that specific version).
- **Compare-and-set** — a concurrent per-credential `rotate_secret` is never clobbered (its CAS predicate matches nothing once the row has moved off the old version).
- **No key material** — the audit rows and the status endpoint carry identifiers/versions/counts only — never DEK/KEK/wrapped bytes (ADR-0032 §6).

## Failure modes & response

| Symptom | Response |
|---|---|
| `rows_pending` stalls above zero | The provider could not unwrap an old version (`UnknownKekVersionError`) — restore the matching old KEK material, then re-run. Old KMS key versions must stay available until `rows_pending == 0`. |
| Pass raises `KeyProviderUnavailable` (503) | The KMS became unreachable mid-pass; already-migrated rows stay migrated (the predicate makes the next run resume). Restore KMS reachability and re-trigger `credentials.re_wrap_keys`. |
| `rotation-status` shows the wrong `to_version` | The active provider did not pick up the new KEK version — verify the KMS rotation / `NETOPS_KEK_VERSION` and that the worker rebuilt its provider. |

## Roll-back / safety

- The pass only ever changes `wrapped_dek` / `dek_nonce` / `kek_version`; the secret payload is never rewritten, so there is no payload to roll back.
- The per-credential `rotate_secret` (device secret re-issue) path is a separate, untouched operation — it changes `ciphertext`/`nonce`, not the KEK.
- Re-triggering the pass is always safe (idempotent): a fully-migrated corpus is a no-op.
