# W6-T3 — Master-Key Rotation / DEK Re-Wrap Job + Key-Access Audit

| | |
|---|---|
| **Wave** | P1 W6 — Security hardening (P1 subset) |
| **Owner** | `wf-implementer` (strong — Python, secret-surface) |
| **Review tier** | **strong** spec + **strong** quality |
| **Depends on** | W6-T1 (interface); W6-T2 for KMS-version semantics (no hard import) |
| **ADRs** | ADR-0032 §3 (rotation/re-wrap), §5 (key-access audit), §6 (no-leak); ADR-0011 §1 |
| **PRODUCTION.md** | §5 ("key rotation procedure with re-wrap of data keys, rehearsed"), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement master-key rotation as a **KEK-version bump + DEK re-wrap pass** — rotate the wrapper,
never re-encrypt the secrets. Ship the idempotent/resumable `re_wrap_keys` worker job, the
`kek.rotate.*` audit events, and a rotation-status endpoint that returns counts/versions only. This
delivers the ADR-0011 §1 promise ("a rotation job re-wraps DEKs — cheap, no payload re-encryption")
concretely, and PRODUCTION.md §5's "rehearsed" rotation procedure.

## Scope

**In** (`backend/app/workers/tasks/…`, `backend/app/services/credentials/…`, an API router slice)
- `re_wrap_keys` job (worker-run, audited) per ADR-0032 §3: streams `device_credentials` rows
  **where `kek_version != active`** in batches and per row:
  - `dek = provider.unwrap_dek(row.wrapped_dek, aad=row_id)` under the **old** version (the blob
    self-identifies its version);
  - `new = provider.wrap_dek(dek, aad=row_id)` under the **active** KEK;
  - `UPDATE … SET wrapped_dek=new.ciphertext, kek_version=new.kek_version WHERE id=row_id AND
    kek_version=<old>` (**compare-and-set** so a concurrent per-credential rotation can't be
    clobbered); then **zeroize `dek`**.
  - **`ciphertext`/`nonce` are never read or written** — the secret payload is untouched.
- **Idempotent + resumable** (ADR-0032 §3): `kek_version != active` is the worklist predicate; a
  crash mid-pass leaves un-migrated rows for the next run; re-running once all rows match `active`
  is a no-op.
- **Mixed versions valid at rest** (ADR-0032 §3): decrypt reads `row.kek_version` and unwraps under
  that specific version, so the platform keeps serving credentials throughout migration — no
  maintenance window, no big-bang re-encrypt. Old-version cutover only after zero rows reference it
  (and, for Vault Transit, after raising `min_decryption_version`).
- **Audit** (ADR-0032 §5): `kek.rotate.start` (before=`{from_version,row_count}`) /
  `kek.rotate.complete` (after=`{to_version,rows_migrated}`) into the ADR-0011 append-only
  `audit_log` — ids/versions/counts only, never DEK/KEK/wrapped bytes.
- **Rotation-status endpoint** (ADR-0032 §6): returns counts/versions only —
  `{from_version, to_version, rows_pending}` — **never blobs**; no schema exposes `wrapped_dek`/
  `kek_version` as response fields.
- Operator/auto-rotation entry: both the manual KEK bump and the KMS auto-rotation hook advance
  `provider.kek_version`; the job migrates regardless of trigger (ADR-0032 §3 step 1).

**Out**
- The provider implementations + per-backend rotation primitives (W6-T2; this job calls
  `wrap_dek`/`unwrap_dek` provider-agnostically).
- Per-credential (device re-issue) rotation — that path exists (`rotate_secret`) and changes
  `ciphertext`/`nonce`, **not** the KEK; this task must not disturb it (ADR-0032 §3 table).
- KEK escrow / key-recovery drill (PRODUCTION.md §8 — separate).

## Requirements (grounded in ADR-0032 §3, §5, §6)

1. **Rotate the wrapper, not the secrets** (ADR-0032 §3, the core win): only `wrapped_dek` +
   `kek_version` change per row; `ciphertext`/`nonce`/DEK value/device secret are untouched. A test
   must assert `ciphertext`/`nonce` are byte-identical before and after a re-wrap.
2. **Compare-and-set** on the UPDATE so a concurrent per-credential rotation is never clobbered
   (ADR-0032 §3 step 2).
3. **Idempotent + resumable** — crash-mid-pass and re-run leaves a consistent corpus; re-run on a
   fully-migrated corpus is a no-op (assert with a partial-failure test).
4. **Online, no maintenance window** — mixed `kek_version` rows decrypt correctly throughout
   (ADR-0032 §3 step 4); a decrypt test across mixed versions stays green during a simulated
   in-flight migration.
5. **Mandatory on suspected KEK compromise** (ADR-0032 §3) — the job is the rehearsed procedure;
   because no secret is re-encrypted, a full-corpus re-wrap is cheap/online.
6. **No key material in audit/response** (ADR-0032 §5/§6): rotation audit + status endpoint carry
   identifiers/versions/counts only; extends `test_no_key_material_leak`.

## Contracts / artifacts

- `re_wrap_keys` Celery task (worker; **not** Celery-beat-coupled to DR jobs — this is an app task
  triggered by operator/KMS hook) + a service function doing the batched compare-and-set re-wrap.
- A rotation-status endpoint on an existing router (no new router beyond the fixed ten — cf. M5
  task 15) returning `{from_version, to_version, rows_pending}`; RBAC `engineer`+ / admin.
- `audit_log` action emitters `kek.rotate.start` / `kek.rotate.complete`.

## Test & gate plan (Python TDD)

- ruff / mypy strict / import-linter / pytest ≥80% on touched modules.
- Re-wrap correctness (deterministic fake provider from W6-T2): after a KEK bump, all rows migrate to
  `active`; **`ciphertext`/`nonce` byte-identical** pre/post; the device secret still decrypts.
- Idempotent/resumable: inject a mid-pass failure ⇒ partial migration ⇒ re-run completes; re-run on a
  migrated corpus updates zero rows.
- Compare-and-set: a concurrent per-credential rotation during re-wrap is not clobbered.
- Mixed-version decrypt: rows at old and new versions both decrypt during an in-flight migration.
- Audit + status: `kek.rotate.start/complete` emitted with versions/counts only; status endpoint
  returns no blobs; `test_no_key_material_leak` extended and green (strong tier).

## Exit criteria

- [ ] `re_wrap_keys` migrates DEKs to the active KEK without touching `ciphertext`/`nonce` (proven
      byte-identical) — the ADR-0011 §1 "cheap re-wrap" promise (G-SEC).
- [ ] Idempotent, resumable, compare-and-set; mixed-version corpus decrypts throughout (online).
- [ ] `kek.rotate.start`/`complete` audited (versions/counts only); status endpoint exposes no blobs.
- [ ] Per-credential rotation path untouched.
- [ ] No-key-material-leak gate extended and green; D16 gates green; rotation procedure documented
      (rehearsed-ready for PRODUCTION.md §5).

## Workflow (P1-PLAN.md §3, secret-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** in parallel → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- A re-wrap bug that touches `ciphertext`/`nonce` would silently corrupt the credential corpus — the
  byte-identical assertion is the guardrail and is mandatory.
- Without compare-and-set, a re-wrap racing a per-credential rotation could clobber a freshly-rotated
  secret — the concurrency test must exercise this.
