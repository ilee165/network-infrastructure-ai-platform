# W0-T5 — ADR-0038 Audit-Log Hash Chaining + Daily Verification

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** spec + **strong** quality (audit spine — tamper-evidence is the integrity root) |
| **Depends on** | — (independent of T1–T4) |
| **ADRs** | ADR-0011 §2 (append-only `audit_log`), migration 0009 (M5 append-only trigger + retention index), ADR-0015 (observability — verify-job metric/alert) |
| **PRODUCTION.md** | §5 (audit-log integrity), §11 G-SEC / G-MNT |
| **Status** | Proposed |

## Objective

Decision record for making the append-only `audit_log` **tamper-evident**: each
entry carries a **predecessor hash**, forming a hash chain; a **daily
verification job** recomputes the chain and alerts on any break. Design gate;
build is **W4-T1**.

## Scope

**In**
- **Chain construction:** each `audit_log` entry stores `entry_hash =
  H(canonical(entry_fields) || prev_hash)`; a fixed **genesis** value seeds the
  chain. Decide the hash (SHA-256), the **canonical serialization** of the hashed
  fields (ordering, encoding — so the recompute is deterministic), and which
  columns are added (e.g. `prev_hash`, `entry_hash`) → **migration** (new
  Alembic revision; current head is `0010`).
- **Append-only interplay** (migration 0009): the chain sits on top of the
  existing append-only trigger; decide how the per-insert `prev_hash` is set
  (trigger vs application write) and that it cannot be back-filled silently.
- **Daily verification job:** a CronJob recomputes the chain end-to-end (or from
  the last verified checkpoint), emits a metric + **alerts on a break**
  (ADR-0015). Decide checkpointing for large logs.
- **Tamper-detection test:** mutating/deleting a row mid-chain is detected by the
  verifier — an exit-criterion test.

**Out**
- Implementation (migration, chain write, CronJob, test) → **W4-T1**.
- SIEM export of the audit log → **P3-Platform** (re-scoped out, §0).
- mTLS / network controls → W0-T6 / W0-T8.

## Requirements (grounded in ADR-0011 §2, migration 0009, ADR-0015)

1. **Append-only preserved** (ADR-0011 §2): hash chaining strengthens, never
   weakens, the existing trigger; no UPDATE/DELETE path is introduced.
2. **Deterministic recompute**: the canonical hashed form is fully specified so an
   independent verifier reproduces `entry_hash` byte-for-byte — otherwise the job
   false-alarms.
3. **Break is loud** (ADR-0015 / secure-by-default): a chain break raises an alert
   and a failing verification status; it never silently passes.
4. **No secret material hashed-in-the-clear**: the canonical form excludes (or
   already-redacted) any secret payload; audit rows already carry ids/versions
   only (cf. ADR-0032 §5 posture).
5. **K8s exec-argv discipline** (P1-W4-LESSONS **L3**): the verify CronJob wraps
   any `$(VAR)` in `sh -c "tool \"$VAR\""` — K8s does not substitute `$(VAR)` in
   exec argv. (Flagged for W4-T1; recorded in the ADR's implementation notes.)

## Contracts / artifacts

- Alembic revision adding chain columns to `audit_log` (forward + down).
- Chain-write path (trigger or application) defined.
- Verification CronJob (Helm-rendered) + a Prometheus metric + alert rule.

## Validation / Test & gate plan (ADR review — strong)

- Repo ADR template; canonicalization spec is unambiguous (the recompute is
  reproducible from the ADR alone).
- **Consistency with migration 0009**: chain does not bypass the append-only
  trigger; genesis + ordering defined.
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0038 written; status **Proposed**.
- [ ] Chain construction (hash, canonical form, genesis, columns) fixed.
- [ ] Append-only interplay + per-insert `prev_hash` mechanism decided.
- [ ] Daily verify-job behavior (recompute, checkpoint, metric, alert) decided.
- [ ] Tamper-detection test named as a W4-T1 exit criterion; L3 exec-argv noted.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` writes ADR → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Non-deterministic canonicalization** ⇒ a verifier that false-alarms or, worse,
  one tuned until it stops alarming (masking real tampering). The ADR must nail
  the byte-exact form.
- **Checkpoint design** for a large/long log: a full recompute every day may not
  scale; decide a verified-checkpoint strategy now so W4-T1 doesn't bolt one on.
