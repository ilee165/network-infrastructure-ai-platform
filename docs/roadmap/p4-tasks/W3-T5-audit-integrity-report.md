# W3-T5 — Audit-integrity report: daily hash-chain verification history + append-only grant attestation — admin floor

| | |
|---|---|
| **Wave** | P4 W3 — Compliance & audit reporting suite |
| **Owner** | `wf-implementer` (strong) |
| **Review tier** | **strong** spec + quality (escalated: hash-chain integrity surface) |
| **Depends on** | **W3-T1** (engine) |
| **ADRs** | ADR-0053 §7.4 (binding), ADR-0038 (hash chain + daily verification CronJob) |
| **PRODUCTION.md** | §7 (audit integrity report), §5, §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement the ADR-0053 §7.4 audit-integrity report: **per-day hash-chain
verification outcomes for the period + the append-only grant attestation** —
surfacing the ADR-0038 spine as 7-year-capable evidence (metrics retention
cannot back an evidence trail). Includes the named small additive change to the
ADR-0038 CronJob: writing **`audit_chain_verification_runs`** rows.

## Scope

**In** — the `audit_chain_verification_runs` table (expand-only migration;
`started_at`/`finished_at`, verified range, `outcome` clean|break, checkpoint
before/after) + the additive CronJob change writing a row per run (metric +
exit-code behavior unchanged); report payload + queries: per-day outcomes,
**missing days surfaced as gap findings** (a verification that never ran is a
finding, not a blank); generation-time **grant attestation** — the generator
queries the PG catalog and attests no `UPDATE`/`DELETE` grant exists on
`audit_log`, recording result + timestamp; CSV + PDF templates; regime tags
(`soc2:CC7.2`); monthly cadence (PROPOSED); **admin** floor both ends.

**Out** — any change to the chain construction or verification algorithm
(ADR-0038 unchanged; the CronJob gains persistence only); chain *entry*
content (the report carries outcomes and ranges, plus presentation of digests
— which the redaction filter deliberately does not flag, ADR-0053 §6).

## Requirements (grounded in ADR-0053 §7.4/§6, ADR-0038)

1. **History, not just signal** — every CronJob run persists an outcome row;
   the report reads history, never re-verifies inline (generation must not
   take chain-verification time).
2. **Gaps are findings** — missing verification days render as explicit
   findings in the artifact.
3. **Attestation is live** — the grant check runs at generation time against
   the PG catalog (the G-SEC "append-only attested" criterion), not cached.
4. **Digests allowed, secrets not** — SHA-256 presentation must not trip
   redaction (format-anchored patterns, no entropy detection — asserted).
5. **All queries under `tests/pg/`** (the grant-check runs against real PG by
   nature — SQLite has no grant catalog).

## Contracts / artifacts

- Migration + CronJob additive change; payload + queries + templates + regime
  tags; golden fixture for W4-T3.

## Test & gate plan

- Full gate suite; `tests/pg/`: verification-run persistence, gap detection
  (missing day), break-outcome rendering, grant attestation against real PG
  (REVOKE semantics — the P2 lesson class).
- CronJob test: a verification run writes exactly one row; failure path still
  exits non-zero + persists `break`.
- Redaction sanity: digest-bearing payload passes; planted PEM value rejects.
- Golden CSV/PDF structure fixture green.

## Exit criteria

- [ ] `audit_chain_verification_runs` persisted by the daily CronJob (additive; metric/exit behavior unchanged).
- [ ] Report renders per-day outcomes + gap findings + live grant attestation at admin only, CSV + PDF.
- [ ] Digest presentation unflagged by redaction; `tests/pg/` coverage incl. the grant check.
- [ ] One atomic commit.

## Workflow

`wf-implementer` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Inline re-verification** at generation would couple report latency to
  chain length — read history instead (requirement 1).
- **Attestation staleness** — caching the grant check would let a granted
  UPDATE slip a period; it runs live per generation.
