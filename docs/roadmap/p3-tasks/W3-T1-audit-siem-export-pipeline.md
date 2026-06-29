# W3-T1 — Audit→SIEM export pipeline (syslog/CEF/HTTPS, at-least-once, export-lag metric)

| | |
|---|---|
| **Wave** | P3 W3 — SIEM export + SLO enforcement |
| **Owner** | `wf-implementer` (escalated — audit spine) |
| **Review tier** | **strong** spec + quality (audit material leaves the platform) |
| **Depends on** | W0-T4 (ADR-0045) |
| **ADRs** | ADR-0045 (the contract), ADR-0011 (audit), ADR-0038 (hash-chain `seq`), ADR-0015 (metrics), ADR-0041 (egress NetworkPolicy) |
| **PRODUCTION.md** | §5, §6 (export-lag SLO), §7 |
| **Status** | Proposed |

## Objective

Implement ADR-0045: a **vendor-neutral** audit→SIEM export pipeline —
**RFC5424 syslog + CEF + generic HTTPS/JSON over TLS** — delivering audit rows
**at-least-once, in `seq` order, with backpressure**, never blocking the audit
write path, and exposing an **export-lag metric** (the p95 < 60 s SLO that W3-T3
alerts on). No vendor adapter (decision 2026-06-29).

## Scope

**In** — the exporter (a worker/sidecar reading committed audit rows via a durable
cursor over the hash-chain `seq`); RFC5424 syslog + CEF formatters + an HTTPS/JSON
sink, all over TLS; at-least-once + ordered + no-gap delivery; bounded buffer +
retry on sink outage; the `export_lag_seconds` metric; redaction parity with the
in-DB audit (no plaintext credential exported); egress confined per ADR-0041.

**Out** — a named vendor adapter (deferred → GA); the recording rule + alert for the
lag SLO (W3-T2/T3); the daily hash-chain *verification* job (P2 ADR-0038, exists).

## Requirements (grounded in ADR-0045, ADR-0038, PRODUCTION.md §5/§6)

1. **At-least-once + ordered + no-gap** — a durable cursor over `seq`; a restart
   resumes from the cursor without skipping; ordering follows the hash-chain.
2. **Never block the audit write** — export is strictly downstream of the DB commit;
   a sink outage buffers (bounded) + retries, never stalls the write path and never
   drops a row.
3. **`export_lag_seconds` metric** = `now - last_exported_commit_ts`; the SLI W3-T3
   alerts on (p95 < 60 s).
4. **No secret leak** — a sentinel secret is **absent** from every exported payload
   (syslog/CEF/HTTPS); redaction parity with §289.
5. **Egress confined** — exporter egress allowed only to the SIEM endpoint (ADR-0041
   posture).

## Contracts / artifacts

- Exporter module + 3 formatters (syslog/CEF/HTTPS-JSON); durable cursor; metric;
  tests (at-least-once under sink outage, cursor-resume-no-gap, lag metric present,
  sentinel-secret-absent); deployment wiring (worker or sidecar — L3 `sh -c` if exec argv).

## Test & gate plan

- Unit/integration (`tests/pg/` for the cursor over real PG): at-least-once under a
  fault-injected sink outage; **cursor resume leaves no gap**; lag metric exposed;
  **sentinel secret absent** from every formatter's output.
- Backend D16 gates green; `include_router` introspection green; mypy/ruff clean.
- If deployed as a sidecar/Job: L3 `sh -c` on exec argv; infra render gates green.

## Exit criteria

- [ ] Exporter emits valid RFC5424 syslog + CEF + HTTPS/JSON over TLS.
- [ ] At-least-once + ordered + **no-gap on restart** (durable `seq` cursor) proven on real PG; never blocks the audit write.
- [ ] `export_lag_seconds` metric exposed; **sentinel-secret-absent leak test bites**; egress confined.
- [ ] `pg-integration` + backend D16 + `include_router` green; one atomic commit.

## Workflow

`wf-implementer` (escalated) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Export coupled into the commit** → a slow SIEM stalls the platform. Strictly
  downstream.
- **Cursor not durable** → silent gap (audit loss in the SIEM) after a restart.
- **Secret in an exported record** → the worst leak (audit fans out widely). The
  leak test must bite.
