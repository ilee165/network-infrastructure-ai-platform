# W0-T4 — ADR-0045 Audit→SIEM export (syslog/CEF + HTTPS, at-least-once, export-lag SLO)

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** (audit spine leaves the platform) |
| **Depends on** | — |
| **Builds on** | ADR-0011 (credential vault + audit + change approval), ADR-0038 (audit hash-chain), ADR-0015 (observability), ADR-0041 (collector egress NetworkPolicy) |
| **PRODUCTION.md** | §5 (audit→SIEM export), §6 (export-lag SLO), §7 (audit-integrity report) |
| **Status** | Proposed |

## Objective

Ratify the **vendor-neutral** audit→SIEM export design (user decision 2026-06-29):
**RFC5424 syslog + CEF over TLS + a generic HTTPS/JSON push sink**, with
**at-least-once delivery, ordering, and backpressure**, and an **export-lag metric**
(p95 < 60 s SLO, §6). No vendor-specific adapter. Fix the cursor/checkpoint model
that guarantees no audit row is skipped, and the no-secret-leak boundary.

## Scope

**In** — transport set (syslog/CEF/HTTPS-JSON over TLS); the delivery contract
(at-least-once, monotonic ordering on the hash-chain `seq`, durable cursor so a
restart resumes without gap or unbounded dup); backpressure when the sink is down
(buffer + retry, never drop, never block the audit write); the export-lag SLI
definition; the redaction/no-leak boundary (no plaintext credential in an exported
record — extends the ADR-0011/§289 leak rule to the export path).

**Out** — implementation (W3-T1); a named vendor adapter (declined, named-deferred
→ customer/GA); the recording-rule/alert for the lag SLO (W3-T2/T3).

## Requirements (grounded in PRODUCTION.md §5/§6, ADR-0011/0038)

1. **At-least-once + ordered + no-gap:** a durable cursor over the hash-chain `seq`
   so every committed audit row is exported exactly once or more, in order, and a
   restart resumes from the cursor — never skips. (The hash-chain `seq` from
   ADR-0038 is the ordering key.)
2. **Backpressure, never lose audit:** sink outage buffers + retries with bounded
   memory; the **audit write path is never blocked** by export pressure (export is
   downstream of the DB commit, not in it).
3. **Export-lag SLI:** `now - last_exported_commit_ts`, exposed as a metric; SLO
   p95 < 60 s (§6) — the contract W3-T3 alerts on.
4. **No secret leak:** exported records carry the same redaction as the in-DB audit
   (§289); a test sentinel secret is **absent** from every exported payload.
5. **Egress confined:** the exporter's egress respects the ADR-0041 collector
   NetworkPolicy posture (only the SIEM endpoint).

## Contracts / artifacts

- `docs/adr/0045-audit-siem-export.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only. The ADR names the W3-T1 assertions: at-least-once under
  fault-injected sink outage, cursor-resume-no-gap, export-lag metric present, and
  the sentinel-secret-absent leak test.

## Exit criteria

- [ ] ADR-0045 written: transports; at-least-once + ordering + durable cursor; backpressure-never-blocks-audit; export-lag SLI; no-leak boundary; egress confinement.
- [ ] Vendor-neutral-only decision + adapter-deferred both named; ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** (audit spine) → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Export coupled into the audit commit** → a slow sink stalls the platform. The
  ADR must make export strictly downstream of commit.
- **Gap on restart** if the cursor isn't durable → silent audit loss in the SIEM.
  The cursor + `seq` ordering is mandatory.
- **Secret leak in an exported record** — the leak boundary must be explicit, tested
  in W3-T1.
