# ADR-0045: Audit→SIEM Export (RFC5424 syslog + CEF over TLS + HTTPS/JSON push, at-least-once, export-lag SLO)

**Status:** Accepted | **Date:** 2026-06-29 (Accepted 2026-07-05, W5-T3) | **Milestone:** P3 W0 (Accepted P3 W5)

## Context

`PRODUCTION.md` §5 requires **audit-log streaming export to the customer SIEM
(syslog/CEF + HTTPS push) in near-real-time**, with **export lag an SLO** (§6:
`Audit → SIEM export lag | p95 < 60 s`), and the **audit-integrity report** (§7)
and §11 G-OBS §339 (`Audit → SIEM export operating within the lag SLO`) restate it
as a release criterion. The §5 line was **deferred to P3-Platform** by the
§1 (2026-06-25) amendment — it "needs the live platform stack; the in-DB audit
hash-chain (ADR-0038) is the P2-Security audit-integrity control." This is the
P3-Platform half of that move: the in-DB tamper-evidence already exists
(ADR-0038); this ADR ratifies how that audit spine **leaves the platform** to an
external SIEM without losing, reordering, or leaking a row.

This ADR is the **design gate**. It ratifies the export design the build
implements in **W3-T1** (the export pipeline — transports, at-least-once + ordering
+ backpressure, export-lag metric) and whose lag SLO the observability wave alerts
on (**W3-T2** recording rule, **W3-T3** burn-rate alert). It does **not** implement
those controls. The audit log is the integrity root (ADR-0011 §2, ADR-0038) and the
exported records carry the audit spine off-platform, so this is a **secret-surface /
audit-spine decision** (strong review).

Bounded by **ADR-0011** (credential vault + append-only `audit_log` + change
approval — the §289 no-plaintext-credential leak rule), **ADR-0038** (audit-log
hash chaining — the monotonic append-order **`seq`** column is the ordering key this
export inherits), **ADR-0015** (observability — the export-lag metric is a
Prometheus gauge, the W3-T3 alert target), **ADR-0041** (collector egress
NetworkPolicy — the egress-confinement posture this exporter's outbound to the SIEM
respects), and **ADR-0032 §5** (audit rows carry no plaintext secret). PRODUCTION.md
§5, §6 (export-lag row), §7 (audit-integrity report), §11 G-OBS §339 are the
line-by-line source. The user decision (2026-06-29) is **vendor-neutral only**: the
three open transports, no vendor-specific adapter.

Per `P3-PLATFORM-PLAN.md` §0, the *mechanism* (at-least-once under sink outage,
cursor-resume-no-gap, lag metric, no-leak) is proven to bite at **reduced scale** in
W3-T1 against a fault-injected local sink; **certified-scale** throughput numbers are
**named deferred-accepted → GA / customer cluster**, never silently claimed.

## Decision

**A standalone export pipeline, strictly downstream of the audit DB commit, streams
every committed `audit_log` row to the customer SIEM over a vendor-neutral transport
set — RFC5424 syslog and ArcSight CEF, both over TLS, plus a generic HTTPS/JSON push
sink. Delivery is at-least-once and monotonically ordered on the ADR-0038 `seq`
append-order key, driven by a durable cursor (the last-exported `seq`) so a restart
resumes from the cursor with no skipped row and bounded duplication. A sink outage
buffers and retries with bounded memory and never drops a row and never blocks the
audit write path. The pipeline exposes an export-lag gauge (`now − commit_ts of the
last exported row`) with the §6 p95 < 60 s SLO. Exported records carry the same
redaction as the in-DB audit row — no plaintext credential ever leaves in an export
payload — and the exporter's egress is confined to the configured SIEM endpoint per
the ADR-0041 posture. No vendor-specific adapter is built; a named adapter is
deferred to customer/GA.**

### 1. Transports — vendor-neutral set only (user decision 2026-06-29)

Three transports, all standard SIEM-ingest formats, selectable by configuration; no
vendor-specific (Splunk HEC / Sentinel / QRadar) adapter is built:

- **RFC5424 syslog over TLS** (`syslog-tls`): structured-data syslog framed per
  RFC5424, transported over TLS (RFC5425 TLS transport / octet-counted framing), to a
  configured host:port — the lingua-franca SIEM ingest.
- **ArcSight CEF over TLS** (`cef-tls`): the audit fields mapped to the CEF header +
  extension dictionary, carried over the same TLS syslog transport — the common
  normalized-event format consumed by most SIEMs.
- **Generic HTTPS/JSON push** (`https-json`): the canonical audit JSON POSTed to a
  configured HTTPS collector endpoint (TLS, bearer/mTLS auth as configured) — the
  fallback for SIEMs that prefer an HTTP collector over syslog.

All three are **over TLS** (no cleartext export of the audit spine). The field
mapping (which `audit_log` columns map to which syslog SD-PARAM / CEF extension /
JSON key) is fixed in the W3-T1 implementation notes from the **already-redacted**
column set (§4); a transport is a *serialization* of the same canonical record, not a
different record. A vendor-specific adapter (Splunk HEC, Microsoft Sentinel, IBM
QRadar) is **declined and named-deferred → customer/GA**: the three vendor-neutral
transports cover the §5 requirement now, and a customer-specific adapter is a
superseding/extending decision when a customer requires it (G-MNT, no silent drift).

### 2. At-least-once + ordered + no-gap — durable cursor over `seq` — the load-bearing decision

The §5 requirement is **near-real-time streaming export** of every committed audit
row; G-OBS §339 makes "operating within the lag SLO" a release gate; and the audit
spine must arrive in the SIEM **complete and in order**. The ordering key is the
ADR-0038 **`seq`** column — the monotonic append-order key the audit writer assigns
`MAX(seq)+1` under a transaction-scoped advisory lock (`backend/app/models/audit.py`,
ADR-0038 §3). `seq` (not `(created_at, id)`) is the chain's order, so two rows with an
equal `created_at` can never be exported in an ambiguous order.

- **Durable cursor = last-exported `seq`.** The exporter persists a watermark — the
  highest `seq` it has confirmed delivered to the sink — in a durable store (a small
  Postgres row, mirroring the ADR-0038 §4 `audit_chain_checkpoint` watermark pattern).
  On each cycle it reads committed rows with `seq > cursor` **ordered by `seq`**,
  delivers them, and advances the cursor only after the sink **acknowledges**. The
  cursor advances strictly monotonically; it is never advanced over an unacknowledged
  row.
- **At-least-once + no-gap on restart.** The cursor is advanced only on sink ACK, so a
  crash between "sink received" and "cursor persisted" re-exports the un-advanced rows
  on restart — **at-least-once, never at-most-once**: no committed row is ever skipped.
  A restart resumes from the persisted cursor and reads forward by `seq`, so there is
  **no gap** and only **bounded duplication** (at most the in-flight batch). The SIEM
  side deduplicates on `seq` (a stable per-row key included in every transport
  payload) — exactly-once *effect* on an at-least-once *channel*.
- **Monotonic ordering.** Rows are always selected and delivered `ORDER BY seq`, the
  same key the ADR-0038 verifier uses, so SIEM-side order matches DB append order.
- **Pre-chain / NULL-`seq` rows — excluded from the `seq`-cursor export, mirroring the
  verifier.** ADR-0038 leaves `seq` NULLABLE only for pre-W4 old-writer rows (which
  also carry the genesis `entry_hash` and are treated as untrusted pre-chain history).
  The cursor model operates **only** over the chained, non-NULL-`seq` rows: the
  exporter's read carries the same `seq IS NOT NULL` filter the ADR-0038 verifier
  applies (`backend/app/services/audit/verify.py`, `_entries_after`), so it selects and
  delivers exactly the rows the chain walks and **never streams a NULL-`seq` pre-chain
  row into the SIEM**. This is the corrected decision: NULL-`seq` rows are **not**
  ordered NULLS-FIRST into the export stream. Doing so would contradict the audit-integrity
  control — the verifier deliberately EXCLUDES NULL-`seq` rows (PostgreSQL sorts NULLs
  FIRST, which would otherwise FALSE-break the chain) and `count_pre_chain_rows()`
  surfaces them separately and treats a non-genesis-hash NULL-`seq` row as a LOUD FAILURE
  (suspicious / likely tampered). Exporting those rows would stream into the SIEM exactly
  the rows the integrity control keeps out of the chain and flags as suspicious. Residual
  pre-chain rows are a bounded, transitional pre-W4 set (the verify job already counts and
  fails loud on suspicious ones); their off-platform disposition is **not** part of the
  `seq`-cursor export and is left to the audit-integrity report (PRODUCTION.md §7), not the
  SIEM stream. The export contract is therefore consistent with the ADR-0038 verifier:
  both walk the non-NULL-`seq` chain in `seq` order and both exclude NULL-`seq` pre-chain
  history.

### 3. Backpressure — never lose audit, never block the audit write path

The dominant risk (W0-T4 §Risks) is **export coupled into the audit commit**: a slow
or down SIEM must never stall the platform. Therefore:

- **Export is strictly downstream of the DB commit, not inside it.** The audit writer
  (`audit_service.record()`, `backend/app/services/audit/service.py`) is unchanged: it
  flushes the audit INSERT in the **caller's** action transaction and the caller
  commits (ADR-0011 §2, ADR-0038; ADR-0042 §2 makes that commit synchronous for
  durability). The exporter reads **already-committed** rows by `seq` cursor — it is a
  separate process/loop with **no path that can hold open or roll back the action
  transaction**. A sink outage cannot apply backpressure to the audit write.
- **Buffer + retry with bounded memory; never drop.** When the sink is down or slow,
  the exporter retries with capped backoff. Backpressure is absorbed by the **durable
  audit table itself** — because the cursor is the source of truth, the unsent rows
  already sit committed in `audit_log`; the exporter simply does not advance the cursor
  and re-reads forward when the sink recovers. Any in-memory batch/queue is **bounded**
  (a fixed read-batch size, fixed in W3-T1), so a long outage grows lag (visible on the
  §3-below metric) and the durable backlog, never unbounded memory. **No row is ever
  dropped to relieve pressure** — drop is not a failure mode of an at-least-once cursor.
- **Export-lag SLI:** `now − commit_ts of the last exported audit row` (the §44 W0-T4
  definition; in practice the `created_at`/commit timestamp of the row at the cursor),
  exposed as a Prometheus gauge (ADR-0015). SLO **p95 < 60 s** (§6). This is the metric
  **W3-T2** turns into a recording rule and **W3-T3** alerts on (multi-window burn
  rate, runbook-linked). A growing backlog (sink down) drives lag up and fires the
  alert — the operator-visible signal that export has stalled, with no audit loss.

### 4. No secret leak — exported records carry the in-DB redaction (§289 boundary)

PRODUCTION.md §307 (G-SEC) forbids any plaintext device credential in any API
response, log, trace, **or backup sample**; ADR-0011 establishes the no-leak boundary
and ADR-0032 §5 / ADR-0038 §5 record that **audit rows carry no plaintext secret** —
the audited columns are ids/actor/action/target/`request_id`/`reasoning_trace_id` and
a structured `detail` that is already secret-free. The export path **extends that same
boundary to the wire**:

- An exported record is a serialization of the **already-redacted** `audit_log` row —
  the export adds no new field that re-introduces a secret, and does not re-read the
  credential vault or any plaintext source. Redaction is inherited, not re-implemented.
- **W3-T1 ships a sentinel-secret leak test:** a known sentinel secret is planted in
  the credential/action path, an audited action is exported through **each** transport
  (syslog/CEF/HTTPS-JSON), and the test asserts the sentinel is **absent from every
  exported payload** (the §45 W0-T4 leak assertion). This is the export-path mirror of
  the existing in-DB no-secret-in-audit posture, and it bites per transport — a CEF
  extension or JSON key that accidentally carried `detail` plaintext would be caught.
- The transport itself is **TLS** (§1), so even the redacted record is not exposed in
  cleartext on the network.

### 5. Egress confinement — exporter outbound respects the ADR-0041 posture

The exporter reaches **out** of the cluster to the SIEM endpoint, so its egress is a
segmentation surface. It runs under a default-deny egress NetworkPolicy that re-permits
**only** the configured SIEM endpoint(s) (host:port / CIDR, operator-configured via
chart values) plus the in-cluster services it needs (Postgres for the cursor + audit
read, kube-dns), mirroring the ADR-0041 collector-egress allow-list pattern. A
compromised exporter cannot exfiltrate to an arbitrary destination — its only external
reach is the SIEM it is configured to feed. As with ADR-0041, NetworkPolicy enforcement
**requires an enforcing CNI** (kind's default does not enforce it); the W4-T1 harness
already installs Calico/Cilium, and any kind assertion of the exporter deny rides that
cluster (named for the build, not asserted here — design gate only).

### 6. Build-task contract — the assertions this ADR pins

So the build task has a testable contract (the ADR is the design; the gates are the
proof):

- **W3-T1** (`wf-implementer`, escalated — audit spine): the export pipeline emits the
  three vendor-neutral transports (RFC5424 syslog-TLS, CEF-TLS, HTTPS/JSON), driven by
  a durable last-exported-`seq` cursor. The required assertions:
  - **At-least-once under fault-injected sink outage:** with the sink forced down then
    recovered, every committed row is eventually delivered (≥ once), no row dropped.
  - **Cursor-resume-no-gap:** kill the exporter mid-stream; on restart it resumes from
    the persisted cursor, the SIEM receives a contiguous `seq` sequence with **no gap**
    and only bounded duplication.
  - **Ordering:** delivered order matches `ORDER BY seq` (= DB append order).
  - **Export-lag metric present** and reflects backlog: a held-down sink drives the lag
    gauge up; a recovered sink drains it below the SLO.
  - **Sentinel-secret-absent leak test** across all three transports (§4).
  - **Audit write path unblocked:** an assertion that a sink outage does **not** delay
    or fail an audited action commit (export is downstream of commit, §3) — the
    negative control that proves the decoupling bites.
- **W3-T2** (`wf-observability`): a Prometheus **recording rule** for the export-lag
  SLI (§6).
- **W3-T3** (`wf-observability`): a **multi-window burn-rate alert** on the export-lag
  SLO with a `promtool` firing test (a synthetic high-lag series **fires** the alert —
  the gate must RUN and BITE, P1-W4 lesson) and a runbook link.

### 7. Scope boundary

**In:** the export design — the vendor-neutral transport set (syslog/CEF/HTTPS-JSON
over TLS), the at-least-once + ordered + durable-`seq`-cursor delivery contract, the
backpressure-never-blocks-audit posture, the export-lag SLI definition, the no-leak
boundary on the export path, and the egress-confinement posture. **Out:** the
implementation (W3-T1); a named vendor-specific adapter (declined, named-deferred →
customer/GA); the recording rule / burn-rate alert for the lag SLO (W3-T2 / W3-T3);
log/event retention windows (the Consultant data-retention open item, §12); certified
export throughput at scale (named deferred-accepted → GA, §0). Neo4j/Redis and the
non-audit log streams are **out** — this ADR is the `audit_log` → SIEM path only.

## Consequences

**Positive**
- The audit spine reaches the customer SIEM in near-real-time, complete and in order
  — satisfying §5 and the G-OBS §339 in-lag-SLO release criterion.
- At-least-once over a durable `seq` cursor means **no committed audit row is ever
  silently lost** in the SIEM, even across exporter restarts and SIEM outages — the
  gap-on-restart risk (W0-T4) is closed by the cursor + `seq` ordering.
- Export strictly downstream of the DB commit means a slow/down SIEM **never stalls the
  platform** — the "export coupled into the audit commit" risk is closed by design.
- Vendor-neutral transports keep the platform un-coupled to any one SIEM vendor; a
  customer adapter is an additive, not a rewrite.
- The export-lag gauge gives an operator-visible, alertable signal of a stalled export
  with **no audit loss** — backlog grows in the durable table, not in lost rows.
- Reusing the ADR-0038 `seq` ordering key and the redacted-column posture means the
  export inherits ordering and no-leak from the in-DB audit spine rather than
  re-deriving them.

**Negative**
- At-least-once means **duplicates are possible** (bounded to the in-flight batch on a
  crash); the SIEM must deduplicate on the per-row `seq` key — stated, and the price of
  never-lose over never-duplicate (exactly-once delivery over a network is not
  achievable, so the at-least-once + idempotent-key shape is chosen deliberately).
- A long SIEM outage grows the durable backlog and the export lag (visible, alerted),
  and a very long outage interacts with the §7 retention window — if audit rows are
  pruned before export under an extreme outage, unexported rows could be lost; the
  retention-vs-export-lag interaction is named for the Consultant retention answer
  (§12) and must keep retention ≥ max tolerated export backlog.
- Three transports are three serialization surfaces to keep correct (and leak-test,
  §4); the field mapping is fixed once in W3-T1 and covered by the per-transport
  sentinel test to bound the maintenance/leak surface.
- The exporter is another egress surface (§5) — bounded by the ADR-0041-style
  default-deny-to-SIEM-only NetworkPolicy, which (like ADR-0041) requires an enforcing
  CNI to bite.

## Alternatives considered

1. **Export inside the audit write transaction (synchronous push to SIEM on commit).**
   Rejected (§3, W0-T4 dominant risk): a slow or down SIEM would stall every audited
   action — coupling the platform's availability to the SIEM's. Export must be strictly
   downstream of the DB commit; the durable audit table is the buffer.
2. **Fire-and-forget / best-effort export (no cursor, no durability).** Rejected: an
   exporter crash or SIEM outage would silently drop the audit rows in flight — the
   exact silent-audit-loss-in-the-SIEM risk (W0-T4) the gate exists to close. A durable
   `seq` cursor with at-least-once is mandatory.
3. **At-most-once (advance cursor before sink ACK).** Rejected: a crash between cursor
   advance and sink delivery loses rows with no trace. At-least-once (advance only on
   ACK) + SIEM-side dedup on `seq` is the correct trade for an audit spine — never lose,
   tolerate bounded duplicates.
4. **Order by `(created_at, id)` instead of `seq`.** Rejected: equal-`created_at` rows
   would order ambiguously by random UUID, the exact failure ADR-0038 introduced `seq`
   to fix. `seq` is the single monotonic append-order key for both the verifier and the
   export cursor.
5. **A vendor-specific adapter (Splunk HEC / Microsoft Sentinel / IBM QRadar).**
   Declined by the user decision (2026-06-29) and **named-deferred → customer/GA**: the
   three vendor-neutral transports meet §5 now; a vendor adapter is an
   additive/superseding decision when a customer requires it (G-MNT, no silent drift).
6. **Kafka / message-bus as the export transport.** Rejected for P3: adds a broker
   dependency the §5 requirement (syslog/CEF + HTTPS push) does not call for and most
   SIEMs ingest syslog/CEF/HTTPS directly. A bus is a future option if a customer
   standardizes on it; not the shipped vendor-neutral set.
7. **Logging-sidecar / node log-shipper scrapes the app's stdout audit lines.**
   Rejected: stdout scraping has no delivery guarantee, no ordering guarantee, and no
   redaction boundary owned by the platform — it would risk both gaps and leaks. The
   `seq`-cursor pull from the durable `audit_log` is the auditable, gap-free, redacted
   source.
