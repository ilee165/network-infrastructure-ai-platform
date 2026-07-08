# W2-T2 — Derivation pipelines: F5 VIP→pool→member, VMware VM→host, M5 DNS linkage — idempotent, provenance per edge

| | |
|---|---|
| **Wave** | P4 W2 — Application-dependency topology |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | **W2-T1** (tables), **W1-T1** (persisted ADC rows), **W1-T2** (persisted virtualization rows) |
| **ADRs** | ADR-0052 §2/§3/§4 (binding), ADR-0050 §4 / ADR-0051 §5.5 (upstream field contracts) |
| **PRODUCTION.md** | §2.4, §11 G-REL |
| **Status** | Implemented — `1e8d16f` (P4 W2) |

## Objective

Implement the ADR-0052 §2 derivation: **one deterministic, pure derivation
function** (no I/O inside; inputs loaded by the caller; output independent of
input ordering — the `derive_dns`/`derive_topology` house pattern) producing
`application_dependencies` rows for the three automated sources — **F5
VIP→pool→member chains, VMware VM→host placement (chain extender), M5 DNS
dependencies (caller-fetched inputs)** — with per-source provenance chains,
per-source row ownership, and idempotent diff-replace by natural key.

## Scope

**In** — source 1: derived application per virtual server
(`origin_ref = f5:<device_pg_id>:<vs_full_path>`), edges to reconciled member
endpoints (`ip_address` else `device`), unreconcilable members counted in
stats, VS-name-as-FQDN seed heuristic; source 2: chain-extender edges
app→hypervisor-host device via manual-tag or member-IP↔guest-IP reconciliation,
VM hop recorded in provenance, no edge for hosts not in inventory; source 3:
M5 `_AddressIndex` reconciliation applied to caller-fetched DDI records for
each application's `fqdns`, CNAME hops in provenance; name-collision attach
(case-insensitive, §3.3.4); manual rows never touched (§3.3.1); diff-replace
per source inside one transaction, unchanged rows not rewritten (§4);
post-discovery-run trigger wiring for sources 1–3; derivation stats/metrics.

**Out** — the projection (W2-T1); tagging (W2-T3 = source 4, user-written);
the eval corpus + precision/recall thresholds (W4-T2); flow telemetry (closed
set of four); `DnsRecord`/app-to-app targets (named-deferred).

## Requirements (grounded in ADR-0052 §2/§3/§4)

1. **Deterministic + pure** — same inputs ⇒ same rows; no plugin/DDI calls
   inside the derivation function (source 3's DDI fetch is the caller's).
2. **Per-source row ownership** — a pass for source *S* inserts/updates/deletes
   only `source=S` rows; `manual` rows untouchable.
3. **Idempotent re-derivation** — re-run against unchanged inputs is a no-op
   (no `updated_at`/audit churn); `derived` apps MERGE on `origin_ref` (stable
   UUIDs ⇒ stable Neo4j keys, no duplicate nodes).
4. **Provenance on every row** — ordered evidence chain, refs by row id/natural
   key only, never embedded content (no secret path).
5. **Rebuild-safe targets only** — `device`/`ip_address`; source 3's *results*
   persist so rebuild never needs DDI reachability.
6. **Manual-wins precedence** respected (via the W2-T1 dirty-tracking
   mechanism); scalar precedence `manual > f5 > vmware > dns`.

## Contracts / artifacts

- `engines/topology/` derivation module + trigger wiring; derivation stats
  surfaced (counters for emitted/unreconciled per source); tests + `tests/pg/`.

## Test & gate plan

- Full gate suite; `tests/pg/` under `pg-integration`: idempotent diff-replace,
  natural-key upsert, per-source ownership isolation, origin_ref MERGE
  stability, dirty-tracking interaction.
- Unit fixtures per source incl.: unreconcilable member (no edge, counted);
  FQDN member joining guest IPs; VM without inventory host (no edge);
  case-insensitive name-collision attach; input-order permutation (same
  output).
- The prove-it-bites corpus lands in W4-T2; this task ships correctness tests.

## Exit criteria

- [ ] All three automated sources emit provenance-carrying rows per the ADR-0052 §2 table.
- [ ] Re-run ⇒ no-op asserted under real PG; no duplicate applications or edges.
- [ ] Per-source ownership + manual-untouched asserted under real PG.
- [ ] Post-discovery-run trigger wired; derivation never projects (writes flow one way).
- [ ] One atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Reconciliation precision** — member-IP↔guest-IP joins on stale
  Tools-reported IPs create wrong edges; the W4-T2 corpus thresholds catch
  drift, and provenance makes every edge auditable.
- **Cross-source coupling** — source 2 depends on source 1's reconciliation
  results in the same pass; ordering inside the function must be explicit and
  deterministic.
- **Transaction size** on large estates — diff-replace batches within one
  transaction per source; bounded by ADC-scale volumes (ADR-0050 Negative #4).
