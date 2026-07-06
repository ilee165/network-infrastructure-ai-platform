# W0-T3 — ADR-0052 application-dependency topology (PG-backed `Application`/`DEPENDS_ON`, four sources, direct-write tagging)

| | |
|---|---|
| **Wave** | P4 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** (escalated from sonnet at plan review 2026-07-05 — tagging-authz section is secret-surface-adjacent; the projection decision carries the D5 rebuild contract) |
| **Depends on** | — (reads ADR-0050/0051 drafts for the upstream model contract) |
| **Builds on** | ADR-0005 D5 (rebuildable projection), ADR-0011 (audit spine), ADR-0038 (hash-chain), ADR-0050/0051 (W1 upstream models), M5 DNS layer (`engines/topology/dns.py`) |
| **PRODUCTION.md** | §2.4 (app-dependency paragraph), §11 G-REL/G-SEC |
| **Status** | **Done** (W0, `feat/p4-w0-adrs`) |

## Objective

Ratify the application-dependency design the W2 build implements
mechanism-for-mechanism: **two PG tables (`applications`,
`application_dependencies`) as system of record behind an expand-only migration,
projected to Neo4j as `Application`/`DEPENDS_ON` under the existing projector
mechanics; exactly four derivation sources with per-source provenance,
per-source row ownership, additive-evidence conflict semantics, manual-wins
attribute precedence, and idempotent re-derivation; derivation/projection wired
into the MANDATORY whole-inventory pass (never an optional kwarg); tagging as a
direct write at the `engineer` floor with full audit (CR-gating declined — user
decision 2026-07-05); impact analysis as a `topology_read` extension + read-only
provenance-citing Troubleshooting-Agent tool.**

## Scope

**In** — schema field tables (§1), the closed four-source set + the source-3
caller-fetched-inputs exception (§2), rebuild-safe target restriction
(`Device`/`IPAddress` only, §2.3), provenance/edge-identity/precedence rules
(§3), idempotency under real PG (§4), projection contract + mandatory-pass
wiring (§5), rebuild-drill/SLO exit criteria (§6), the tagging authz decision +
hard edges (§7), impact surface (§8).

**Out** — implementation (W2-T1..T4); the eval corpus (W4-T2); flow-telemetry
enrichment (out until Consultant Q10 answered); `DnsRecord`/app-to-app edge
targets and intermediate node labels (all named-deferred); re-wiring the M5
DNS display layer.

## Requirements (grounded in D5/ADR-0005, PRODUCTION.md §2.4, P4-PLAN §0a)

1. **Rebuild from Postgres alone** — no edge target that vanishes on rebuild;
   the auto-rebuild reconciler and `neo4j-rebuild-bite.sh` must stay green with
   the new kinds (explicit exit criteria restated in the ADR).
2. **The `dns=` optional-kwarg deletion hazard must not be repeated** — the
   application layer joins every production projection pass mandatorily.
3. **Tagging decision recorded, not re-opened:** direct write under RBAC
   (`engineer`+) + full audit entry per mutation; the Consultant item may refine
   the role floor only. Agents cannot tag in P4.
4. **Every edge carries provenance** traceable through normalized rows to
   verbatim raw artifacts; no secret material can enter the layer (references
   by id, never content).
5. **Idempotency + partial-unique-index semantics asserted under real PG**
   (`tests/pg/`, blocking `pg-integration`).

## Contracts / artifacts

- `docs/adr/0052-application-dependency-topology.md` (Proposed); index entry via W0-T5.

## Test & gate plan

- D16 docs gates only (ADR — no code). The ADR names the exact assertions
  W2-T1 (schema/projection/rebuild), W2-T2 (idempotent derivation), W2-T3
  (authz/audit), W2-T4 (provenance-citing impact) and W4-T2 (planted wrong-edge
  negative control) must satisfy.

## Exit criteria

- [x] ADR-0052 written (Proposed): schema, four sources, provenance/precedence, idempotency, mandatory-pass projection, rebuild-drill compatibility, tagging decision, impact surface.
- [x] Reviewed whole at the strong bar (plan-review escalation).
- [x] Named deferrals recorded (`DnsRecord` targets, app-to-app edges, intermediate labels, suppress-derived flag).
- [x] One atomic commit (`7092be2`, review fixes folded).

## Workflow

`wf-implementer` drafts → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Optional-layer wiring regression** — a future pass omitting the layer would
  silently sweep it; the mandatory-pass integration is the load-bearing
  decision.
- **Manual-wins dirty tracking** under-specified → derivation clobbers operator
  edits or freezes derived metadata; the ADR names the mechanism for W2-T1 and
  flags it for the reviewer.
