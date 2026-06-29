# W0-T1 — ADR-0042 Postgres HA (CloudNativePG 1+2) + PgBouncer + synchronous audit write path

| | |
|---|---|
| **Wave** | P3 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** (data tier + audit spine) |
| **Depends on** | — |
| **Builds on** | ADR-0004 (Postgres pgvector system-of-record), ADR-0029 (Helm GA + hardening), ADR-0030 (backup/DR baseline), ADR-0038 (audit hash-chain) |
| **PRODUCTION.md** | §3.1/§3.2, §8, §11 G-REL |
| **Status** | Proposed |

## Objective

Ratify the Postgres HA design the W1/W4 build implements: **CloudNativePG operator,
1 primary + 2 streaming replicas, PgBouncer in front, and synchronous (quorum)
replication on the `audit_log` write path** so a committed audit entry survives
primary loss. Fix the failover behaviour (automatic promotion, write service
restored ≤ 60 s) and the pgvector-on-replica requirement.

## Scope

**In** — the design decision and its rationale: operator choice (CloudNativePG vs.
Patroni fallback), replica count, PgBouncer pooling mode, **which write paths are
synchronous** (audit only, vs. all), quorum/`synchronous_standby_names` shape, how
pgvector is verified on a replica, and the failover RTO/RPO targets (≤ 60 s / zero
audit loss) that W4-T3 asserts.

**Out** — implementation (W1-T1/T2); the failover *drill* (W4-T3); certified-scale
sizing (named-deferred, §0); cloud-managed PG (self-hosted only, D-series).

## Requirements (grounded in PRODUCTION.md §3.2, §8, §11 G-REL)

1. **Sync audit path:** the `audit_log` commit path uses quorum/synchronous commit
   so a promoted replica has every committed audit row — the design rationale for
   "zero committed-audit-entry loss" (G-REL §316). State the latency trade-off.
2. **Automatic failover:** primary kill → operator-driven promotion; write service
   restored ≤ 60 s. No manual step.
3. **PgBouncer:** connection pooling mode (transaction-mode default) and the
   connection-budget rationale that W4-T6 asserts (G-SCA §330).
4. **pgvector on replica:** the extension is available + queryable on replicas
   (read scale-out must not break embedding reads).
5. **Operator decision recorded:** CloudNativePG primary; Patroni named as the
   no-operator fallback (PRODUCTION.md §3.2). No silent default.

## Contracts / artifacts

- `docs/adr/0042-postgres-ha-cloudnativepg-sync-audit.md` (Proposed), ADR index updated.

## Test & gate plan

- D16 docs gates only (this is an ADR). No code.
- The ADR names the exact assertions W1-T1 (render/policy), W1-T2 (sync-commit
  under real PG), and W4-T3 (failover drill) must satisfy — so the build tasks have
  a testable contract.

## Exit criteria

- [ ] ADR-0042 written: operator, replica count, PgBouncer mode, **sync-audit path**, failover RTO/RPO, pgvector-on-replica.
- [ ] Patroni fallback + certified-scale-deferred both named (no silent drift).
- [ ] ADR index updated; one atomic commit.

## Workflow

`wf-implementer` drafts → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** (audit/data tier) → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Sync replication latency** on the audit path under-specified → W4-T3 can't hit
  the RTO. The ADR must state the quorum shape and the write-latency budget.
- **Over-scoping sync to all writes** — kills throughput. Scope sync to audit only;
  justify.
