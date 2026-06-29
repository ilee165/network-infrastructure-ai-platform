# W1-T1 — CloudNativePG (1 primary + 2 replicas) + PgBouncer + sync-audit quorum + pgvector-on-replica

| | |
|---|---|
| **Wave** | P3 W1 — Data-tier HA |
| **Owner** | `wf-infra` (strong — data tier) |
| **Review tier** | **strong** spec + quality (data/audit tier) |
| **Depends on** | **W0-T1** (ADR-0042) |
| **ADRs** | ADR-0042 (the contract), ADR-0004 (Postgres SoR), ADR-0029 (Helm GA), ADR-0030 (backup/DR), ADR-0038 (audit hash-chain) |
| **PRODUCTION.md** | §3.1/§3.2, §8, §11 G-REL |
| **Status** | Proposed |

## Objective

Implement ADR-0042: a **CloudNativePG** cluster (1 primary + 2 streaming replicas)
with **PgBouncer** pooling and **synchronous (quorum) commit on the `audit_log`
write path**, pgvector available on replicas, rendered into the Helm chart with
hardened, secure-by-default values. This is the HA tier the W4-T3 failover drill
acts on.

## Scope

**In** — CloudNativePG `Cluster` manifest (3 instances, storage, resources,
PriorityClass so PG outranks batch workers); `synchronous_standby_names` / quorum
config scoped to the audit write path per ADR-0042; PgBouncer pooler (transaction
mode); pgvector extension enabled + verified queryable on a replica; chart values +
`lookup` reuse-or-generate for the superuser/replication secret (**L4**); backup
integration consistent with ADR-0030.

**Out** — app-side connection wiring (W1-T2); the failover drill (W4-T3); Patroni
(ADR-0042 fallback, not built); certified-scale sizing (named-deferred).

## Requirements (grounded in ADR-0042, PRODUCTION.md §3.2/§8)

1. **Sync audit path** — quorum commit configured so a committed audit row is on a
   replica before ack; W1-T2 + W4-T3 assert the zero-loss consequence.
2. **PgBouncer** — transaction-mode pooling; connection budget per ADR-0042 (W4-T6
   asserts no exhaustion).
3. **pgvector on replica** — extension present + an embedding query succeeds on a
   replica (read scale-out doesn't break RAG reads).
4. **Secure-by-default + L4** — non-root, resource limits; cert/superuser secret via
   `lookup` reuse-or-generate (empty in CI, reused on upgrade, never regenerated).
5. **Policy-as-test** — kubeconform/conftest/kube-linter green; render-twice stable.

## Contracts / artifacts

- CloudNativePG `Cluster` + PgBouncer pooler manifests; chart values; a render-twice
  idempotency check; a pgvector-on-replica smoke assertion.

## Test & gate plan

- Infra gates: `helm lint`, `helm template | kubeconform -strict`, kube-linter,
  conftest — all green.
- **L4 render-twice** stable (no secret regen on simulated upgrade).
- pgvector-on-replica smoke (in W4-T1 kind bring-up or a rendered emulation if kind
  absent locally — say which; L1).
- The sync-quorum config is asserted for real in W1-T2/W4-T3 (real PG).

## Exit criteria

- [ ] CloudNativePG 1+2 + PgBouncer render and pass all infra policy gates.
- [ ] Sync-quorum config present on the audit write path per ADR-0042.
- [ ] pgvector verified queryable on a replica.
- [ ] L4 render-twice stable; secure-by-default values; one atomic commit.

## Workflow

`wf-infra` (strong) → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Sync commit on all writes** (not just audit) → throughput collapse. Scope to the
  audit path per ADR-0042.
- **L4 secret regen** on upgrade → severs every DB connection. `lookup` mandatory.
- **pgvector missing on replicas** → RAG reads fail when routed to a replica.
