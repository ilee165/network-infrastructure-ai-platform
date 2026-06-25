# W0-T6 — ADR-0039 mTLS Between Containers (cert-manager / SPIFFE)

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** spec + **strong** quality (cert material / transport trust) |
| **Depends on** | — (independent of T1–T5) |
| **ADRs** | ADR-0013 / ADR-0029 (K8s/Helm GA chart + hardening), ADR-0004 (Postgres system-of-record), ADR-0008 (Celery workers), ADR-0002 (SQLAlchemy connection) |
| **PRODUCTION.md** | §5 (in-cluster transport encryption), §9, §11 G-SEC |
| **Status** | Proposed |

## Objective

Decision record for **mutual-TLS on the database links**: `api↔postgres` and
`worker↔postgres` authenticate both ends and refuse plaintext. Decides the cert
authority, issuance/rotation mechanism, Postgres TLS mode, and the kind-cluster
assertion. Design gate; build is **W4-T4** (validated on the W4-T3 kind cluster).

## Scope

**In**
- **Issuer decision:** **cert-manager** (in-cluster CA Issuer) vs **SPIFFE/SPIRE**
  — pick one, with rationale (operational weight on a self-hosted stack vs
  identity richness). Recommend cert-manager for the P2 scope.
- **Links in scope:** `api↔postgres` and `worker↔postgres` (the two named in
  §0/§1). `api↔neo4j`, `↔redis`, ingress TLS — explicitly **deferred/named** (not
  silently dropped).
- **Postgres side:** server cert + client-cert (`verify-full` class) so the DB
  authenticates clients and clients verify the server; **plaintext connections
  refused** at the server.
- **Client side:** SQLAlchemy / psycopg connection configured for mTLS
  (sslmode/sslcert/sslkey/sslrootcert) for both api and worker.
- **Cert lifecycle:** issuance + **rotation** (cert-manager renewal) + trust
  distribution; Helm renders cert material via **`lookup` reuse-or-generate**
  (P1-W4-LESSONS **L4**: empty in CI, reused on `helm upgrade` — regen breaks auth).
- **kind assertion** (W4): handshake succeeds with valid certs; a plaintext /
  wrong-CA client is **refused** — the deterministic enforcement bite.

**Out**
- Implementation (cert-manager manifests, chart wiring, connection config, kind
  assertion) → **W4-T4** (depends on the **W4-T3** kind harness).
- Service-mesh adoption (Istio/Linkerd) — out; the decision is point-to-point mTLS.
- HA/scale-out networking → **P3-Platform** (§0).

## Requirements (grounded in ADR-0029, ADR-0004, P1-W4-LESSONS L4)

1. **Mutual auth, plaintext refused** (secure-by-default): both ends present
   certs; the Postgres server rejects non-TLS / untrusted-CA connections.
2. **Automated rotation** (ADR-0029 hardening): certs renew without manual
   re-issue; rotation does not require a credential the operator must hand-rotate.
3. **Idempotent dev secrets** (L4): chart-rendered cert material uses `lookup`
   reuse-or-generate so a `helm upgrade` does not regenerate and break auth.
4. **kind-validatable** (P2-SECURITY-PLAN.md §5): the handshake + plaintext-refusal
   is asserted on the ephemeral in-CI cluster (W4-T3) — the "kind for cheap" bite.
5. **No app-code secret exposure**: cert keys are K8s secrets / mounted files,
   never baked into images or logged.

## Contracts / artifacts

- cert-manager `Issuer` + `Certificate` resources (or SPIFFE equivalent).
- Postgres TLS config (server + required client verification).
- api / worker connection config (mTLS parameters) in the chart values.

## Validation / Test & gate plan (ADR review — strong)

- Repo ADR template; the issuer decision is justified, not asserted.
- **Consistency with ADR-0029** chart structure; the `lookup` idempotency pattern
  is referenced (L4) so W4-T4 inherits it.
- Manifest-policy gates (kubeconform / conftest / kube-linter) named for W4-T4.
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0039 written; status **Proposed**.
- [ ] Issuer (cert-manager vs SPIFFE) decided with rationale.
- [ ] Links in scope (api↔pg, worker↔pg) fixed; others named-deferred.
- [ ] Postgres `verify-full`-class config + plaintext-refusal decided.
- [ ] Rotation + L4 `lookup` idempotency recorded; kind assertion specified.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` writes ADR → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **Rotation that breaks live auth** (the L4 trap, now at the transport layer): a
  regenerated cert on `helm upgrade` severs every DB connection. The `lookup`
  reuse-or-generate pattern must be in the ADR, not discovered in W4.
- **Scope creep to a service mesh**: tempting but heavy for a self-hosted stack;
  the ADR fixes point-to-point mTLS and names mesh as out.
