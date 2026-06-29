# ADR-0039: mTLS Between Containers (cert-manager)

**Status:** Accepted | **Date:** 2026-06-25 (Accepted 2026-06-29) | **Milestone:** P2 W0 (Accepted P2 W5)

## Context

`PRODUCTION.md` §5 / §9 require in-cluster transport encryption with mutual
authentication on the database links. Today api↔postgres and worker↔postgres traffic
relies on network isolation, not mutual TLS. This ADR is the design gate; the build
is **W4-T4**, validated on the **W4-T3** ephemeral in-CI kind cluster
(`P2-SECURITY-PLAN.md` §3). Cert material is a secret surface (strong review).

Bounded by ADR-0013 / ADR-0029 (K8s/Helm GA chart + hardening), ADR-0004 (Postgres
system-of-record), ADR-0008 (Celery workers), ADR-0002 (SQLAlchemy/psycopg
connection).

## Decision

**Mutual TLS on api↔postgres and worker↔postgres, issued and auto-rotated by
cert-manager (in-cluster CA). Postgres requires and verifies client certificates and
refuses plaintext; clients verify the server (`verify-full` class). Chart-rendered
cert material uses `lookup` reuse-or-generate so a `helm upgrade` never regenerates
and severs auth. The handshake + plaintext-refusal is asserted on the W4-T3 kind
cluster.**

### 1. Issuer — cert-manager (not SPIFFE/SPIRE)

cert-manager with an in-cluster CA `Issuer` issues a server certificate for Postgres
and client certificates for api and worker. **Rationale:** cert-manager is the
lighter operational fit for a self-hosted single-cluster stack; SPIFFE/SPIRE's
workload-identity richness is unneeded for two point-to-point DB links and adds a
control plane to run. SPIFFE is named, not silently dropped — revisit if a
service-mesh-scale identity need appears (P3-Platform).

### 2. Links in scope — api↔pg, worker↔pg

The two links named in `PRODUCTION.md` §5/§0. **Named-deferred (not dropped):**
`api↔neo4j`, `↔redis`, and ingress TLS — separate follow-ups; this ADR is
point-to-point DB mTLS only.

### 3. Postgres side — required client cert, plaintext refused

Postgres is configured with a server cert and `hostssl` + `clientcert=verify-full`
(class) `pg_hba` rules so it **authenticates the client cert** and **rejects
non-TLS / untrusted-CA connections** at the server. There is no plaintext fallback
listener for these links.

### 4. Client side — SQLAlchemy/psycopg mTLS

api and worker connect with `sslmode=verify-full` and `sslcert` / `sslkey` /
`sslrootcert` pointing at mounted cert material (chart values, ADR-0002). Both verify
the server identity and present their client cert.

### 5. Cert lifecycle — automated rotation, idempotent dev secrets

cert-manager renews certs automatically before expiry (no operator hand-rotation).
Chart-rendered cert material (dev/CI path) uses the **`lookup` reuse-or-generate**
pattern (P1-W4-LESSONS **L4**): empty in CI, reused on `helm upgrade` — a regen on
upgrade would sever every DB connection. Cert keys are K8s Secrets / mounted files,
never baked into images or logged.

### 6. kind assertion (W4-T4 on the W4-T3 cluster)

On the ephemeral cluster: a valid-cert client handshakes successfully; a plaintext
or wrong-CA client is **refused**. This is the deterministic enforcement bite —
proving the *refusal*, not merely a working TLS path.

## Consequences

**Positive**
- Mutual auth + plaintext refusal on the DB links closes in-cluster
  sniff/impersonate paths; secure-by-default transport.
- cert-manager auto-rotation removes manual cert ops; the `lookup` pattern keeps
  `helm upgrade` safe.
- kind-validated handshake/refusal gives a cheap, deterministic G-SEC bite without
  HA/scale hardware.

**Negative**
- cert-manager is a new chart dependency to operate (CRDs, CA bootstrap).
- A regenerated cert on upgrade would break live auth — the L4 `lookup` pattern is
  mandatory and render-twice tested (W4-T4).
- neo4j/redis/ingress remain non-mTLS in P2 (named-deferred).

## Alternatives considered

1. **SPIFFE/SPIRE workload identity.** Rejected for P2 scope (§1): heavier control
   plane than two DB links justify; cert-manager is the right weight. Revisit at
   service-mesh scale (P3-Platform).
2. **Service mesh (Istio/Linkerd) mTLS.** Rejected: a mesh is disproportionate for a
   self-hosted stack; the decision is point-to-point mTLS.
3. **TLS without client certs (server-auth only).** Rejected: §5 requires *mutual*
   auth so the DB authenticates its clients, not just encryption in flight.
4. **Network-policy isolation alone (no mTLS).** Rejected as insufficient for §5
   transport encryption; segmentation (ADR-0041) is complementary, not a substitute.
