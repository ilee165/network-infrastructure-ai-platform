# W4-T4 — mTLS api↔postgres / worker↔postgres (handshake asserted on kind, plaintext refused)

| | |
|---|---|
| **Wave** | P2 W4 — Security hardening + kind validation (network stream) |
| **Owner** | `wf-infra` (strong — cert material / transport trust) |
| **Review tier** | **strong** spec + **strong** quality (secret-surface: cert keys / transport trust) |
| **Depends on** | **W4-T3** (kind harness) + **W0-T6** (ADR-0039) |
| **ADRs** | ADR-0039 (the contract this builds), ADR-0029 (Helm GA chart + hardening), ADR-0004 (Postgres system-of-record), ADR-0008 (Celery workers), ADR-0002 (SQLAlchemy connection) |
| **PRODUCTION.md** | §5 (in-cluster transport encryption), §9, §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement exactly what **ADR-0039** ratified: **mutual TLS** on the two database
links — `api↔postgres` and `worker↔postgres` — both ends authenticate, **plaintext
is refused** at the Postgres server, and the handshake (valid certs succeed /
plaintext + wrong-CA refused) is **asserted on the W4-T3 kind cluster**. Cert
issuance/rotation uses the issuer ADR-0039 chose (cert-manager recommended).

## Scope

**In** (cert-manager resources + chart wiring + Postgres TLS config + api/worker
connection config + a T4 assertion plugged into the W4-T3 runner)
- **Issuer + certs** (per ADR-0039): cert-manager `Issuer` + `Certificate`
  resources (or the SPIFFE equivalent ADR-0039 fixed) for the postgres server +
  api/worker clients.
- **Postgres side**: server cert + required client-cert verification (`verify-full`
  class) so the DB authenticates clients **and** clients verify the server;
  **plaintext connections refused** at the server.
- **Client side**: SQLAlchemy / psycopg connection configured for mTLS
  (sslmode/sslcert/sslkey/sslrootcert) for both api and worker, via chart values.
- **Cert lifecycle**: issuance + **automated rotation** (cert-manager renewal) +
  trust distribution; chart renders cert material via **`lookup` reuse-or-generate**
  (P1-W4-LESSONS **L4**) — empty in CI, reused on `helm upgrade`, never regenerated
  in-place (a regen severs every DB connection).
- **kind assertion** (T4's plug into the W4-T3 runner): a valid-cert client
  handshakes successfully; a **plaintext / wrong-CA client is refused** — the
  deterministic enforcement bite.

**Out**
- ADR / issuer decision → **W0-T6** (this implements it).
- kind harness itself → **W4-T3**.
- `api↔neo4j` / `↔redis` / ingress TLS, service-mesh adoption → named-deferred per
  ADR-0039 (not silently dropped).
- HA/scale-out networking → **P3-Platform** (§0).

## Requirements (grounded in ADR-0039, ADR-0029, P1-W4-LESSONS L4)

1. **Mutual auth, plaintext refused** (secure-by-default): both ends present certs;
   the Postgres server **rejects** non-TLS / untrusted-CA connections — asserted on kind.
2. **Automated rotation** (ADR-0029): certs renew without manual re-issue; rotation
   needs no operator-hand-rotated credential.
3. **Idempotent dev secrets** (**L4**): chart-rendered cert material uses `lookup`
   reuse-or-generate so a `helm upgrade` does not regenerate certs and break auth —
   a render-twice test proves the material is stable.
4. **No app-code secret exposure**: cert keys are K8s secrets / mounted files, never
   baked into images or logged.
5. **kind-validated** (§5): the handshake + plaintext-refusal runs on the W4-T3
   cluster — the live bite, not a unit mock.

## Contracts / artifacts

- cert-manager `Issuer` + `Certificate` resources (or SPIFFE equivalent).
- Postgres TLS config (server cert + required client verification).
- api / worker mTLS connection parameters in chart values.
- A T4 assertion (valid handshake succeeds / plaintext refused) in the W4-T3 runner.

## Test & gate plan (infra gates + targeted unit)

- **kind handshake assertion** (the exit bite): valid certs → connection succeeds;
  plaintext + wrong-CA → **refused**; run via the W4-T3 harness.
- **L4 idempotency**: render the chart twice (`lookup` path) → identical cert
  material; no regen on simulated `helm upgrade`.
- Manifest-policy gates green: kubeconform / conftest / kube-linter; helm lint clean.
- mypy/ruff on any client-config Python touched; fastapi route-introspection green.
- **Local run first** (L1, inherited via W4-T3) before the assertion is gating.

## Exit criteria

- [ ] cert-manager (or ADR-0039 issuer) issues server + client certs for both links.
- [ ] Postgres requires client-cert + verifies server; **plaintext refused**.
- [ ] api + worker connect over mTLS via chart values.
- [ ] Rotation automated; **L4 `lookup` idempotency** holds (render-twice stable).
- [ ] kind handshake assertion bites (valid succeeds / plaintext + wrong-CA refused).
- [ ] Helm manifest gates green; cert keys never logged/imaged; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **Rotation that breaks live auth** (the L4 trap at the transport layer): a
  regenerated cert on `helm upgrade` severs every DB connection. The `lookup`
  reuse-or-generate pattern is mandatory; the render-twice test is the guard.
- **kind assertion that does not actually refuse plaintext**: if the harness
  connects over plaintext and the test still "passes," the control is nominal —
  the assertion must prove the *refusal*, not just a successful TLS path.
- **Scope creep to a service mesh**: heavy for a self-hosted stack; ADR-0039 fixed
  point-to-point mTLS — stay there.
