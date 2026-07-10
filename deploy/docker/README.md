# Docker Compose deployment (MVP / dev)

Compose is the deployment target for the MVP and small on-prem installs
(ADR-0013 / D13). One `docker compose up` brings up the full, air-gap-capable
platform. Production deployments use the Kubernetes Helm chart
([deploy/kubernetes/](../kubernetes/README.md), production roadmap).

| Service | Image | Port (host) | Purpose |
|---|---|---|---|
| `api` | `netops-backend` (built) | `8000` | FastAPI REST + WebSocket API |
| `worker` | `netops-backend` (same image) | — | Celery queues: `discovery`, `config`, `packet`, `docs` |
| `frontend` | `netops-frontend` (built) | `8080` | SPA + `/api/` reverse proxy |
| `postgres` | `pgvector/pgvector:pg16` | — | System of record + embeddings |
| `neo4j` | `neo4j:5-community` | — | Topology / knowledge graph |
| `redis` | `redis:7-alpine` | — | Celery broker, cache |
| `ollama` | `ollama/ollama` (profile `local-llm`) | — | Local LLM inference |

Data stores are intentionally **not** published to the host (secure by
default); commented `ports:` stanzas in `docker-compose.yml` exist for local
debugging.

## Quickstart

Prerequisites: Docker Engine with Compose v2. Run everything from the
**repository root**.

```bash
cp .env.example .env
# Edit .env first — see "First-run notes" below (secret key, neo4j password).

docker compose -f deploy/docker/docker-compose.yml up -d --build
```

With a local LLM (Ollama):

```bash
docker compose -f deploy/docker/docker-compose.yml --profile local-llm up -d --build
```

Recommended invocation — add `--env-file .env` so the `NETOPS_NEO4J_*` values
from your root `.env` reach the `neo4j` container (see note 2). Use `--build`
on first run and after frontend/backend changes (or after `docker image prune`
/ Docker Desktop reset): `netops-backend:dev`, `netops-backend-packet:dev`, and
`netops-frontend:dev` are **local-only** image tags. Compose will **build** them
(`pull_policy: build`); they are not published to Docker Hub. Without a local
image, a registry pull fails with `pull access denied for netops-frontend`
(same for `netops-backend`).

```bash
docker compose --env-file .env -f deploy/docker/docker-compose.yml up -d --build
docker compose --env-file .env -f deploy/docker/docker-compose.yml --profile local-llm up -d --build
```

The core stack (`api`, `worker`, `frontend`, `postgres`, `redis`, `neo4j`) comes
up with the commands above. The **`packet-analysis`** pcap-parser worker is now
**functional and ON by default** (ADR-0049 executor-split): it comes up with the
default `up`, no extra profile needed. ADR-0049 resolved the old contradiction —
the ADR-0031 §3 no-socket seccomp sandbox was incompatible with a broker-connected
Celery worker (glibc's DNS resolver needs a socket) — by **drawing the sandbox
boundary around the untrusted work, not the Celery machinery**: this container is
the broker-connected *dispatcher* (running the deny-by-default DISPATCHER seccomp
profile, client sockets allowed), and each analysis job spawns a short-lived
`python -m app.engines.packet.executor` child that **re-confines with the strict
no-socket profile** before it opens a single pcap byte, then dies. So tshark's
CVE-bearing dissectors parse attacker-controlled bytes with zero sockets, zero
capabilities, a read-only rootfs, and no egress — while the dispatcher keeps its
Redis connection. The re-enable is gated on the Linux CI bite-proof (job
`packet-analysis-bite-proof`, three legs: confined GREEN parse, RED self-test
denial with a negative control, and process-group TIMEOUT kill) being green at
HEAD. To keep it opt-out on a constrained host, add `--scale packet-analysis=0`.

Then verify (core stack):

```bash
curl http://localhost:8000/api/v1/health/live    # {"status":"ok"}
curl http://localhost:8000/api/v1/health/ready   # per-dependency postgres/neo4j/redis status
```

- Frontend: <http://localhost:8080>
- API swagger UI: <http://localhost:8000/docs>

## First-run notes

### 1. Generate a secret key

`NETOPS_SECRET_KEY` signs JWT access tokens. The shipped dev value is refused
when `NETOPS_ENV=prod`. Generate a strong key and put it in `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 2. Neo4j password

The `neo4j:5-community` image **rejects** the default password `neo4j` (and
any password shorter than 8 characters). Set `NETOPS_NEO4J_PASSWORD` in `.env`
to a strong value before the first start.

How the value reaches the containers:

- `api`/`worker` read it from `.env` via the compose `env_file:` key.
- The `neo4j` container gets it through compose **variable interpolation**
  (`NEO4J_AUTH: ${NETOPS_NEO4J_USER:-neo4j}/${NETOPS_NEO4J_PASSWORD:-neo4j}`).
  With `-f deploy/docker/docker-compose.yml`, compose interpolates from
  `deploy/docker/.env` (the compose project directory) or the shell — **not**
  the root `.env`. Either pass `--env-file .env` (recommended invocation
  above) or export `NETOPS_NEO4J_USER`/`NETOPS_NEO4J_PASSWORD` in your shell.

The password is persisted in the `neo4jdata` volume on first start; to change
it later, change it in Neo4j (or recreate the volume) **and** update `.env`.

### 3. Database migrations + admin seed

Alembic owns the schema (ADR-0004) and the backend image ships the migration
environment. Apply migrations after starting the stack (revisions `0001`→`0010`
ship today — identity/inventory/evidence/audit, topology, agent sessions, auth,
config+docs, change-requests, OIDC):

```bash
# Preferred (one-shot migrate service — same image as api):
docker compose --env-file .env -f deploy/docker/docker-compose.yml run --rm migrate

# Equivalent if api is already up:
docker compose --env-file .env -f deploy/docker/docker-compose.yml exec api alembic upgrade head
```

Skipping this step leaves an empty database: `POST /auth/login` returns
**503** (`urn:netops:error:schema-not-ready`) with an `alembic upgrade head`
hint, and `GET /health/ready` reports the `schema` dependency as error.

The `0001` baseline also **seeds the bootstrap `admin` user** from
`NETOPS_ADMIN_PASSWORD`. If that variable is unset the migration seeds the
insecure default `admin`/`admin` and logs a loud warning — set a strong
`NETOPS_ADMIN_PASSWORD` in `.env` **before** the first `upgrade head`, and rotate
the account after first login. Verify the stack end-to-end once migrated:

```bash
# 1. obtain a token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your-admin-pw>"}' | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# 2. call a protected endpoint with the token (expects the admin user JSON)
curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer $TOKEN"
```

### 4. LLM availability

The platform is local-first: `NETOPS_LLM_PROFILE=local` targets the `ollama`
service, which only runs under `--profile local-llm`. After starting it, pull
a model once (persisted in the `ollama-models` volume):

```bash
docker compose -f deploy/docker/docker-compose.yml --profile local-llm exec ollama ollama pull llama3.1
```

Without the profile there is **no working LLM** until you opt into an external
provider via `NETOPS_LLM_PROFILE` (ADR-0009); no traffic leaves the deployment
unless you do.

## TLS at the edge (optional overlay)

By default the base stack serves plaintext HTTP on `:8000` (api) and `:8080`
(frontend) for local development. To terminate TLS at the compose edge — so no
plaintext HTTP crosses the host boundary (ADR-0013 §3, M5 hardening) — apply the
`docker-compose.tls.yml` **overlay**. It adds an `edge` reverse proxy
(`nginx:1.27-alpine`) in front of `frontend` + `api` and never alters the base
file, so the plain `up -d` bring-up above is unchanged.

```bash
# 1. one-time: generate a DEV self-signed cert into deploy/docker/tls/certs/
bash deploy/docker/tls/generate-dev-cert.sh        # optional: pass a CN, default "localhost"

# 2. bring the stack up with TLS terminated at the edge (base FIRST, overlay SECOND):
docker compose --env-file .env \
  -f deploy/docker/docker-compose.yml \
  -f deploy/docker/docker-compose.tls.yml up -d
```

Then browse <https://localhost> (HTTP on `:80` 301-redirects to HTTPS). The dev
cert is **self-signed**, so the browser shows a trust warning on first visit —
expected for dev. The generated `certs/` directory is git-ignored; the key and
cert bytes are never committed.

- **Dev:** the self-signed cert above. No identity assurance — accept the
  browser warning, or import the cert into your local trust store.
- **Production:** do **not** use this edge or the self-signed cert. Production
  terminates TLS at the Kubernetes `Ingress` with a CA-issued certificate
  (ADR-0013 §4, [deploy/kubernetes/](../kubernetes/README.md)).

For a hardened compose deployment, drop the `:8000`/`:8080` host port mappings
from the base file so the platform is reachable only through the TLS edge.

### packet-analysis seccomp profile path

The `packet-analysis` service applies the deny-by-default **dispatcher** Localhost
seccomp profile (ADR-0049 blocker 5), byte-for-byte the same JSON the Helm chart
references. This CONTAINER profile is the strict child profile PLUS the client
sockets + `seccomp()`/`prctl()` a broker-connected Celery worker + self-confining
parent need; each analysis job then spawns a `python -m app.engines.packet.executor`
child that re-confines with the strict no-socket profile before parsing the pcap
(ADR-0049 executor-split). Docker **Compose** resolves a `seccomp=` **relative**
path against the **project directory** — the directory of the first `-f` compose
file (`deploy/docker/` by default), **not** the client CWD (that CWD-relative rule
applies to `docker run --security-opt`, a different tool). So the default is
compose-file-relative and resolves correctly from **any** working directory:
`NETOPS_SECCOMP_PROFILE=./seccomp/packet-analysis-dispatcher-seccomp.json`. Do
**not** add a `deploy/docker/` prefix — Compose already anchors to that directory,
so a prefixed value doubles the path (`deploy/docker/deploy/docker/seccomp/...`)
and fails with "opening seccomp profile ... failed". Do **not** point it at the
strict `packet-analysis-seccomp.json` — that no-socket profile is the CHILD profile
and would block the worker's broker connection at the container level. For an
air-gapped mirror, override it with an **absolute** path:

```bash
NETOPS_SECCOMP_PROFILE=/opt/netops/seccomp/packet-analysis-dispatcher-seccomp.json \
  docker compose -f deploy/docker/docker-compose.yml up -d
```

## Operations

```bash
docker compose -f deploy/docker/docker-compose.yml ps                 # status + health
docker compose -f deploy/docker/docker-compose.yml logs -f api        # follow a service log
docker compose -f deploy/docker/docker-compose.yml down               # stop (volumes preserved)
docker compose -f deploy/docker/docker-compose.yml down -v            # stop AND DELETE ALL DATA
```

Both backend containers run the same `netops-backend` image (ADR-0013): `api`
uses the image's default `uvicorn` command; `worker` overrides it with
`celery -A app.workers.celery_app worker -Q discovery,config,packet,docs,system`.
Rebuild after backend or frontend changes with `up -d --build`.

## Backup tier (pgBackRest → MinIO, W5-T1)

Single-node parity for the Helm backup CronJobs (ADR-0030 §1/§4): weekly-full +
daily-incr pgBackRest backups to a MinIO repo, repo-encrypted (aes-256-cbc), each
run gated by `pgbackrest verify`. Scheduling is host-cron-equivalent via `ofelia`
(a container cron triggering `job-exec` against the long-lived `pgbackrest`
container). It is an OPT-IN compose profile, but the backup TIER is on-by-default
in the chart (secure/resilient-by-default; the profile only keeps the dev stack
light).

```bash
# Set the repo secrets in .env first (PGBACKREST_REPO1_CIPHER_PASS, MINIO_ROOT_*).
docker compose \
  -f deploy/docker/docker-compose.yml \
  -f deploy/docker/docker-compose.backup.yml \
  --profile backup --env-file .env up -d

# Run a full backup + verify on demand (the same script ofelia schedules):
docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.backup.yml \
  exec pgbackrest sh -c 'set -euo pipefail; pgbackrest --stanza=netops stanza-create || true; \
    pgbackrest --stanza=netops --type=full backup; pgbackrest --stanza=netops verify'
```

Secrets (the aes-256-cbc repo passphrase + the MinIO key/secret) come from the
root `.env` as `PGBACKREST_REPO1_*` / `MINIO_ROOT_*` env — NEVER inlined in
`pgbackrest/pgbackrest.conf` or the compose file (the repo and its key are never
co-located, ADR-0011 §4). The restore / PITR drill is W5-T2. RPO ≤ 5 min is a
PROPOSED target (ADR-0030 §6), re-based in the W5-T5 evidence doc.

> **⚠️ This `backup` profile is LOCAL-DEV-ONLY — do not run it in production.**
> Scheduling uses `ofelia`, which mounts the host Docker socket
> (`/var/run/docker.sock`). The `:ro` flag on that mount marks only the socket
> *file* read-only; it is **not** a Docker-API write barrier — any process that can
> reach the socket can still issue write calls (create/exec/stop containers), which
> is effectively host root. That is acceptable for a single-developer stack but not
> for a shared or production host. The production-grade equivalent is the Helm
> `netops` chart's pgBackRest CronJobs (`deploy/kubernetes`), which schedule via the
> Kubernetes API with a scoped ServiceAccount and never mount the Docker socket. A
> hardened compose variant (fronting `ofelia` with a least-privilege
> `docker-socket-proxy`) is intentionally out of scope for this dev convenience
> profile.
