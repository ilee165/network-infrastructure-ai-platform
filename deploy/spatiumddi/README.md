# SpatiumDDI lab — runbook for the opt-in live DDI golden-path test (T6)

Stands up a **self-hosted SpatiumDDI** so the env-guarded live test drives the DDI
golden path against a *real* REST appliance:

> [`backend/tests/agents/eval/test_spatiumddi_live_golden_path.py`](../../backend/tests/agents/eval/test_spatiumddi_live_golden_path.py)

It is the live twin of the deterministic, mock-backed CI test
(`test_spatiumddi_ddi_golden_path.py`): seed a (soon-stale) DNS record → the
genuine plugin mutator returns a vendor-neutral `ChangeRequestDraft` (no inline
write) → the gate persists a `ddi_record` ChangeRequest → a **different** user
approves (four-eyes) → the **Automation Agent** executes via the real
`SpatiumClient` → re-query verifies → the audit chain links
`reasoning_trace → CR → audit_log`. It also proves the SpatiumDDI-distinctive
**delete → RESTORE** inverse (soft-delete; ADR-0024 §3).

> **This is a manual / lab step.** Nothing here runs in CI — the test is
> *collected but skipped* unless the `SPATIUMDDI_*` env vars below are set, and CI
> never sets them. You do **not** need this stack for the backend gates.

**Verified end-to-end on 2026-06-20** against SpatiumDDI release `2026.06.19-1`
(both test cases pass). Authority:
[`docs/adr/0024-spatiumddi-client-and-endpoint-capability-mapping.md`](../../docs/adr/0024-spatiumddi-client-and-endpoint-capability-mapping.md)
(§6.1 records the live findings).

---

## 1. Bring the SpatiumDDI stack up

SpatiumDDI is published as `ghcr.io/spatiumddi/spatiumddi-api` (CalVer tags). The
control plane serves the REST API on **`http://127.0.0.1:8000`** (global prefix
`/api/v1`; OpenAPI doc at `/api/openapi.json`; health at `/health/live`).

### Option A — the mirror compose in this directory (quickest)

```bash
cd deploy/spatiumddi
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD and SECRET_KEY (openssl rand -hex 32);
# optionally pin SPATIUMDDI_VERSION to a CalVer tag instead of latest.

docker compose run --rm migrate      # alembic upgrade head
docker compose up -d                 # postgres + redis + api + worker + beat
# wait for health: curl -s http://127.0.0.1:8000/health/live   # -> 200
```

This compose is a faithful, pinned mirror of upstream's, trimmed to the services
the test needs. **Upstream is canonical** — if it has drifted, use Option B.

### Option B — upstream compose (canonical source of truth)

```bash
git clone https://github.com/spatiumddi/spatiumddi.git
cd spatiumddi
cp .env.example .env                 # set POSTGRES_PASSWORD, SECRET_KEY, DNS_AGENT_KEY
docker compose run --rm migrate
docker compose up -d
```

Default login is **`admin` / `admin`** (you are forced to change the password on
first use). The UI (if the `frontend` service is enabled) is on `:8077`; the live
test only needs the API on `:8000`.

---

## 2. Bootstrap a test group + zone, and mint a token

A fresh install does **not** auto-seed a group/zone for an external integration —
create them (ADR-0024 §6.1). All of this is plain REST against `/api/v1`:

```bash
BASE=http://127.0.0.1:8000

# a) Log in as admin/admin, rotate the forced password, re-login for a clean token.
ADMIN_JWT=$(curl -s -X POST $BASE/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .access_token)
curl -s -X POST $BASE/api/v1/auth/change-password -H "Authorization: Bearer $ADMIN_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"admin","new_password":"<a-strong-lab-password>"}'
ADMIN_JWT=$(curl -s -X POST $BASE/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<a-strong-lab-password>"}' | jq -r .access_token)

# b) Create a DNS server-group and a zone (note the non-secret UUIDs).
GROUP_ID=$(curl -s -X POST $BASE/api/v1/dns/groups -H "Authorization: Bearer $ADMIN_JWT" \
  -H 'Content-Type: application/json' -d '{"name":"golden-lab"}' | jq -r .id)
ZONE_ID=$(curl -s -X POST $BASE/api/v1/dns/groups/$GROUP_ID/zones -H "Authorization: Bearer $ADMIN_JWT" \
  -H 'Content-Type: application/json' -d '{"name":"golden.lab","zone_type":"forward"}' | jq -r .id)
```

> `view_id` is **optional** on zone- and record-create (ADR-0024 §6.1) — omit it
> for the single-view golden path.

---

## 3. Mint a least-privilege API token

SpatiumDDI mints bearer tokens via `POST /api/v1/api-tokens` and returns the raw
token **exactly once** in the response field **`token`** (the `prefix` field is
only a short display id — do **not** use it). Accepted `scopes` are exactly:

```
read   dns:write   dhcp:write   ipam:write   agent      (  "*" is REJECTED  )
```

The golden path needs `read` + `dns:write`:

```bash
SDDI_TOKEN=$(curl -s -X POST $BASE/api/v1/api-tokens -H "Authorization: Bearer $ADMIN_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"name":"netops-golden-path-lab","expires_in_days":1,"scopes":["read","dns:write"]}' \
  | jq -r .token)            # the full sddi_... secret; shown ONCE
```

> **The token is a SECRET.** Never commit it, never log it. Prefer a short
> `expires_in_days`. Our `SpatiumClient` holds it in a non-`repr` field and pins it
> only onto the `Authorization` header (ADR-0024 §2 / D11).

### ⚠️ Restore needs an ADMIN session, not an API token (verified finding)

`POST /api/v1/admin/trash/{type}/{row_id}/restore` returns **401 "Token scope
insufficient"** for **every** API-token scope (verified up to an all-scopes
token); only an admin **user session JWT** can restore (ADR-0024 §6.1). The
record CRUD path works with the `read`+`dns:write` token above, but the
**delete → RESTORE** half of the test needs an admin-privileged bearer. To run the
*full* test, set `SPATIUMDDI_TOKEN` to the **`$ADMIN_JWT`** session token instead
of the scoped `$SDDI_TOKEN`. (Production note: the change-executor that applies a
soft-delete rollback must therefore hold an admin/session credential.)

---

## 4. Export the env the live test reads, then run it

| Variable | Required | Meaning |
|---|---|---|
| `SPATIUMDDI_BASE_URL` | yes | Scheme + host[:port]; `/api/v1` is appended. e.g. `http://127.0.0.1:8000` |
| `SPATIUMDDI_TOKEN` | yes | Bearer for `SpatiumClient`. Use `$SDDI_TOKEN` for CRUD-only; use the admin `$ADMIN_JWT` to also exercise the restore case (above). |
| `SPATIUMDDI_GROUP_ID` | yes | DNS server-group id holding the test zone |
| `SPATIUMDDI_ZONE_ID` | yes | The test zone id |
| `SPATIUMDDI_VERIFY` | no | `0`/`false` to disable TLS verify for a self-signed lab cert (default: on) |

```bash
export SPATIUMDDI_BASE_URL="http://127.0.0.1:8000"
export SPATIUMDDI_TOKEN="$ADMIN_JWT"      # admin session → runs BOTH cases incl. restore
export SPATIUMDDI_GROUP_ID="$GROUP_ID"
export SPATIUMDDI_ZONE_ID="$ZONE_ID"

cd backend
python -m pytest tests/agents/eval/test_spatiumddi_live_golden_path.py -v
```

The test is self-cleaning (creates, updates, soft-deletes, restores, then
permanently removes its own throw-away record). With the env unset it is
**SKIPPED** — exactly what happens in CI.

---

## 5. Tear down

```bash
cd deploy/spatiumddi
docker compose down -v        # also drops the lab Postgres/Redis volumes
```

Revoke the lab API token server-side if it has not yet expired.
