# SpatiumDDI lab — runbook for the opt-in live DDI golden-path test (T6)

This directory wires up a **self-hosted SpatiumDDI** instance so the env-guarded
live test can drive the DDI golden path against a *real* REST appliance:

> [`backend/tests/agents/eval/test_spatiumddi_live_golden_path.py`](../../backend/tests/agents/eval/test_spatiumddi_live_golden_path.py)

That test is the live twin of the deterministic, mock-backed CI test
(`test_spatiumddi_ddi_golden_path.py`). It exercises the same flow against a
running instance: seed a (soon-stale) DNS record → the genuine plugin mutator
returns a vendor-neutral `ChangeRequestDraft` (no inline write) → the framework
gate persists it as a `ddi_record` ChangeRequest → a **different** user approves
it (four-eyes, server-side) → the **Automation Agent** executes it via the real
`SpatiumClient` → re-query verifies the change → the audit chain links
`reasoning_trace → CR → audit_log`. It also proves the SpatiumDDI-distinctive
**delete → RESTORE** inverse (soft-delete; ADR-0024 §3), not a re-create.

> **This is a manual / lab step.** Nothing here runs in CI — the test is
> *collected but skipped* unless the `SPATIUMDDI_*` env vars below are set, and CI
> never sets them. You do **not** need this stack running for the backend gates.

Authority: [`docs/adr/0024-spatiumddi-client-and-endpoint-capability-mapping.md`](../../docs/adr/0024-spatiumddi-client-and-endpoint-capability-mapping.md).

---

## 1. Bring the SpatiumDDI stack up

SpatiumDDI is an open-source FastAPI DDI backend:
**https://github.com/spatiumddi/spatiumddi**. Two options:

### Option A — the wrapper compose in this directory (quickest)

```bash
cd deploy/spatiumddi
cp .env.example .env
# Edit .env: pin SPATIUMDDI_IMAGE to a known tag and set lab admin/db passwords.

docker compose up -d
docker compose logs -f spatiumddi   # wait for the API to report ready
```

The API is published on the host at **`http://127.0.0.1:8088`** (lab-only, bound
to localhost). Its global prefix is `/api/v1` (appended by `SpatiumClient`).

### Option B — upstream compose (canonical)

If upstream's image name/topology differs from the thin wrapper here, clone their
repo and use their compose directly — it is the source of truth for service
versions:

```bash
git clone https://github.com/spatiumddi/spatiumddi
cd spatiumddi
docker compose up -d        # see their README for required env / ports
```

Either way, note the **base URL** (scheme + host[:port], no `/api/v1`) the API is
reachable at — that becomes `SPATIUMDDI_BASE_URL`.

---

## 2. Create the test zone (and note its ids)

The live test mutates DNS records inside one zone. Create a throw-away test zone
under a DNS server group (via the SpatiumDDI UI or API), e.g. `golden.lab`, and
record two ids — both are **non-secret server UUIDs**:

- the **DNS server-group id** → `SPATIUMDDI_GROUP_ID`
- the **zone id** → `SPATIUMDDI_ZONE_ID`

```bash
# Example (adjust to your admin auth): list groups, then the group's zones.
curl -s http://127.0.0.1:8088/api/v1/dns/groups | jq '.[].id'
curl -s http://127.0.0.1:8088/api/v1/dns/groups/<GROUP_ID>/zones | jq '.[] | {id, name}'
```

> A fresh SpatiumDDI may auto-seed a default group/zone, or you may need to create
> them — confirm against your instance (ADR-0024 §6, open question 1). The test
> creates and cleans up its *own* record inside the zone; it does not create the
> zone.

---

## 3. Mint a least-privilege, resource-scoped API token

The live test authenticates with a SpatiumDDI bearer token
(`Authorization: Bearer sddi_<token>`). SpatiumDDI mints user-scoped, resource-
grantable tokens via `POST /api/v1/api-tokens` and returns the raw token **exactly
once** (only its sha256 hash + an `sddi_…` prefix are stored server-side).

Mint a token scoped to **just the test zone/subnet** with only the scopes the
golden path needs (DNS read + write so it can update/delete/restore a record).
The server enforces token `scopes` **before** RBAC, so a token without write
scope can never reach a write handler.

```bash
# Authenticate as the lab admin first (session/login flow per your instance),
# then mint the resource-scoped token. Adjust scope strings + grant shape to
# your SpatiumDDI version (ADR-0024 §6, open question 5):
curl -s -X POST http://127.0.0.1:8088/api/v1/api-tokens \
  -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "netops-golden-path (lab, least-privilege)",
        "expires_in_days": 1,
        "scopes": ["dns:read", "dns:write", "trash:restore"],
        "resource_grants": [{"type": "dns_zone", "id": "<ZONE_ID>"}]
      }'
# -> response includes {"token": "sddi_..."} ONCE. Copy it now; it is never shown again.
```

> **The token is a SECRET.** Never commit it, never paste it into a file under
> version control, never log it. Prefer a short `expires_in_days` for a lab token.
> If it leaks, revoke it server-side and mint a new one. (Our `SpatiumClient` holds
> it in a non-`repr` field and pins it only onto the `Authorization` header —
> ADR-0024 §2 / D11.)

---

## 4. Export the env vars the live test reads

The test reads these from the **environment** (not from any committed file):

| Variable | Required | Meaning |
|---|---|---|
| `SPATIUMDDI_BASE_URL` | yes | Scheme + host[:port]; `/api/v1` is appended. e.g. `http://127.0.0.1:8088` |
| `SPATIUMDDI_TOKEN` | yes | The raw `sddi_<token>` bearer from step 3 (**secret**) |
| `SPATIUMDDI_GROUP_ID` | yes | DNS server-group id holding the test zone |
| `SPATIUMDDI_ZONE_ID` | yes | The test zone id (what the token is scoped to) |
| `SPATIUMDDI_VERIFY` | no | `0`/`false` to disable TLS verify for a self-signed lab cert (default: verify ON) |

```bash
export SPATIUMDDI_BASE_URL="http://127.0.0.1:8088"
export SPATIUMDDI_TOKEN="sddi_...."          # from step 3; do not echo into history files
export SPATIUMDDI_GROUP_ID="<GROUP_ID>"
export SPATIUMDDI_ZONE_ID="<ZONE_ID>"
# export SPATIUMDDI_VERIFY=0                  # only for a self-signed lab cert
```

---

## 5. Run the live test

From `backend/` (using the project venv):

```bash
cd backend
python -m pytest tests/agents/eval/test_spatiumddi_live_golden_path.py -v
```

When the env vars are set it runs end to end against your instance (it creates,
updates, soft-deletes, restores, then permanently removes its own throw-away
record, so re-runs start clean). When they are **unset** it is skipped — that is
exactly what happens in CI:

```bash
# With nothing exported, the test reports SKIPPED (never fails the gate):
python -m pytest tests/agents/eval/test_spatiumddi_live_golden_path.py -v
# ... SKIPPED (opt-in live lab gate: set SPATIUMDDI_BASE_URL, ...)
```

---

## 6. Tear down

```bash
cd deploy/spatiumddi
docker compose down -v        # -v also drops the lab Postgres volume
```

Revoke the lab API token server-side if it has not yet expired.
