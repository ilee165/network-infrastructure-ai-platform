# Settings hub — completed plans

Snapshot of work **merged to `main`** as of squash `7afab8b` (PR #127, 2026-07-10).  
Original prioritization lived in an operator-hub inventory session plan; this doc is the durable record.

---

## Delivery map

```text
[Done] PR #124  P0 hub + P1 vault / agents / LLM readiness
       │
       ▼
[Done] PR #125  Path A — honesty + OIDC status + KEK strip
       │         T1.1 · T1.2 · T1.4
       ▼
[Done] PR #126  Path B — integrations + platform health + retention
       │         T2.1 · T2.2 · T2.3
       ▼
[Done] PR #127  Path C (partial) — credential soft-disable
                 T1.3
```

---

## PR #124 — Hub shell (P0 + P1)

**Merge:** squash on `main` · branch `feat/settings-hub-p0-p1`  
**Title:** feat(settings): hub for LLM, credentials, agents, and access

### Sections shipped

| Section | Path | Min role | Capability |
|---|---|---|---|
| Appearance | `/settings` | any auth | Theme picker (light / dark / system) |
| Agents & Chat | `/settings/agents` | any auth | Prerequisites, core agents, example prompts, safety |
| My account | `/settings/account` | any auth | Deep-link to Profile |
| Credentials | `/settings/credentials` | engineer+ | List + paginate + create + rotate (secrets write-only) |
| AI / LLM | `/settings/llm` | admin | Profile + role map, egress warning, setup copy, readiness + connection test |
| Users & access | `/settings/access` | admin | Link to Users + RBAC ranks + OIDC/break-glass **static help** |

### Supporting surfaces

| Capability | Where |
|---|---|
| Runtime LLM badge | `GET /auth/llm-profile` → Layout header |
| Static configured? | `GET /auth/settings/llm-readiness` |
| Live probe | `POST /auth/settings/llm-test` (+ `llm.connection_tested` audit) |
| Vault client | `frontend/src/api/credentials.ts` |
| Hub shell | Nested routes in `App.tsx`, section nav |

### Inventory closed

- [x] P0 hub IA / discoverability  
- [x] P0 surface LLM without tribal knowledge  
- [x] P0 deep-links (Users, Profile, Credentials, Chat)  
- [x] P1 credential vault UI over existing API  
- [x] P1 agents onboarding  
- [x] P1 OIDC/break-glass *help* (static copy only)  
- [x] P1 LLM readiness + connection test + Ollama model list on probe  

---

## PR #125 — Path A (Tier 1 honesty)

**Merge:** squash on `main` · branch `feat/settings-hub-path-a-honesty-oidc-kek`  
**Title:** feat(settings): audit honesty, OIDC status, and KEK rotation strip

| Task | Deliverable |
|---|---|
| **T1.1** Audit honesty | `/audit` retitled **Agent tool audit**; copy no longer overclaims platform-wide `audit_log` browser |
| **T1.2** OIDC status | Admin `GET /auth/settings/oidc-status` — enabled / configured flags only (no secret refs as values); Access section StatusPill |
| **T1.4** KEK rotation strip | Settings → Credentials surfaces existing `GET /credentials/rotation-status` (versions + `rows_pending` only) |

### Lessons recorded

- **L-FE-1** — partial `vi.mock` of API modules must list every new export (`SettingsRoute.test.tsx` + `getRotationStatus`)  
- **L-IMG-1** — fixable Alpine CVE + GHA cache → bump frontend Dockerfile `apk upgrade` cache-bust date  

See `docs/roadmap/LESSONS.md`.

---

## PR #126 — Path B (Tier 2 first cut)

**Merge:** squash on `main` · branch `feat/settings-path-b-integrations-platform`  
**Title:** feat(settings): integrations matrix and platform health panel

| Task | Deliverable |
|---|---|
| **T2.1** Integrations matrix | Admin `GET /api/v1/integrations` — registered vendors, capabilities, static category tags; Settings → Integrations table |
| **T2.2** Platform health | Admin `GET /auth/settings/platform-health` reuses same readiness probes as public `/health/ready` via shared `build_readiness_report()`; dependency cards + refresh |
| **T2.3** Retention / export flags | Admin `GET /auth/settings/platform-config` — pcap/raw-artifact retention schedules + SIEM format/`configured` bools only (never host/URL/bearer) |

### Security checklist (met)

- [x] Admin-only RBAC on new surfaces  
- [x] No secrets in JSON responses  
- [x] Public `/health/ready` remains unauthenticated for K8s  

---

## PR #127 — Path C / T1.3 credential soft-disable

**Merge:** squash `7afab8b` · branch `feat/settings-t1.3-credential-disable`  
**Title:** feat(settings): T1.3 credential vault soft-disable (retire)

### Design choice (locked)

**Soft-disable (retire), not hard DELETE of ciphertext.**

| Behavior | Detail |
|---|---|
| API | `POST /api/v1/credentials/{id}/disable` (engineer+) |
| Row | Sets `disabled_at` (migration `0019`); renames to free operator-facing unique name |
| List | Active-only (`disabled_at IS NULL`) so dead names leave the UI |
| Decrypt / rotate | Refuse disabled credentials (`409 Conflict`) |
| Audit | `credential.disabled` — name / kind / disabled_name only (never secret material) |
| UI | Settings → Credentials **Disable** + confirm dialog |
| Ciphertext | Left envelope-encrypted; unusable via API. Hard purge deferred |

### Key files

- `backend/alembic/versions/0019_credential_disabled_at.py`
- `backend/app/services/credentials/service.py` (`disable_credential`)
- `backend/app/api/v1/credentials.py`
- `frontend/src/api/credentials.ts` (`disableCredential`)
- `frontend/src/pages/SettingsPage.tsx`

---

## Task checklist (completed)

### Tier 0

| # | Item | Status |
|---|---|---|
| T0.1 | Manual smoke checklist on PR body | Partial (checklists present; operator may still smoke live stack) |
| T0.2 | Merge #124 → `main` | **Done** |

### Tier 1

| # | Item | Status | PR |
|---|---|---|---|
| T1.1 | Audit page honesty | **Done** | #125 |
| T1.2 | OIDC live status strip | **Done** | #125 |
| T1.3 | Credential delete/retire | **Done** (soft-disable) | #127 |
| T1.4 | KEK rotation status UI | **Done** | #125 |

### Tier 2 (first cut)

| # | Item | Status | PR |
|---|---|---|---|
| T2.1 | Integrations matrix | **Done** | #126 |
| T2.2 | Platform health panel | **Done** | #126 |
| T2.3 | Retention effective-config (read-only) | **Done** | #126 |

---

## Success criteria — closed

### Tier 1 (Path A)

- [x] Audit page no longer claims full platform audit log  
- [x] Admin Access shows live OIDC enabled/disabled without secrets  
- [x] Credentials section shows KEK rotation pending count  
- [x] Tests + gates green at merge  

### Tier 2 first cut (Path B)

- [x] Admin can list registered vendor plugins + capabilities  
- [x] Admin can see dependency readiness from authenticated Settings  
- [x] Admin can see effective retention numbers (read-only)  
- [x] No secrets in new response schemas (API tests)  

### T1.3

- [x] Engineer can retire a vault entry without secret leakage  
- [x] Name reusable after disable  
- [x] Disabled rows excluded from default list  
- [x] Decrypt/rotate fail closed on disabled rows  
