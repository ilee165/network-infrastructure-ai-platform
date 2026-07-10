# Settings hub — remaining plans

Open work after PRs #124–#127. Prefer **small, secret-safe** Settings slices; do not sneak in Tier 3 items.

For the full living plan and invariants, see [PLAN.md](PLAN.md). Shipped work is recorded in [COMPLETED.md](COMPLETED.md).

---

## Recommended next builds

| Priority | Task | Effort | When |
|---|---|---|---|
| **1 (default next Settings)** | **T2.4** SIEM export status depth | M | Lab/ops uses SIEM export |
| **2 (optional polish)** | **T0.3 / T0.4** LLM probe unit coverage | S | Want stronger #124 residual tests |
| **3 (separate program)** | **T2.5** Full platform audit-log browser | L | Align with P4 W3 compliance reporting |
| **Ops (not code)** | Manual smoke of #124–#127 on live stack | S | Before treating hub as “done” for operators |

If SIEM is not used in the lab, **stop Settings feature work** after smoke and pick non-Settings roadmap items.

---

## T2.4 — SIEM export status (optional Path C remainder)

### Why

Path B already surfaces **static** effective config:

- `audit_export_format` (or null = disabled)
- `audit_export_configured` (bool — host/token *presence* only)

Operators still lack a **liveness** signal: is export running, lagging, or stalled? That is the gap T2.4 closes.

### Scope

| In | Out |
|---|---|
| Read-only admin surface (Platform section or Access) | Writable SIEM config from UI |
| Export enabled / format (reuse platform-config) | Bearer token, full URL secrets |
| Lag / last-success if already recorded in metrics or exporter state | Inventing a new SIEM pipeline (ADR-0045 already owns export) |
| Secret-free problem details on probe failures | Scraping arbitrary host process state |

### Design notes

- Prefer extending `GET /auth/settings/platform-config` **or** a sibling `GET /auth/settings/siem-status` (admin).
- Source lag from existing exporter / Prometheus series if present (see ADR-0045, runbook `docs/runbooks/slo-audit-siem-export-lag.md`) — **do not** invent a second export path.
- **Never** return `audit_export_bearer_token` or raw sink credentials.
- Tests: admin 200, non-admin 403, configured=false when unset, lag field absent or null when unknown (no fake zeros that hide outage).

### Acceptance

- [ ] Admin Platform (or dedicated strip) shows export enabled + format + lag/last-success when available  
- [ ] No secret fields in schema or JSON  
- [ ] API + Settings UI tests green  

### Critical files (expected)

| File | Role |
|---|---|
| `backend/app/api/v1/auth/settings.py` | Admin GET |
| `frontend/src/pages/SettingsPage.tsx` | Platform section UI |
| `frontend/src/api/auth.ts` | Client types |
| `backend/tests/api/test_settings_admin.py` | RBAC + no-secret assertions |

---

## T0.3 / T0.4 — LLM probe residual tests (optional)

Residual from #124 close-out. **No product UI.**

| # | Item | Effort | Notes |
|---|---|---|---|
| T0.3 | Unit tests for openai / azure probe **success** paths | ~15 min | Complements local-profile coverage |
| T0.4 | Unit test HTTP error → safe `error` detail | ~10 min | No stack / secret leakage in problem body |

**Files:** LLM readiness/probe modules under `backend/app/api/v1/auth/` and related tests (`test_settings_admin.py` or llm test package).

**Acceptance:** pytest green; asserts response `detail` never contains credential material.

---

## T2.5 — Full audit-log browser (separate program)

### Why

Settings Access / Audit honesty correctly state that the SPA does **not** yet browse platform `audit_log`. Operators and compliance need filtered history (actor / action / target / time). That is larger than Settings hub IA.

### Scope

| In | Out |
|---|---|
| Admin `GET /api/v1/audit` (or equivalent) over `audit_log` | Viewer unrestricted dump |
| Pagination + filters (actor, action, target_type/id, time range) | Mutating or deleting audit rows |
| Honest UI (replace or supersede session tool-call page, or deep-link from Settings) | SIEM sink reconfiguration from SPA |
| Alignment with P4 compliance reporting / ADR-0053 | Duplicating hash-chain verify UI (already CronJob + runbooks) |

### Design notes

- May need a short ADR or amendment if route budget / retention UX is non-trivial.
- Hash-chain integrity remains service-owned (ADR-0038); browser is **read** of sealed rows, not a re-verify console (unless explicitly specified).
- Settings hub **only deep-links** to the browser once it exists (`/settings/access` → “Platform audit log”).
- Secret-free `detail` already enforced at write time — still red-team list/get serializers.

### Acceptance

- [ ] Admin can filter and page platform audit entries  
- [ ] Non-admin 403  
- [ ] No secret material in list payloads (tests with planted credential-shaped strings in unrelated fields if needed)  
- [ ] Settings copy/links updated so honesty claims match reality  

### Critical files (expected)

| File | Role |
|---|---|
| New `backend/app/api/v1/audit.py` (or under `auth/`) | List endpoint |
| `frontend/src/pages/AuditPage.tsx` (or new page) | Browser UI |
| `docs/adr/` | Only if contract needs a new ADR |
| P4 task specs under `docs/roadmap/p4-tasks/` | Cross-link when built under compliance wave |

---

## Tier 3 — Explicitly out of scope

Do **not** implement these under Settings without a new ADR and explicit product decision:

| Item | Why defer |
|---|---|
| Enter/store LLM or cloud API keys in SPA | Forbidden by ADR-0009 |
| Writable retention / SIEM / OIDC from UI | Deploy-time secrets & blast radius |
| `POST /llm-test` rate limit | Needs shared rate-limit primitive |
| Credential *connection* test (SSH/SNMP probe) | Device-scoped; different domain from LLM probe |
| Font size / high-contrast Appearance extras | Product preference; never in shipped IA |
| New LLM profiles (Bedrock, etc.) | Provider registry expansion, not Settings IA |
| Public `/health/ready` redesign | Data-plane probes stay unauthenticated & non-secret |
| Hard purge of credential ciphertext | Deferred from T1.3; needs retention/compliance design |

---

## Manual smoke (ops — still open)

Not a code task; blocks claiming full operator-ready close:

- [ ] Viewer: Appearance / Agents / Account only; no LLM / credentials / integrations / platform  
- [ ] Engineer: Credentials list/create/rotate/**disable**; name reuse after disable  
- [ ] Admin: LLM profile save + badge; OIDC strip; Integrations; Platform health + retention  
- [ ] Non-admin cannot hit admin Settings APIs (403)  

---

## Suggested execution prompts

**T2.4 only:**

> Implement Settings T2.4 SIEM export status per `docs/features/settings-hub/REMAINING.md`. Admin-only, no secrets, extend Platform section. One PR from `main`.

**T2.5 (large):**

> Plan T2.5 full audit-log browser against ADR-0038/0053 and `docs/features/settings-hub/REMAINING.md`. Spec before code; do not fold into a Settings cosmetics PR.
