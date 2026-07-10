# Settings hub — living plan

**Feature folder:** `docs/features/settings-hub/`  
**Last updated:** 2026-07-10 (after PR #127 merge)  
**Authority for done/remaining detail:** [COMPLETED.md](COMPLETED.md) · [REMAINING.md](REMAINING.md)

---

## 1. What Settings is for

Settings is the **role-gated operator hub** for day-to-day platform configuration and readiness — not a dump of every env var.

| Invariant | Meaning |
|---|---|
| **No secrets in SPA** | Provider API keys, OIDC client secrets, vault secrets never shown, entered, or returned |
| **Backend RBAC is source of truth** | Frontend `RoleRoute` is defense-in-depth only |
| **Env-owned deploy knobs** | OIDC issuer, SIEM sinks, retention days, Ollama URL stay deploy-time; UI reports *effective* status |
| **Audit mutations** | Profile changes, connection tests, vault create/rotate/disable audited; new writes must too |

---

## 2. Delivery sequence (as executed)

```text
[Done] PR #124  P0 hub + P1 vault / agents / LLM readiness
       │
       ▼
[Done] PR #125  Path A — T1.1 Audit honesty · T1.2 OIDC · T1.4 KEK strip
       │
       ▼
[Done] PR #126  Path B — T2.1 Integrations · T2.2 Health · T2.3 Retention flags
       │
       ▼
[Done] PR #127  Path C partial — T1.3 credential soft-disable
       │
       ▼
[Open]  T2.4 SIEM lag status (optional) · T0.3/T0.4 probe tests (optional)
       │
       ▼
[Open]  PR D / T2.5 — full audit-log browser (separate program)
```

---

## 3. Status board

### Done

| ID | Item | PR |
|---|---|---|
| P0 / P1 | Hub IA, Appearance, Agents, Account, Credentials list/create/rotate, LLM readiness+probe, Users help | #124 |
| T1.1 | Audit page honesty (agent tool audit) | #125 |
| T1.2 | OIDC live status strip (admin) | #125 |
| T1.4 | KEK rotation status on Credentials | #125 |
| T2.1 | Integrations matrix | #126 |
| T2.2 | Platform health panel | #126 |
| T2.3 | Retention / SIEM *configured* read-only flags | #126 |
| T1.3 | Credential soft-disable (retire) | #127 |
| T0.2 | Merge hub to main | #124 |

### Open

| ID | Item | Priority | Effort |
|---|---|---|---|
| T2.4 | SIEM export **lag / liveness** status | Default next Settings | M |
| T0.1 | Manual smoke on live stack | Ops | S |
| T0.3 | openai/azure probe success unit tests | Optional | S |
| T0.4 | LLM probe HTTP error → safe detail unit test | Optional | S |
| T2.5 | Full platform audit-log browser | Separate program | L |

### Out of scope (Settings SPA)

See [REMAINING.md § Tier 3](REMAINING.md#tier-3--explicitly-out-of-scope).

---

## 4. Sections live today (role map)

| Section | Path | Min role |
|---|---|---|
| Appearance | `/settings` | any auth |
| Agents & Chat | `/settings/agents` | any auth |
| My account | `/settings/account` | any auth |
| Credentials | `/settings/credentials` | engineer+ |
| AI / LLM | `/settings/llm` | admin |
| Users & access | `/settings/access` | admin |
| Integrations | `/settings/integrations` | admin |
| Platform | `/settings/platform` | admin |

---

## 5. Success criteria

### Closed (first cut)

- [x] Role-gated hub with discoverable LLM, vault, agents, access  
- [x] Settings tells the truth about audit scope, SSO, KEK pending  
- [x] Admin integrations inventory + dependency health + retention flags  
- [x] Vault entries can be retired without secret leakage  

### Still open

- [ ] Operator manual smoke complete  
- [ ] SIEM lag status if SIEM used in deployment  
- [ ] Platform-wide audit browser (T2.5) when compliance prioritizes it  

---

## 6. How to extend this feature

1. Update **REMAINING.md** with design notes before coding.  
2. Ship **one PR per secret-surface or IA slice** (pattern of #125–#127).  
3. Move completed rows into **COMPLETED.md** and flip this status board.  
4. Honor **L-FE-1** (update every `vi.mock` of changed API modules) and **L-IMG-1** (frontend apk cache-bust on fixable Alpine CVEs).  
