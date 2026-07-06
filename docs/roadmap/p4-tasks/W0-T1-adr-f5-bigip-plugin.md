# W0-T1 — ADR-0050 F5 BIG-IP plugin (iControl REST, `ADC_SERVICES`, UCS archive backup)

| | |
|---|---|
| **Wave** | P4 W0 — ADRs / design gate |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet; **strong** on the credential flow (§2) and UCS secret-surface (§7) sections |
| **Depends on** | — |
| **Builds on** | ADR-0006 (plugin contract), ADR-0007 D7 (httpx for F5 iControl), ADR-0011 (vault/audit/CR), ADR-0020/0021 (CR gating, never-silent rollback), ADR-0034/0035 (capability-ratification + httpx-client precedents) |
| **PRODUCTION.md** | §2.4 (Wave 3 row), §2.6, §11 G-SEC/G-MNT |
| **Status** | **Done** (W0, `feat/p4-w0-adrs`) |

## Objective

Ratify the F5 BIG-IP plugin design the W1-T1 build implements field-for-field:
**plain-httpx iControl REST client (no third-party F5 library), vault-referenced
token auth, the NEW `ADC_SERVICES` capability with final
`NormalizedVirtualServer`/`NormalizedPool`/`NormalizedPoolMember` models, routes
from self-IPs with route-domain→`vrf` mapping, `HA_STATUS` on the existing
model, and UCS backup as an opaque secret-bearing archive** via a new additive
archive-capability pair with CR-gated restore.

## Scope

**In** — the design decisions and rationale: client/library choice (§1), token
credential flow + least-privilege note (§2), capability map (§3), `ADC_SERVICES`
ABC + models + enums + nesting + single-vendor-validation deviation (§4), routes
via self-IPs / route domains (§5), `HA_STATUS` mapping (§6), the UCS posture —
per-backup vault passphrases, double envelope encryption, metadata-only
surfaces, no download endpoint, CR-gated restore with baseline rollback, the
named F5 text-drift deferral (§7), conformance/fixture obligations (§8), open
lab questions (§9).

**Out** — implementation (W1-T1); inventory UI (W1-T3); the W2 derivation
(ADR-0052); AFM/`FIREWALL_POLICY`; F5 text-config drift (named-deferred,
ADR-0050 §7.6).

## Requirements (grounded in PRODUCTION.md §2.4/§2.6, ADR-0006/0011/0021)

1. **New capability surface ratified before code** (REPO-STRUCTURE §6–§7): enum
   member, typed ABC signatures, final model names + field tables W1-T1 binds to.
2. **Secret surface to the strong bar:** login/token lifecycle, redaction filter
   coverage (password + token, literal + percent-encoded), and the entire UCS
   chain (passphrase, storage, restore) named explicitly — zero plaintext
   leakage is a W1 exit criterion.
3. **Write paths CR-only:** archive restore refuses without an approved CR;
   backup justified as a read (ADR-0017/0021 split).
4. **Named deviations, never silent:** single-vendor ADC validation; no F5 text
   drift surface in P4; live golden path deferred-accepted → live lab.

## Contracts / artifacts

- `docs/adr/0050-f5-bigip-plugin.md` (Proposed); index entry via W0-T5.

## Test & gate plan

- D16 docs gates only (ADR — no code). The ADR names the exact fixture cases,
  secret-leak assertions, and conformance wiring (`_INTERFACE_SPECS`, the
  ADR-0025 §8 three-file lesson) W1-T1 must satisfy.

## Exit criteria

- [x] ADR-0050 written (Proposed): client choice, credential flow, `ADC_SERVICES` + models/enums, routes/route-domains, `HA_STATUS`, UCS archive posture + CR-gated restore.
- [x] Secret-surface sections (§2/§7) reviewed at the strong bar.
- [x] Named deviations recorded (single-vendor validation, text-drift deferral, live-lab deferral).
- [x] One atomic commit (`f694add`, review fixes folded).

## Workflow

`wf-implementer` drafts → spec + quality review (strong on §2/§7) → fixer if findings → verifier → one atomic commit.

## Risks

- **UCS under-specification** → W1-T1 improvises on the most sensitive artifact
  yet stored. The ADR pins passphrase lifecycle, storage encryption, API
  surface, and restore/rollback sequence.
- **Model-field gaps** → W2 derivation churn mid-wave. The field tables carry
  every join field ADR-0052 consumes (VIP/port/protocol/pool/member
  address/port/state, `fqdn`, `vrf`).
