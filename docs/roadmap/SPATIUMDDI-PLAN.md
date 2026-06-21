# SpatiumDDI plugin + DDI golden-path validation — plan

**Status:** COMPLETE — shipped 2026-06-18 (PR #28, `0a23a6a feat(ddi): SpatiumDDI vendor plugin + DDI golden-path validation`).
**Decisions locked at review:** D-SP1 = **(A) generalize the draft**; scope = **full
plugin** (all four DDI capabilities, conformance); validation = **CI mock + opt-in
live** integration test.
**Authority:** Enables `docs/roadmap/M5-RELEASE-READINESS.md` §3 item #1 (the DDI
golden path — the one lab-deferred criterion currently blocked only by "no real
Infoblox grid"). Bound by `CLAUDE.md`, decisions D6 (vendor-plugin discovery
group) / D11 (human approval for changes) / D14 (sandboxing) / D16 (CI), and
ADR-0022 (DDI capability interfaces) + ADR-0020 (ChangeRequest four-eyes).

## Why

M5 shipped the DDI write-path against **Infoblox WAPI** and verified it against a
**mock** in CI. The live golden path (stale record → CR → different-user approve →
Automation executes → re-query verifies → audit chain) was deferred because the
user has no Infoblox grid. **SpatiumDDI** (https://github.com/spatiumddi/spatiumddi)
is a self-hostable, open-source DDI platform — so it becomes the **runnable** target
for that validation. Adding it also proves the multi-vendor DDI claim against a
second, non-Infoblox API.

## What SpatiumDDI is (from its README; endpoint-exact details come from its OpenAPI)

- **API-first REST/JSON.** "Every UI action is a REST call." FastAPI control plane,
  so a machine-readable **OpenAPI spec is available at `/openapi.json`** on a running
  instance — the source of truth for exact paths/bodies.
- **Real servers underneath:** BIND9 + Kea (and PowerDNS) as first-class containers;
  the control plane owns their config. DNS via RFC 2136 / TSIG; DHCP via Kea.
- **Resources:** hierarchical IPAM (spaces · blocks · subnets · IPv4/IPv6 addresses),
  DNS (zones · records, incl. SVCB/HTTPS/DNAME), DHCP (Kea scopes · leases ·
  reservations).
- **Auth:** API tokens (bearer), with **scoped + resource-scoped** tokens — we mint a
  least-privilege token bound to the test zone/subnet.
- **Soft-delete:** `DNSZone`/`DNSRecord`/`Subnet`/`DHCPScope` carry `deleted_at`
  (30-day trash). Affects our delete semantics + rollback inverse.
- **Typed events / webhooks** (`dns.record.updated`, `ip.allocated`, …) — not needed
  for the plugin, but a future verification signal.

## Codebase baseline (verified)

- The DDI capability contract a vendor plugin must satisfy is concrete (see
  `backend/app/plugins/vendors/infoblox/plugin.py`): a `VendorPlugin` with
  `vendor_id`/`display_name`/`capabilities`/`_capability_classes()`, and four
  capability classes — `DISCOVERY_API` (`discover`), `DDI_DNS` (`get_zones`,
  `get_records`, `add/modify/delete_record`), `DDI_DHCP` (`get_ranges`,
  `get_leases`, `add/delete_range`), `DDI_IPAM` (`get_networks`,
  `get_next_available_ip`, `add/delete_network`).
- Reads normalize to the shared `app.schemas.normalized` models (reused as-is) and
  record **raw-first** (`PluginCapability._record_raw`).
- **Mutations never write inline** — they return a `ChangeRequestDraft` with an
  inverse/rollback spec; only the Automation Agent executes an **approved** CR. This
  invariant is preserved unchanged.
- The plugin **conformance suite** exists (Infoblox was the first API-discovery
  plugin to pass it) — SpatiumDDI must pass the same suite.

## Design decision D-SP1 — generalize the write-path draft (ACCEPTED: option A)

`ChangeRequestDraft` is currently **Infoblox-shaped**: its fields are `WapiVerb` and
`wapi_object`. SpatiumDDI is a REST resource API, not WAPI. Options:

- **(A, recommended) Vendor-neutral draft.** Rename to a transport-agnostic shape:
  `verb` (CREATE/UPDATE/DELETE) + `resource` (e.g. `dns.record`, `dhcp.range`,
  `ipam.network`) + `body` + `object_ref` + `inverse`. Migrate the Infoblox plugin
  (it keeps a WAPI-object string as its `resource`), the Automation executor, and the
  CR `payload` serialization. Cleanest; pays down latent WAPI-in-the-core debt that
  the multi-vendor mandate (CLAUDE.md) always implied. Touches shared base + Infoblox
  + executor + their tests — bounded, fully covered by existing tests.
- **(B) Parallel Spatium draft.** Leave WAPI draft for Infoblox; give SpatiumDDI its
  own draft variant. Less churn now, but bakes a second write-path representation and
  re-introduces the duplication CodeRabbit just had us remove elsewhere. Not
  recommended.

This plan assumes **(A)**. It is the one change that ripples beyond the new vendor
directory; flagged for explicit sign-off at plan review.

## Task waves (dependency-ordered)

Built via the orchestrated wf-* workflow (same as M5): TDD per task, one atomic
commit, dual review → fix-if-findings → verify. ⚠️ = strong-model reviewers
(token/secret-touching or shared-core changes).

| # | Task | wf-* role | Cx |
|---|------|-----------|----|
| 1 | **API recon + ADR-0024**: stand up SpatiumDDI via its compose, pull `/openapi.json`, map endpoints → the four capability interfaces + auth/pagination/soft-delete/object-id semantics; write ADR-0024 (SpatiumDDI client + endpoint↔capability mapping + rollback/soft-delete semantics) | `wf-implementer` | M |
| 2 | **Draft generalization (D-SP1)** ⚠️: rename `WapiVerb`/`wapi_object` → vendor-neutral `verb`/`resource`; migrate Infoblox plugin + Automation executor + CR payload serialization; all existing tests green (behavior-preserving) | `wf-implementer` | M |
| 3 | **`spatiumddi` client**: httpx REST client (bearer token via the A9/secret-handling path, never logged), pagination, raw-first recording; unit-tested against recorded fixtures | `wf-implementer` | L |
| 4 | **`spatiumddi` plugin**: `DISCOVERY_API` + `DDI_DNS`/`DDI_DHCP`/`DDI_IPAM` over the client; mutations → generalized drafts with inverse/rollback honoring soft-delete; **passes the plugin conformance suite** | `wf-implementer` | L |
| 5 | **Deterministic SpatiumDDI mock** + **DDI golden-path CI test**: mock the REST surface; assert stale record → CR draft → different-user approve → Automation executes → re-query verifies → audit chain — runs in the unit-only CI backend job | `wf-eval-designer` | L |
| 6 | **Opt-in live integration test** + **compose wiring**: env-guarded (`SPATIUMDDI_BASE_URL`/token) golden-path test that skips in CI; a `deploy/` compose profile or doc to bring SpatiumDDI up locally for the live run | `wf-implementer` | M |
| 7 | **Register + route + docs**: register `spatiumddi` in the plugin discovery group; DDI Agent works over it unchanged (vendor-agnostic by the normalized boundary); update `M5-RELEASE-READINESS.md` §3 item #1 to name SpatiumDDI as the live target; vault/README | `wf-implementer-light` | S |

## Risks → escalation

1. **Token = secret.** The SpatiumDDI API token is a credential — it flows through the
   same secret-handling/A9 path, is never logged, never reaches an LLM prompt. Use a
   **resource-scoped** token bound to the test zone/subnet. ⚠️ reviewers on #3.
2. **Shared-core change (D-SP1, #2).** The draft rename touches the Infoblox plugin +
   executor. Mitigation: behavior-preserving, gated by the existing Infoblox + executor
   tests; ⚠️ reviewers; one atomic commit.
3. **Write-path invariant unchanged.** SpatiumDDI mutators draft CRs only; four-eyes +
   Automation-as-sole-executor are untouched. The conformance suite + golden-path test
   assert no inline write path exists.
4. **Soft-delete rollback.** A SpatiumDDI delete is a soft-delete (`deleted_at`); the
   inverse is an **undelete/restore**, not a re-create — ADR-0024 must pin this so the
   rollback spec is correct (distinct from Infoblox's hard delete → re-create).
5. **Mock fidelity.** A wrong mock makes the CI golden path pass while live fails. The
   mock is built from the **recorded** `/openapi.json` + real recorded responses (#1),
   and the opt-in live test (#6) is the fidelity backstop.

## Exit criteria

- `spatiumddi` plugin passes the **plugin conformance suite** (four capabilities).
- DDI **golden-path CI test** (vs the mock) is green in the unit-only backend job;
  asserts the full write-path + four-eyes + audit chain.
- **Opt-in live test** runs green against a real self-hosted SpatiumDDI (manual/lab),
  and **skips cleanly** in CI.
- The generalized draft keeps every existing Infoblox + executor test green.
- `M5-RELEASE-READINESS.md` §3 item #1 updated: DDI golden path is now **runnable**
  against SpatiumDDI (no longer blocked on hardware).
- ADR-0024 records the client + endpoint↔capability mapping + soft-delete/rollback
  semantics. Trivy/CI gates green.

## Open items (resolved at build time, need the live instance)

- Exact REST paths + request/response bodies + object-id field — from `/openapi.json`
  (#1). The plan is endpoint-shape-agnostic until then by design.
- DHCP specifics: Kea lease/reservation representation in SpatiumDDI's API.
- Whether SpatiumDDI exposes a server-side "next available IP" (maps to
  `get_next_available_ip`) or we compute it from subnet free-space.
