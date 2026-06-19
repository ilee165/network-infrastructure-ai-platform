# M5 Release Readiness — Wave 6 Task 20 (gates + release cut)

**Date:** 2026-06-19
**Branch:** `release/m5` (the cut branch — already exists)
**Authority:** `docs/roadmap/M5-PLAN.md` row 20 ("Full gates + live-lab validation
+ release branch `release/m5`") and the M5 exit-table row 8 ("Security review
checklist signed off; **Trivy zero critical CVEs**; **all M0 CI gates green**").
**Companion docs:** `docs/security/2026-06-19-m5-security-review-signoff.md` (T19
security sign-off), `docs/security/2026-06-14-trivy-baseimage-cves.md` (deferred
base-image CVEs), `.github/workflows/ci.yml` (canonical CI gate definitions).

This document records the **real** gate results captured on the release HEAD,
states the Trivy posture honestly (it is CI-gated — the scanner is not runnable
on the dev host), and enumerates the **lab-deferred manual pre-merge checklist**
that a human must execute against real infrastructure before merging
`release/m5` to `main`. **This host has no real network devices; live-lab
validation has NOT been performed here and is NOT claimed.**

---

## 1. Repo gates — REAL results (release/m5 HEAD)

All gate commands are the exact ones in `.github/workflows/ci.yml`. Run on the
dev host (Windows) on 2026-06-19 against `release/m5`. Counts are the actual tool
output, not estimates.

### Backend (`cd backend/`, project venv `backend/.venv`)

| Gate | Command | Result |
|------|---------|--------|
| Lint | `ruff check .` | **PASS** — "All checks passed!" |
| Format | `ruff format --check .` | **PASS** — 315 files already formatted |
| Typecheck | `mypy` | **PASS** — no issues in 155 source files |
| Module boundaries | `lint-imports` | **PASS** — 2 contracts kept, 0 broken (151 files, 476 deps) |
| Tests + coverage | `pytest --cov=app --cov-fail-under=80 -q` | **PASS** — 1964 passed, 13 skipped; total coverage **93.75%** (gate 80%) |

### Frontend (`cd frontend/`)

| Gate | Command | Result |
|------|---------|--------|
| Lint | `npm run lint` (eslint) | **PASS** — "No issues found" |
| Typecheck | `npm run typecheck` (tsc --noEmit) | **PASS** — clean |
| Tests | `npm test` (vitest run) | **PASS** — 27 files, 292 passed |
| Build | `npm run build` (vite) | **PASS** — 118 modules transformed, built; bundle-size note is an advisory warning only (exit 0) |

**All 9 repo gates are GREEN on the release HEAD.** (The vitest run emits a benign
jsdom "Not implemented: navigation" log inside a *passing* DocumentsPage
download-link test; the chunk-size note from vite is advisory. Neither is a
failure — both jobs exit 0.)

---

## 2. Trivy — CI-gated (runs on push), NOT runnable on this host

**Status: CI-gated — runs on push. No local result fabricated.**

- The Trivy CLI is **not installed** on the dev host (`which trivy` → not found)
  and the **Docker daemon is not running** (`docker info` → cannot connect to the
  Linux engine pipe). Backend + frontend images therefore could not be built or
  scanned here.
- Trivy is enforced in CI by the `docker (build images + Trivy scan)` job
  (`.github/workflows/ci.yml:124-181`), which `needs: [backend, frontend]`, builds
  both images, and runs `aquasecurity/trivy-action@v0.36.0` with
  `severity: CRITICAL,HIGH`, `ignore-unfixed: true`, `exit-code: "1"` on each
  image. The build **fails on any FIXABLE CRITICAL/HIGH CVE**.
- `ignore-unfixed: true` keeps the gate actionable: it fails only on a CVE that
  has an available fix we have not applied, not on upstream-unpatched base-image
  OS packages. The remaining unfixed Debian base-image CVEs are tracked and
  reasoned about in `docs/security/2026-06-14-trivy-baseimage-cves.md` (all
  `fix_deferred`, off the reachable runtime attack surface).
- The T19 security sign-off rates "Trivy zero-critical posture" **PASS** with the
  release-gating action item carried here.

**Release action (must be green before merge to `main`):** trigger the CI `docker`
job on the `release/m5` HEAD (push / PR) and confirm **both** Trivy steps pass
(zero fixable CRITICAL/HIGH). Re-check whether Debian has since published fixes
for the deferred base-image CVEs in
`docs/security/2026-06-14-trivy-baseimage-cves.md`.

---

## 3. Live-lab validation — DEFERRED (no real devices on this host)

This host has **no real network devices, no real Infoblox grid, and no
capture-capable hardware**. The automated M5 eval suite (T18,
`backend/tests/agents/eval/`) exercises the write-path spine, routing, packet
top-talkers vs `tshark` ground-truth, and the DDI golden path **against mocks /
fixtures** — and is green inside the pytest gate above. The items below require
**real infrastructure** and therefore must be executed **manually by a human
before merging `release/m5` to `main`**. They map 1:1 to the MVP §7 / M5-PLAN
exit-table criteria that depend on live systems.

### Lab-deferred manual pre-merge checklist

1. **Golden path on a real DDI backend (E2E write-path).** DDI Agent finds a
   stale DNS record → opens a ChangeRequest → a **different** user (four-eyes)
   approves → the Automation Agent executes the record change → re-query confirms
   the record is corrected → the full audit chain (CR transitions + approval +
   reasoning-trace links) is intact. (Exit-table row 1.)

   **Live target: SpatiumDDI (self-hostable, now RUNNABLE — no appliance required).**
   `spatiumddi` is registered in the built-in plugin group and the
   `netops.plugins` entry-point group (ADR-0024, T7 — `spatiumddi-plugin` branch).
   A self-hosted SpatiumDDI instance (`github.com/spatiumddi/spatiumddi`) can be
   stood up via Docker Compose with zero appliance hardware, replacing the
   previously-deferred real Infoblox grid requirement for this checklist item.
   The Infoblox path (WAPI) remains a valid alternative for teams that have a grid.
   SpatiumDDI open questions (ADR-0024 §6: default group_id bootstrapping,
   view_id requiredness, restore 409 surface) must be confirmed against the live
   instance before the E2E run.

2. **Config restore on a real device.** Restore a prior `config_snapshots` entry
   to a **real** route/switch (cisco_ios / cisco_iosxe / eos) **through a
   ChangeRequest** (Automation Agent executes the approved CR), then confirm the
   running device config matches the snapshot afterward, with the structured
   rollback step exercised on a forced failure. (Exit-table row 3.)

3. **Capture → Wireshark (real capture path).** From the UI, launch a packet
   capture on a **real device / link** → produce a pcap → run the sandboxed
   `tshark` analysis → confirm top-talkers match independently-computed ground
   truth → confirm the pcap **opens in Wireshark** unmodified. (Exit-table row 4.)

4. **Live-model redaction (real LLM provider).** With a **real** external LLM
   provider configured (anthropic / openai / azure), drive a CR-diff preview, a
   config/DNS explanation, and an agent narrative, and confirm via provider-side
   request capture that **no** secret material (SNMP communities, Cisco type-7 /
   enable secrets, RADIUS/TACACS keys, IPsec PSKs, routing-auth keys) leaves the
   process un-redacted. (A9 redaction; T19 sign-off control #3 — code path
   PASS/test-pinned, live-provider confirmation deferred to lab.)

5. **Real-device drift detection.** Run drift detection against a **real** device
   whose running config has diverged from its stored baseline and confirm the
   detected drift, the surfaced diff, and the audit entry are correct on live
   hardware (not just the M4 fixture path). (Exit-table row 7 dependency /
   config-management posture on real gear.)

> Additional pre-merge gate (not a live-device item, listed for completeness):
> trigger the CI `docker` + Trivy job on the release HEAD and confirm green
> (see §2).

---

## 4. Known deferred (carried past M5 by design — NOT release blockers)

From the T19 security sign-off (`docs/security/2026-06-19-m5-security-review-signoff.md`),
sign-off control **#2 (packet sandbox) is PARTIAL**:

- **Signed PASS now:** the process-launch controls — argv-not-shell, display-filter
  whitelist before spawn, `-n` (no name resolution), hard subprocess timeout, and
  the capture/analysis privilege split — are in code and test-pinned.
- **Deferred to the production/K8s milestone (PRODUCTION.md, ADR-0013 §4,
  ADR-0023 §1):** the OS-level isolation half — CPU/mem resource limits, a
  no-network container, dropped capabilities (`cap_drop: [ALL]`), non-root,
  read-only pcap mount, and a dedicated least-privilege `packet` worker. There is
  no Helm chart and no Compose hardening today; this must **not** be signed PASS
  until that work lands.

These are explicitly milestone-deferred (post-MVP hardening) and are **not** M5
release blockers — they are recorded here so the merge decision is fully informed.

---

## 5. Release cut

- **Cut branch:** `release/m5` (already exists; this is the validated cut branch).
- **Tag:** an **annotated** tag `m5-wave6` is created at the `release/m5` HEAD
  **after** this readiness doc is committed, marking the gate-validated release
  candidate.
- **Merge to `main`:** **NOT performed.** Left to the human after the lab-deferred
  checklist (§3) and the CI Trivy job (§2) are confirmed green on the release HEAD.
- **Push:** **NOT performed.**

**MVP is feature-complete at M5 exit.** Repo gates are green; Trivy is CI-gated;
the remaining sign-offs are the live-lab manual checklist and the CI Trivy run,
both owned by the human merge decision.
