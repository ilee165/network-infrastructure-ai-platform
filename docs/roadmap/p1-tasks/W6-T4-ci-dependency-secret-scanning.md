# W6-T4 — CI Dependency + Secret Scanning (pip-audit, npm audit, gitleaks)

| | |
|---|---|
| **Wave** | P1 W6 — Security hardening (P1 subset) |
| **Owner** | `wf-infra` (CI pipeline; policy-as-test) |
| **Review tier** | sonnet spec + **strong** quality (supply-chain = security-semantic CI, P1-PLAN.md §2 review watch) |
| **Depends on** | — (independent CI slice; lands before W6-T5 which extends the same `ci.yml`) |
| **ADRs** | ADR-0016 (D16 CI pipeline), ADR-0011 §6 (no-secret posture) |
| **PRODUCTION.md** | §5 ("Dependency and secret scanning in CI — pip-audit, npm audit, gitleaks — added to the D16 pipeline"), §11 G-SEC / G-MNT |
| **Status** | Proposed |

## Objective

Add dependency-vulnerability and secret scanning to the existing GitHub Actions pipeline
(`.github/workflows/ci.yml`, D16/ADR-0016): **pip-audit** (backend), **npm audit** (frontend), and
**gitleaks** (repo + history), with reviewed allowlists for accepted findings. This closes the
PRODUCTION.md §5 supply-chain checklist line for dependency/secret scanning; image SBOM/signing is
the sibling task W6-T5.

## Scope

**In** (`.github/workflows/ci.yml` + small config files)
- **pip-audit** over the backend dependency set (`backend/pyproject.toml` / resolved lockset);
  fails on known-vulnerable dependencies above the agreed severity floor.
- **npm audit** over `frontend/package-lock.json`; fail threshold aligned with the Trivy posture
  (PROPOSED: fail on `high`+, matching ADR-0016's "raise to HIGH,CRITICAL at production release").
- **gitleaks** scanning the working tree **and** git history for committed secrets; fails the job on
  a finding.
- Reviewed allowlists for accepted findings: `.gitleaks.toml` allowlist + a pip-audit/npm-audit
  ignore list with **expiry/justification comments** (mirrors the existing reviewed `.trivyignore`
  posture referenced in `ci.yml`).
- Wire as discrete jobs (or steps) in the D16 pipeline so a finding is a **red gate**, not advisory.

**Out**
- SBOM (syft) + cosign image signing + admission verification + Trivy gate raise → **W6-T5**.
- The KMS/rate-limit Python work (W6-T1..T3, T6).
- Runtime secret management (that is the KMS track / external-secrets) — this task scans the *repo
  and dependencies*, not runtime config.

## Requirements (grounded in PRODUCTION.md §5, ADR-0016)

1. **All three scanners are CI gates** (PRODUCTION.md §5): pip-audit + npm audit + gitleaks, added to
   the D16 lint→typecheck→test→build pipeline (ADR-0016 §). A finding fails the run.
2. **gitleaks scans history, not just HEAD** — a secret committed earlier and later removed is still
   exposed in history; the scan must catch it (G-SEC credential-leak posture, ADR-0011 §6).
3. **Reviewed allowlists, never blanket-ignore** — every accepted finding has a justification +
   (where supported) an expiry, mirroring the `.trivyignore` convention already in `ci.yml`. No
   silent suppression.
4. **Offline-friendly / self-hosted-fork-friendly** where feasible (ADR-0016 Alt #4 rationale —
   tools that run in a self-hosted fork): pin tool versions/actions, document any advisory-DB fetch.
5. **Deterministic + pinned** — pin action SHAs/versions (the repo already pins `actions/*@vN`,
   `trivy-action@v0.36.0`), so the supply-chain scan is not itself a supply-chain risk.

## Contracts / artifacts

- `.github/workflows/ci.yml` — new `pip-audit` step in the `backend` job, `npm audit` step in the
  `frontend` job, and a `gitleaks` job (or a `security-scan` job aggregating all three); jobs gate
  the run (`needs`/required-check appropriate).
- `.gitleaks.toml` (config + reviewed allowlist), pip-audit / npm-audit ignore files with
  justification+expiry comments.
- A short `docs/security/supply-chain-scanning.md` note documenting thresholds, allowlist policy, and
  how to triage a finding (CLAUDE.md "every feature has documentation").

## Test & gate plan (CI policy-as-test)

- The three scanners run green on the current tree (or with justified, documented allowlist entries).
- Negative validation: a deliberately-planted dummy secret (in a throwaway branch/test) is caught by
  gitleaks; a known-vulnerable pinned dep in a test fixture is caught by pip-audit/npm-audit — proving
  the gates bite (then reverted).
- Action versions/SHAs pinned; workflow YAML lints (actionlint where available).

## Exit criteria

- [ ] pip-audit, npm audit, and gitleaks run as **gating** CI jobs/steps in the D16 pipeline (G-SEC,
      G-MNT).
- [ ] gitleaks scans working tree **and** history.
- [ ] Accepted findings live in reviewed allowlists with justification/expiry; no blanket ignores.
- [ ] Each gate demonstrably bites (negative validation) and is reverted.
- [ ] Tool/action versions pinned; thresholds + triage documented.

## Workflow (P1-PLAN.md §3)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (sonnet) + `wf-quality-reviewer` (strong —
escalated: secret-scanning config is security-semantic)** in parallel → `wf-fixer` if findings →
`wf-verifier` → **one atomic commit**.

## Risks

- Over-broad allowlists silently re-open the gate — the justification/expiry convention + strong
  quality review are the guardrail.
- gitleaks over full history can be slow / noisy on first run — tune with a documented baseline
  allowlist rather than disabling history scanning.
