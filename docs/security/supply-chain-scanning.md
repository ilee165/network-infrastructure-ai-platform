# Supply-chain scanning — dependency + secret gates (CI)

**Task:** P1 W6-T4 · **Pipeline:** `.github/workflows/ci.yml` (D16 / ADR-0016)
**Posture refs:** PRODUCTION.md §5 (dependency + secret scanning), §11 G-SEC / G-MNT;
ADR-0011 §6 (no-secret posture); ADR-0016 §5 (pinned, deterministic CI).

This note documents the three supply-chain gates added to the D16
`lint → typecheck → test → build → scan` pipeline, their severity thresholds, the
reviewed-allowlist policy, and how to triage a finding. Image SBOM (syft) + cosign
signing + admission verification are the sibling task **W6-T5** and are out of scope
here — this task scans the *repository and its dependencies*.

## Gates at a glance

| Gate | Where (job · step) | Scope | Fail threshold | Allowlist |
|------|--------------------|-------|----------------|-----------|
| **pip-audit** | `backend` · "Dependency audit (pip-audit)" | resolved backend env (`pip install -e ./backend[dev]`) vs OSV/PyPI advisories | any known-vulnerable dep (`--strict`) | `backend/.pip-audit-allowlist.txt` (`--ignore-vuln` per line) |
| **npm audit** | `frontend` · "Dependency audit (npm audit)" | `frontend/package-lock.json` (prod + dev) | `high`+ (aligned with Trivy `CRITICAL,HIGH`) | `frontend/.npm-audit-allowlist.json` (via `scripts/npm-audit-gate.mjs`) |
| **gitleaks** | `security-scan` · "gitleaks detect" | working tree **+ full git history** | any secret finding | `.gitleaks.toml` `[allowlist]` (path-scoped) |

All three are **RED gates**: a finding fails the run. None is advisory.

## Why history, not just HEAD (gitleaks)

A secret committed in an earlier commit and later removed is still recoverable from
git history and must be treated as exposed. The `security-scan` job therefore checks
out **full history** (`actions/checkout` with `fetch-depth: 0`) and runs
`gitleaks detect` (the history-walking mode — *not* `--no-git`, which would scan only
the working tree). `--redact` keeps any matched secret out of the CI log (ADR-0011 §6).

Local validation scanned all 1585 commits of history clean (0 leaks) with the
reviewed allowlist.

## Thresholds

- **pip-audit** — fail on *any* advisory for an installed backend distribution
  (`--strict` also fails if a dependency cannot be resolved/audited rather than
  skipping it silently). Accepted advisories are suppressed only via the reviewed
  allowlist below.
- **npm audit** — fail on **`high` and above**. This matches the Trivy image/IaC
  posture (`severity: CRITICAL,HIGH`) and ADR-0016's "raise to HIGH,CRITICAL at
  production release". `low`/`moderate` advisories are reported by `npm audit` but do
  not gate. The floor lives in `frontend/.npm-audit-allowlist.json` (`severityFloor`).
- **gitleaks** — any finding fails; there is no severity dimension for secrets.

## Allowlist policy (reviewed, never blanket)

Every accepted finding is an explicit entry with a **justification** and, where the
tool supports it, an **expiry / re-review date**. This mirrors the reviewed
`deploy/kubernetes/.trivyignore` convention already in the pipeline. We never disable
a rule globally and never allowlist by a broad secret-shaped regex (that would also
mask a *real* planted secret).

- **`backend/.pip-audit-allowlist.txt`** — one advisory ID (`PYSEC-`/`GHSA-`/`CVE-`)
  per line; the comment carries the justification + re-review date. The CI step turns
  each line into a `--ignore-vuln` flag. Currently **empty** (no accepted vulns).
- **`frontend/.npm-audit-allowlist.json`** — `{ ghsa, package, severity,
  justification, expires }` per accepted advisory. `scripts/npm-audit-gate.mjs`
  enforces it and **fails the gate** if an entry is **expired** *or* **stale**
  (matches no current advisory) — so the allowlist cannot silently rot open. Two
  entries are currently accepted (react-router XSS pending an in-range dep bump;
  dev-only form-data CRLF), each expiring 2026-09-30.
- **`.gitleaks.toml`** — `extend.useDefault = true` (inherits the full upstream rule
  set) plus a `[allowlist]` with **path-scoped** allowances only: the unit-test trees
  (`backend/tests/`, `frontend/src/__tests__/`) which hold obviously-fake credential
  sentinels, the generated `frontend/package-lock.json` (integrity hashes trip the
  high-entropy detector), and this config file itself. A real secret in
  application / deploy / CI code outside those paths still fails.

### Adding an allowlist entry

1. Confirm the finding is a genuine false positive or an accepted, time-boxed risk
   (with a tracked remediation). Do **not** allowlist a real, reachable secret —
   rotate it and purge it from history.
2. Add the narrowest possible entry (specific advisory ID / specific path), with a
   justification and a re-review date.
3. Re-run the gate locally (see below) to confirm it passes *and* still bites on a
   planted negative.

## Triaging a finding

**pip-audit / npm audit (vulnerable dependency):**
1. Identify the package, the advisory (GHSA/PYSEC/CVE), and whether it is a direct or
   transitive dep and prod- vs dev-only.
2. Prefer a **fix**: bump the dependency past the fixed version. If the fix is in
   range, do it (in the owning dependency task — not as a drive-by here).
3. If no fix exists, or the fix is blocked by a pinned transitive / out-of-range
   bump, add a **time-boxed allowlist entry** with the justification and the tracking
   reference, then schedule the bump.

**gitleaks (secret finding):**
1. Determine if it is **real**. If yes: treat as an incident — **rotate the
   credential immediately**, then purge it from history (`git filter-repo` /
   BFG) and force-update. The allowlist is NOT the remedy for a real secret.
2. If it is a **false positive** (test fixture, example value), add the narrowest
   path-scoped allowlist entry to `.gitleaks.toml`.

## Determinism, pinning, offline / self-hosted fork

- Tool versions are **pinned**: `pip-audit==2.7.3`; the `gitleaks` binary is installed
  by pinned `v8.21.2` via direct release download (same pattern as the infra job's
  kubeconform/kube-linter/conftest), not the marketplace action — so the scan is not
  itself a supply-chain risk (ADR-0016 §5) and no marketplace license key is needed.
- GitHub Actions are pinned to the repo's existing `@vN` convention
  (`actions/checkout@v7`, `actions/setup-node@v6`, `actions/setup-python@v6`).
- **Advisory-DB fetch:** pip-audit (OSV/PyPI) and npm audit (registry) fetch advisory
  data at run time. gitleaks is rule-based and fully offline. In an air-gapped
  self-hosted fork, point pip-audit at an internal index (`--index-url` / `PIP_*`),
  set `npm config set registry <mirror>`, and gitleaks needs no network.

## Local validation (how these were proven to bite)

`npm` and a pinned `gitleaks` binary run on a developer host; `pip-audit` could not be
run on the authoring host (no `pip` in the local interpreter) and was validated via the
CI-equivalent command.

```bash
# npm audit gate — PASS on the clean tree with the reviewed allowlist:
cd frontend && npm audit --json | node scripts/npm-audit-gate.mjs        # exit 0
#   negatives (each exits 1): drop an allowlist entry / expire an entry /
#   inject a new high advisory into the JSON stream -> gate fails. (reverted)

# gitleaks gate — PASS over working tree + full history with the allowlist:
gitleaks detect --source . --config .gitleaks.toml --redact --exit-code 1  # exit 0
#   negative: a realistic (non-"EXAMPLE") AWS key committed under backend/app/
#   (a non-allowlisted path) -> RuleID aws-access-token, exit 1. (reverted)
#   control: default rules without the allowlist flag the test-fixture sentinels,
#   confirming the path-scoped allowlist is doing real, scoped work.

# pip-audit gate — CI-equivalent (run inside the backend job environment):
pip install "pip-audit==2.7.3"
pip-audit --strict --progress-spinner off   # + one --ignore-vuln per allowlist line
```

## Related

- `deploy/kubernetes/.trivyignore` — the reviewed-suppression convention these
  allowlists mirror.
- `docs/security/2026-06-14-trivy-baseimage-cves.md` — image-CVE gate precedent.
- W6-T5 — image SBOM (syft) + cosign signing + admission verification (sibling task).
