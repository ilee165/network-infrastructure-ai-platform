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

### Enforcement coupling (branch protection)

A red gate only blocks merge if branch protection actually requires it. To avoid an
orphan gate that is advisory-in-practice (a job with no `needs:` edge that a repo
admin must remember to add to the required-checks list), the workflow ends with a
single aggregator job, **`all-gates`**, that declares
`needs: [backend, frontend, security-scan, docker, infra]` and runs with
`if: always()`. It inspects every `needs.*.result` and **fails unless all are
`success`** — so a failed *or skipped* gate blocks it.

- **Branch protection must require exactly one check: `all-gates`.** Because it
  transitively depends on every gate, requiring it enforces all gates atomically;
  there is no per-job required-checks list to keep in sync.
- `security-scan` (gitleaks) additionally carries `needs: [backend, frontend]` so
  it is part of the graph rather than a free-floating parallel job — closing the
  gap where a gitleaks failure did not block merge unless branch protection had
  been manually updated.

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
- The gitleaks tarball download is **SHA-256-verified** before extraction
  (`echo "<sha256>  /tmp/gitleaks.tar.gz" | sha256sum -c -`). The expected digest
  (`5bc41815…e3ba` for `gitleaks_8.21.2_linux_x64.tar.gz`) is pinned in the workflow
  as a documented constant from the upstream
  `gitleaks_8.21.2_checksums.txt`, so a MITM/CDN substitution of the binary that
  would scan the repo's full history is caught before it ever runs — the
  supply-chain scanner is not itself a supply-chain vector. (The infra-job binary
  downloads — kubeconform/kube-linter/conftest — predate this commit and remain a
  tracked follow-up to pin the same way.)
- GitHub Actions are pinned to the repo's existing `@vN` convention
  (`actions/checkout@v7`, `actions/setup-node@v6`, `actions/setup-python@v6`).
- **Advisory-DB fetch:** pip-audit (OSV/PyPI) and npm audit (registry) fetch advisory
  data at run time. gitleaks is rule-based and fully offline. In an air-gapped
  self-hosted fork, point pip-audit at an internal index (`--index-url` / `PIP_*`),
  set `npm config set registry <mirror>`, and gitleaks needs no network.

## Dependency lockfiles + drift gate (P3 W0-T8)

Closes the P1 systemic TODO ("add a dep lockfile — drift bit twice"). The
`fastapi 0.137 include_router` break (P1) had root cause **no lockfile**: the
manifest declared a range, so a fresh resolve silently floated past the
route-flattening boundary. The resolved set is now pinned and CI fails on drift.

- **Backend — `backend/requirements.lock.txt`.** Hash-pinned, fully-resolved
  (121 packages) lockfile compiled from `pyproject.toml` (base + `dev` extra)
  with `uv pip compile --universal --generate-hashes`. `--universal` emits
  platform-marker lines (e.g. `colorama … ; sys_platform == 'win32'`) so the lock
  is **host-independent** — it recompiles byte-identically on the linux CI runner
  from the Windows authoring host. Pinned to **Python 3.12** to match the CI
  install. Determinism additionally requires a pinned **uv** (`UV_VERSION` in the
  `lockfile` CI job — currently `0.11.19`); bump uv and re-lock together. The lock
  is LF-pinned (`backend/.gitattributes`) so a Windows re-lock under
  `core.autocrlf=true` can't false-RED the gate on line-ending churn.
- **Frontend — `frontend/package-lock.json`.** npm's native lockfile; `npm ci`
  refuses to install when it is out of sync with `package.json` (it errors rather
  than mutate the lock), so an unlocked dependency change is already red.
- **CI gate — `lockfile` job** (required via `all-gates`). Re-resolves the backend
  manifest and asserts `git diff --exit-code requirements.lock.txt` is clean;
  runs `npm ci` + a lock-unchanged diff for the frontend. A manifest edit without
  a re-lock (or a hand-edited lock) is **RED**. The job carries an in-CI
  **negative control** that plants out-of-lock drift in a scratch copy and fails
  the job if the recompile+diff does *not* catch it — the gate is proven to bite
  on every run, not just at authoring time (L1).

**Re-lock procedure** (run in the same change as any dependency edit):

```bash
# backend (Python 3.12; uv pinned to the lockfile job's UV_VERSION):
cd backend && uv pip compile pyproject.toml --extra dev --universal \
  --generate-hashes --python-version 3.12 --output-file requirements.lock.txt
# frontend:
cd frontend && npm install            # rewrites package-lock.json
```

Scope note: W0-T8 locks the **current resolved set** — no version bumps. The
`fastapi>=0.136,<0.137` cap (route-introspection trap) stays in effect; lifting
it is a separate follow-up once the wiring tests traverse the nested router
structure (re-review 2026-09-23, see `backend/pyproject.toml`).

## Local validation (how these were proven to bite)

Each gate is validated two ways: (a) it PASSES on the current tree (clean, modulo the
reviewed allowlist), and (b) it BITES — exits non-zero — on a **planted negative**,
which is then reverted. Committed negative-validation fixtures (evidence-only; no CI
step consumes them) make this repeatable on any host:

| Gate | Planted-negative fixture | Repeatable check |
|------|--------------------------|------------------|
| **npm audit** | `frontend/scripts/__fixtures__/npm-audit-planted-vuln.json` (high GHSA not allowlisted) and `…/npm-audit-failed-run.json` (failed-audit error envelope) | `node frontend/scripts/npm-audit-gate.negative.mjs` |
| **pip-audit** | `backend/tests/fixtures/requirements-vuln-test.txt` (`jinja2==2.11.3`, known-vulnerable) | `pip-audit --strict -r backend/tests/fixtures/requirements-vuln-test.txt` |
| **gitleaks** | a realistic AWS key committed under a non-allowlisted path (throwaway commit) | `gitleaks detect --source . --config .gitleaks.toml --redact --exit-code 1` |
| **lockfile (backend)** | a tampered lock pin (`fastapi==0.0.0-PLANTED`) in a scratch copy | re-`uv pip compile` + `git diff --exit-code` → non-zero (in-CI negative-control step) |
| **lockfile (frontend)** | a dep added to `package.json` not present in the lock (scratch copy) | `npm ci` → `EUSAGE … not in sync` exit 1 |

**What was run on the authoring host (Windows + node v24, npm 11):**

```bash
# npm audit gate — PASS on the live tree with the reviewed allowlist:
cd frontend && npm audit --json | node scripts/npm-audit-gate.mjs        # exit 0
#   matched both allowlisted advisories (GHSA-2w69-…, GHSA-hmw2-…), no un-allowlisted high+.

# npm audit gate — BITES on both planted negatives (each exits 1), reverts cleanly:
node scripts/npm-audit-gate.negative.mjs                                 # exit 0 = all cases behaved
#   * planted high GHSA not in allowlist            -> gate exits 1 (vulnerable dep caught)
#   * failed-audit error envelope {"error":{...}}   -> gate exits 1 (NO false-green; see Req 4 fix)
#   * clean-modulo-allowlist report                 -> gate exits 0
```

The npm-audit gate hardening (reject an error envelope / a report missing
`auditReportVersion`+`vulnerabilities`) closes the false-green where a failed audit —
masked by CI's `npm audit --json … || true` — would otherwise PASS with zero advisories.

```bash
# lockfile drift gate (backend) — proven on the authoring host (uv 0.11.19, Python 3.12):
#  POSITIVE: in-place `uv pip compile … --output-file requirements.lock.txt` on a clean
#            scratch copy leaves NO `git diff` (recompile is byte-identical to committed) -> green.
#  NEGATIVE: planting `fastapi==0.0.0-PLANTED` in the lock then recompiling makes the diff
#            non-zero -> gate BITES. (This is exactly the in-CI negative-control step.)
#  Verified universal markers (colorama ; sys_platform == 'win32') + a Python-3.12 lock
#  install with --require-hashes succeeds and the include_router route-introspection tests
#  (tests/api/test_agents_rate_limit_wiring.py) pass against fastapi==0.136.3.
# lockfile drift gate (frontend) — `npm ci` on a scratch package.json with an extra dep
#  not in the lock exits 1 (EUSAGE "not in sync"); `npm ci` on the real tree is clean.
```

**Host caveat (L1):** the authoring host is Windows + Git-Bash with **uv 0.11.19**
and a uv-managed **Python 3.12.13**; CI runs the identical `uv pip compile` argv on
ubuntu with the same pinned uv/Python, and `--universal` makes the resolution
host-independent — so the locally-proven byte-identical recompile is the CI
behaviour. `pip`/`pip-compile` are not on the authoring host (uv is used instead);
the committed lock is pip-installable (`pip install --require-hashes -r
requirements.lock.txt`) and was install-verified via `uv pip install --require-hashes`.

**pip-audit and gitleaks are NOT installed on the authoring host** (no `pip` in the
local interpreter; no `gitleaks` binary), so their negatives are validated by the
**CI-equivalent** commands below against the committed fixtures. The gitleaks
planted-secret negative is performed on a throwaway commit (created, confirmed to trip
`aws-access-token`, then reverted) rather than left in history.

```bash
# pip-audit gate — BITES on the committed vulnerable-dep fixture (run in the backend env):
pip install "pip-audit==2.7.3"
pip-audit --strict --progress-spinner off -r backend/tests/fixtures/requirements-vuln-test.txt
#   -> reports known jinja2 2.11.3 advisories (e.g. GHSA-h5c8-rqwp-cp95 / CVE-2024-22195)
#      and EXITS NON-ZERO. Bumping the pin to jinja2>=3.1.6 makes the same command exit 0.
#      (the fixture is NOT installed by the app or any CI step.)
# pip-audit gate — PASS on the real resolved env (no fixture file):
pip-audit --strict --progress-spinner off   # + one --ignore-vuln per allowlist line

# gitleaks gate — PASS over working tree + full history with the allowlist:
gitleaks detect --source . --config .gitleaks.toml --redact --exit-code 1  # exit 0
#   negative (throwaway commit, reverted): a realistic (non-"EXAMPLE") AWS key committed
#   under backend/app/ (a non-allowlisted path) -> RuleID aws-access-token, exit 1.
#   control: default rules WITHOUT the allowlist flag the test-fixture sentinels,
#   confirming the path-scoped allowlist is doing real, scoped work.

# gitleaks binary install is checksum-pinned; verify it bites on a tampered tarball:
echo "<wrong-sha256>  /tmp/gitleaks.tar.gz" | sha256sum -c -            # exit 1 (mismatch caught)
```

## Related

- `deploy/kubernetes/.trivyignore` — the reviewed-suppression convention these
  allowlists mirror.
- `docs/security/2026-06-14-trivy-baseimage-cves.md` — image-CVE gate precedent.
- W6-T5 — image SBOM (syft) + cosign signing + admission verification (sibling task).
- `backend/requirements.lock.txt`, `frontend/package-lock.json`, `backend/.gitattributes`
  — the dependency lockfiles + LF pin asserted by the `lockfile` CI job (P3 W0-T8).
