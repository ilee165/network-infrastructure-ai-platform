# Wave 7 T4 — CI decomposition evidence

Date: 2026-07-16  
Implementation branch: `codex/wave7-t4`  
Baseline: `870e9353` (first Wave 7 delivery merged locally)

This file is the durable source for the T4 PR-body census and moved-gate bite
checklist required by [`WAVE7-PLAN.md`](WAVE7-PLAN.md). Live run URLs remain
pending until the branch is pushed and GitHub Actions is authorized to run the
planted-failure sequence.

## Entry gate and authoritative census

The fresh post-first-delivery baseline contained:

| Measure | Baseline |
|---|---:|
| `.github/workflows/ci.yml` physical lines | 2,903 |
| Runner jobs | 20 |
| `actions/checkout` uses | 19 |
| Python setup uses | 8 |
| Node setup uses | 3 |
| Jobs with service containers | 2 |
| Direct blocking needs in `all-gates` | 15 |

The remote entry-gate check listed only `main` and the historical
`refactor/review-wave6-frontend` branch; that historical branch has no
`.github/workflows/ci.yml` delta. No active local worktree other than T4 was
changing the workflow. A normal `git fetch` is currently obstructed by a stale
internal `refs/codex/turn-diffs/...` object, so remote heads were checked directly
with `git ls-remote` and the already-present branch objects.

## Implemented shape

The root caller is 1,362 physical lines. The called workflows are 449 lines
(`backend-gates.yml`), 305 (`drift-gates.yml`), and 778
(`platform-gates.yml`). All 20 original runner-job bodies remain present; a
YAML-semantic comparison found no changes outside the approved setup
substitutions and the two dependency rewires (`all-gates`, `docker-publish`).

| Root `all-gates` need | Gates represented |
|---|---|
| `backend-gates` | `backend`, `pg-integration`, `graph-integration`, `coverage-combined` |
| `frontend` | `frontend` |
| `security-scan` | `security-scan` |
| `docker` | `docker` |
| `platform-gates` | `infra`, `drill-bite-proofs`, `observability` |
| `kms-emulators` | `kms-emulators` |
| `packet-analysis-bite-proof` | `packet-analysis-bite-proof` |
| `drift-gates` | `lockfile`, `config-drift`, `contract-drift` |

The fresh census is preserved across the root and called workflows:
checkout ×19, Python composite ×8, Node composite ×3, tool composite ×5, and
service-container jobs ×2. The signal-only `kind-harness` and
`kind-harness-ha` jobs, advisory `pg-test-routing`, and conditional
`docker-publish` job retain their prior blocking semantics.

Reusable-workflow callers use only legal caller-job keys and explicitly narrow
permissions to `contents: read`. Each called workflow repeats the bounded-egress
environment because caller workflow-level `env` does not propagate. Every local
composite runs after checkout. The tool composite preserves pinned Helm and
installs checksum-verified promtool through the bounded acquisition helper.

The three render-twice guards now share:

- `ci/lib/render-twice-common.sh` for lifecycle, interpreter, non-empty render,
  and summary handling;
- `ci/lib/extract-rendered-secret.py` for metadata-scoped Secret extraction,
  strict `data` base64 decoding, and `stringData` extraction.

The former parallel extractors and standalone mTLS test step were removed. The
replacement bite proofs run in the normal blocking backend suite.

## Local verification

| Check | Result |
|---|---|
| Full backend merge-boundary suite | 4,005 passed, 95 skipped |
| Integrated T4 contract/mutation selection | 60 passed |
| Complete `backend/tests/scripts` suite on helper commit | 78 passed |
| Real CNPG render-twice guard | PASS |
| Real mTLS render-twice guard | PASS |
| Real Redis Sentinel render-twice guard | PASS |
| `actionlint` across all four workflows | PASS |
| Ruff check/format | PASS (594 files) |
| mypy | PASS (273 source files) |
| import-linter | PASS (9 contracts) |
| Frontend lint + typecheck | PASS (3 existing warnings, 0 errors) |
| Frontend Vitest | PASS (544 tests in 47 files) |
| Frontend production build | PASS |
| YAML-semantic preservation of original jobs | 20/20 |
| Independent review | Stale deleted-extractor CI step found, fixed in `874bf673`; re-review clean |

`graphify update .` is run after final local integration. None of these local
checks replaces the live GitHub Actions evidence below.

## Moved-gate live bite checklist

Each row requires a pushed planted-failure commit, its observed RED run URL, a
revert commit, and a final GREEN run at the exact final HEAD. Do not mark a row
complete from local structural tests alone.

| Moved gate | Planted failure | RED run | Revert SHA | Final GREEN run |
|---|---|---|---|---|
| `backend` | Add a failing assertion to `backend/tests/api/test_agents_rate_limit_wiring.py` | Pending push | Pending | Pending |
| `pg-integration` | Fail `test_store_then_load_round_trip_under_pg` | Pending push | Pending | Pending |
| `graph-integration` | Fail the manifested real-Redis Lua test | Pending push | Pending | Pending |
| `coverage-combined` | Raise `--fail-under=90` to `101` | Pending push | Pending | Pending |
| `lockfile` | Plant backend or frontend lock drift | Pending push | Pending | Pending |
| `config-drift` | Add a `Settings` field without regenerating `.env.example` | Pending push | Pending | Pending |
| `contract-drift` | Plant a generated TypeScript enum mismatch | Pending push | Pending | Pending |
| `infra` | Change HA CNPG `instances: 3` to `2` | Pending push | Pending | Pending |
| `drill-bite-proofs` | Change the PG failover negative control from `LOSE_LAST=1` to `0` | Pending push | Pending | Pending |
| `observability` | Raise the topology-lag alert threshold without updating its corpus | Pending push | Pending | Pending |

## Exit status

The T4 implementation and local gates are complete. The plan's final external
exit criterion remains open: all ten moved-gate RED proofs and one fully green
GitHub Actions run at final HEAD. This requires permission to push the branch
and run the temporary mutation/revert sequence.
