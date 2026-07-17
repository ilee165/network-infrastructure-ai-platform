# Wave 7 T4 — CI decomposition evidence

Date: 2026-07-16

Implementation branch: `codex/wave7-t4`

Baseline: `870e9353` (first Wave 7 delivery merged locally)

This file is the durable source for the T4 PR-body census and moved-gate bite
checklist required by [`WAVE7-PLAN.md`](WAVE7-PLAN.md). The planted-failure
sequence was executed on GitHub Actions on 2026-07-17; all ten rows below carry
their live RED/revert/GREEN evidence.

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

Counts below are from the original T4 delivery; at the final HEAD (after the
post-review remediation and CodeRabbit-fix commits) the CI `backend` job runs
4,016 passed / 95 skipped and ruff-clean remains 594 files — see the final
green run linked in the checklist.

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

Executed 2026-07-17 in two waves (nine independent gates batched in one planted
commit; `coverage-combined` proven separately because it is *skipped*, not
failed, while its `needs` are red). Run links:
[RED-9] = [run 29583197881](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29583197881)
at plants+gate-fix HEAD `1238420`;
[RED-cov] = [run 29585639966](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29585639966)
at HEAD `7aba01a`;
[GREEN] = [run 29586966846](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29586966846)
at the final gate-relevant HEAD `853ee95` (later commits are docs-only and CI
path-ignores `docs/**`). Reverts: `0296883` (nine plants), `4bc4205` + `853ee95`
(coverage plants).

| Moved gate | Planted failure (as executed) | RED run | Revert SHA | Final GREEN run |
|---|---|---|---|---|
| `backend` | Inverted an assertion in `backend/tests/api/test_agents_rate_limit_wiring.py` | [RED-9] — `Test (pytest + coverage)` | `0296883` | [GREEN] |
| `pg-integration` | Inverted `test_store_then_load_round_trip_under_pg` round-trip assertion | [RED-9] — `PG test layer — RED gate` | `0296883` | [GREEN] |
| `graph-integration` | Inverted an assertion in the manifested real-Redis Lua test | [RED-9] — `Exact graph integration layer — RED gate` | `0296883` | [GREEN] |
| `coverage-combined` | Raised `--fail-under=90` to `101` (consistently: workflow + contract-test expectation + mutation anchor — see note 2) | [RED-cov] — `Combine coverage and enforce headline floor` (combined TOTAL 90%; coverage exits non-zero on the planted floor) | `4bc4205` + `853ee95` | [GREEN] |
| `lockfile` | Hand-edited backend lock: re-pinned `annotated-types` 0.7.0 → 0.6.0 keeping the 0.7.0 hashes | [RED-9] — backend lockfile RED-gate step, hash-verification layer (see note 1) | `0296883` | [GREEN] |
| `config-drift` | Added a `Settings` field without regenerating `.env.example` | [RED-9] — `.env.example in sync with Settings — RED gate` | `0296883` | [GREEN] |
| `contract-drift` | Widened a generated TS enum union (`AgentSessionStatus`) out of sync with the OpenAPI spec | [RED-9] — `Generated TS types in sync — RED gate` | `0296883` | [GREEN] |
| `infra` | Changed CNPG `instances: 3` to `2` in `values.yaml` | [RED-9] — `Render + validate CloudNativePG HA tier (ADR-0042)` | `0296883` | [GREEN] |
| `drill-bite-proofs` | Changed the PG failover negative control `LOSE_LAST=1` to `0` | [RED-9] — `W4-T3 failover drill negative-control bite proof` | `0296883` | [GREEN] |
| `observability` | Raised the topology-lag fast-window threshold `300` → `30000` without updating its corpus | [RED-9] — `promtool test rules` | `0296883` | [GREEN] |

### Findings from the proof execution

1. **The lockfile proof found and fixed a real gate false-green.** The first
   planted-failure run
   ([run 29581672390](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29581672390),
   HEAD `4d7ea77`) turned eight of nine gates RED but `lockfile` stayed GREEN:
   `uv pip compile` reads the existing lock as *preferences* and reproduced the
   hand-edited, still-resolvable pin byte-for-byte, and the job's negative
   control was vacuous (it diffed against a differently-named scratch compile,
   whose uv autogeneration header always differs). Fix `1238420` adds a
   `pip install --dry-run --require-hashes` artifact-verification layer to the
   real gate and replaces the control with two non-vacuous ones exercising the
   gate's own mechanisms; the RED-9 run then caught the plant in the hash layer
   ("THESE PACKAGES DO NOT MATCH THE HASHES", non-transient, no retries). The
   tampered lock was also independently caught downstream by the `docker` image
   build (`pip --require-hashes` from the lock) in both planted runs.
2. **The coverage floor is double-guarded.** The first coverage attempt raised
   only the workflow floor
   ([run 29584340012](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29584340012),
   HEAD `4df6ebb`): `test_repository_coverage_contract` failed the `backend`
   job on the tampered floor, skipping `coverage-combined` via its `needs`
   edge — bonus proof that the floor cannot be changed in the workflow alone.
   The recorded [RED-cov] proof therefore raises the floor consistently in all
   three places so the producers stay green and the combined enforcement step
   itself goes RED.

## Exit status

The T4 exit criterion is met: all ten moved-gate RED proofs are recorded above
with pushed planted-failure commits, observed RED runs, revert SHAs, and the
fully green run at the final gate-relevant HEAD `853ee95`
([run 29586966846](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29586966846)),
whose only delta versus the prior green HEAD `348c34a` is the permanent
lockfile-gate fix `1238420` (whose two new negative controls ran and passed in
that green run). Remaining PR work is outside T4 scope: refresh the PR body and
mark the PR ready for review.
