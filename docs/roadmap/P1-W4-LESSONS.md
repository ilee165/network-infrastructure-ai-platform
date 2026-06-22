# P1 W4 — Lessons Learned (Helm/K8s GA chart)

Retro for the W4 wave (PR #59, squash `cc822b5`). Captured for the W5/W6 executors
(`docs/roadmap/p1-tasks/`) — these are concrete, repo-specific traps that already
cost a CI red and a review round in W4. Read before touching infra/CI tasks.

Each lesson: **what bit us → why → the rule for next time → who it hits next.**

---

## L1 — Run a NEW gating CI tool LOCALLY before you push it

**Bit us:** W4-T6 flipped the Trivy `config` scan from non-gating (exit-code 0) to
gating (exit-code 1). It passed every local gate (helm/kubeconform/kube-linter/conftest)
but went RED in CI on 3 HIGH misconfigs — because `trivy` is not installed on the
build box and was never run locally. First push → infra job FAILURE.

**Why:** local gate set ≠ CI gate set. A gate you add but cannot execute locally is
unverified until CI runs it.

**Rule:** before pushing a step that makes a tool *gating*, run that exact tool
locally — install it, or run it in a throwaway container
(`docker run --rm -v "$PWD:/w" -w /w aquasec/trivy:latest config ...`). If you truly
cannot, say so in the PR and expect a CI iteration.

**Hits next:** **W6-T4** (pip-audit / npm audit / gitleaks) and **W6-T5** (syft SBOM +
cosign verify + Trivy gate *raise*) both ADD/raise gating CI steps. Highest repeat risk.

## L2 — Sanctioned deviations: scoped-suppress the generic scanner, keep conftest as the source of truth

**Bit us:** Trivy flagged KSV-0014/0118 (seccomp-installer must run root with a writable
hostPath to seed the kubelet seccomp dir) and KSV-0119 (packet-capture NET_RAW) — all
INTENTIONAL ADR-0031 deviations, not risk.

**Why:** generic IaC scanners cannot encode ADR exceptions. conftest (policy-as-test) can
— it asserts the deviation is present **only** on the sanctioned workload and that every
other workload stays subject to the hardened rule.

**Rule:** suppress the generic finding in a **scoped** ignore file with a written
justification (`deploy/kubernetes/.trivyignore`, wired via `TRIVY_IGNOREFILE` env on the
specific scan step — NOT globally), and back every suppression with a stronger conftest
rule. Never weaken the gate to go green; narrow it.

**Hits next:** **W6-T5** RAISES the Trivy gate. Extend `.trivyignore` + conftest in
lockstep; do not drop the existing suppressions or globalize them onto image CVE scans.

## L3 — Exec-probe / job argv does NOT do `$(VAR)` substitution — wrap in `sh -c`

**Bit us:** postgres StatefulSet used `pg_isready -U $(POSTGRES_USER) -d $(POSTGRES_DB)`
as an exec-probe `command`. Kubernetes only substitutes `$(VAR)` in container
`command`/`args`, not in probe exec argv — so the literal `$(POSTGRES_USER)` was passed.
(redis already wrapped it in `sh -c`; postgres didn't mirror the sibling — CodeRabbit Critical.)

**Rule:** any exec probe or Job command that needs an env var → `["sh","-c","tool \"$VAR\""]`.
When fixing one manifest, grep the sibling family for the same pattern.

**Hits next:** **W5** backup/restore CronJobs (pgBackRest, `psql`, neo4j-admin) run shell
with credential/DB-name env vars and exec probes — same trap.

## L4 — Helm-generated dev secrets must be idempotent (`lookup`), or `helm upgrade` breaks auth

**Bit us:** the dev `secret.yaml` regenerated every value with `randAlphaNum` on each
render. On `helm upgrade` of an already-initialized stack the new password no longer
matched the credential baked into the data store at first init → silent auth break
(CodeRabbit Major).

**Rule:** reuse-or-generate via `lookup` — `lookup` returns the installed Secret on a
live upgrade (reuse), and empty during `helm template`/CI (fresh placeholder, gates
unaffected). First install generates; upgrades preserve.

**Hits next:** **W6** KMS dev secrets, **W5** any chart-rendered backup credential.

## L5 — A shell pipe in CI masks the upstream exit code — `set -o pipefail` + `test -s`

**Bit us:** `helm template ... | tr -d '\r' > rendered.yaml` returns `tr`'s exit 0, so a
`helm template` failure would pass the render step (false-green gate; CodeRabbit Major).

**Rule:** any `cmd | filter > file` step in CI or a job → `set -o pipefail` and assert the
output (`test -s file`). Especially for render/dump/pipe-to-store steps.

**Hits next:** **W5** backup scripts (`pg_dump | gzip | mc pipe`, restore-drill pipelines)
and any W5/W6 CI step that pipes into a file or object store.

---

## Process / orchestration lessons

## L6 — `gh pr merge` prints a local-checkout fatal under sibling worktrees, but the REMOTE squash still lands

**Saw:** `gh pr merge 59 --squash --delete-branch` →
`fatal: 'main' is already used by worktree at .../curator-overbid`. The remote squash
**succeeded** anyway; only the local post-merge checkout/branch-delete failed.

**Rule:** after that error, verify with `gh pr view <n> --json state,mergeCommit` (expect
`MERGED`), then delete the remote branch manually: `git push origin --delete <branch>`.
Don't re-run the merge.

## L7 — A 6-task chart wave ≈ 2 session windows; atomic per-task commits are what make that survivable

**Saw:** the W4 workflow hit the session limit mid-T4 (~22 agents / 955k tokens). Because
every task commits atomically, T1–T3 survived; the run resumed via
`Workflow({scriptPath, resumeFromRunId})` — T1–T3 replayed from cache, T4–T6 ran fresh.

**Rule:** keep one-atomic-commit-per-task. On resume, discard any half-done uncommitted
work from the killed task (it was never reviewed) and let the resumed run redo it cleanly.

## L8 — Verify the agent registry before launching a workflow

**Saw:** `wf-infra` existed on disk (`.claude/agents/wf-infra.md`) but was NOT loaded into
the runtime registry at session start — the workflow died at the first `agent()` call.
Substituted `wf-implementer` (the infra discipline was already encoded in the task brief).
`wf-infra` loaded later mid-session.

**Rule:** before a workflow launch, confirm every `agentType` it calls is in the live
registry. If a custom agent is missing, substitute a generally-available one and fold its
discipline into the prompt rather than letting the run fail.
