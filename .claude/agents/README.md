# Workflow agent definitions

Reusable subagent roles for orchestrated build workflows (the Workflow tool's
`agent()` calls and the Agent tool). Each definition pre-assigns the model and
tool set, so workflow scripts select a role via `agentType` instead of
hand-tuning models per call.

Established 2026-06-11 during the M1 build (see the vault Decisions note,
"Model tiering in the M1 build workflow").

## Roles and model tiers

| agentType              | Model            | Tools      | Use for |
|------------------------|------------------|------------|---------|
| `wf-implementer`       | inherit (strong) | all        | Core/novel implementation: crypto, auth, transports, engines, APIs |
| `wf-implementer-light` | sonnet           | all        | Template-following work: a plugin mirroring a certified one, standard CRUD/UI |
| `wf-infra`             | inherit (strong) | all        | Infra/CI deliverables: K8s/Helm manifests, NetworkPolicy/PSS/admission, backup/DR jobs, CI supply-chain (SBOM, signing, dep/secret scan). Infra gates (helm lint, kubeconform, kube-linter/kubescape, conftest/OPA, trivy, cosign), not Python-TDD |
| `wf-eval-designer`     | inherit (strong) | all        | Evaluation for an AI-output deliverable: rubrics, reference datasets, deterministic CI evals + opt-in real-LLM manual gates (routing, RAG, grounded generation) |
| `wf-spec-reviewer`     | sonnet           | read-only* | Spec-compliance review of one committed task |
| `wf-quality-reviewer`  | sonnet           | read-only* | Correctness/security/convention review of one committed task |
| `wf-fixer`             | sonnet           | all        | Applying enumerated must-fix review findings |
| `wf-verifier`          | sonnet           | read-only* | Confirming a fix commit resolves its findings |

*read-only = Read, Grep, Glob, Bash (Bash for `git show` and targeted test
runs; the prompt forbids modification).

## Escalation rule

`opts.model` overrides the definition's model. For **security-critical tasks**
(credential vault, auth/RBAC, any endpoint or pipeline that touches secret
material, leak/exit-criteria tests), escalate every role to the strong model:

```js
agent(prompt, { agentType: 'wf-spec-reviewer', model: 'fable', label, phase, schema })
```

Nothing in a secret-handling pipeline runs on a downgraded model.

## Why sonnet reviews don't degrade quality

Reviews check a focused diff against a written spec, and they sit behind hard
mechanical gates (pytest, ruff check, ruff format, mypy, import-linter) that
the implementer must pass before committing. Dual independent review plus those
gates backstops the cheaper reviewer; the strong model is reserved for the
roles that design and write code.

## Token-economy checklist for launching workflows

1. **Tier the models** per the table above; escalate only by the rule above.
2. **Keep per-call prompts to task facts only** — repo paths, branch, gates,
   the task spec, fixed design decisions. Role discipline (TDD, atomic commit,
   review method, severity scale) lives in these definitions; do not duplicate
   it into prompts.
3. **Diff-first reviews** — reviewers run `git show <commit>`, never re-run the
   full gate suite the implementer already passed.
4. **Targeted tests while iterating** — implementers run their own test file
   during TDD and the full gates exactly once before the commit.
5. **Structured output everywhere** — pass a `schema` so results come back as
   validated data, not prose to re-parse.
6. **Atomic commits per task + `resumeFromRunId`** — restarts replay completed
   agents from cache. Keep (prompt, opts) byte-identical for completed calls;
   never retro-edit a running workflow's already-executed calls.
7. **Sequential tasks that share files; parallel only within a task** (the two
   reviews) — avoids merge churn that burns fixer tokens.
8. **Graph-first code location** — when `graphify-out/graph.json` exists at the
   repo root, `graphify query "<question>"` returns a scoped subgraph that is
   cheaper than broad Grep sweeps; `graphify path "<A>" "<B>"` maps cross-file
   impact. The graph is a derived index: verify in source before editing, and
   run `graphify update .` after commits to keep it current. Absent graph =
   normal Grep/Read behavior (the file's existence is the feature flag).

## Maintenance

These definitions are deliberately repo-light: canonical facts (paths, gates,
branch rules) belong in the workflow script's prompt block, so the definitions
survive repo restructuring. Update the model tiers here when model lineups
change; update the escalation list when new secret-handling surfaces appear.
