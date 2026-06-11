# Workflow cost playbook

Token/cost policy for orchestrated milestone builds, derived from measured M1
data (run `wf_a7368a4c-6a1`, June 2026). Complements `.claude/agents/README.md`
(role definitions and model tiers).

## What M1 measured

Per task (transcript volume, proportional to tokens):

| Role | Avg volume | Share of task |
|---|---|---|
| Implementer | ~290 KB | ~40% |
| Spec review + quality review (combined) | ~360 KB | ~45% |
| Fix + verify round (when triggered) | ~325 KB | rare |

- **5 of 6 early tasks had zero must-fix findings** — both reviewers approved
  immediately. The five mechanical gates (pytest, ruff check/format, mypy,
  import-linter) catch most defects before review ever runs.
- **Session-limit retries wasted ~9%**: agents killed mid-task re-run from
  scratch; an in-flight implementer loses everything not committed.
- RTK shell-output filtering is active inside subagents but immaterial
  (<1% of spend); the dominant burn is file reads and test output.

## Policy for next milestones (M2+)

Ranked by expected impact:

1. **Single combined reviewer for non-critical tasks** (~20% of milestone
   total). One sonnet reviewer covering both the spec checklist and the
   quality checklist replaces the dual pair. Keep **dual review, strong
   model** only for security-critical tasks (secret handling, auth, exposed
   APIs) and for any task whose implementer flagged uncertainty. The gate
   suite plus the fix-verify loop is the real quality floor; M1 data shows
   dual review on gate-green work is mostly redundant confirmation.
2. **Schedule long runs inside a fresh limit window** (~9%). Launch right
   after a session-limit reset, not before one. On a halt, resume promptly —
   `resumeFromRunId` replays completed agents free, but in-flight work is
   lost. Never stop a running workflow mid-implementer unless the edit is
   worth more than one implementer re-run (~250 KB).
3. **Batch sibling template tasks into one implementer call** (~5-8%).
   M1 ran cisco_iosxe and eos as separate full cycles; each re-read the same
   cisco_ios template. Group tasks that read the same context into one
   agent with one commit per sub-deliverable.
4. **Role-scoped prompt blocks** (small, free). Reviewers/fixers get a
   slimmed CANON: repo facts and severity rules only — not the TDD process,
   test-strategy, or dependency-freeze text that only implementers need.
5. **Diff-first reviews, targeted-test iteration, structured outputs** —
   already baked into `.claude/agents/` definitions; keep using `agentType`
   so they apply automatically.
6. **Optional, unproven**: haiku for `wf-verifier` on non-critical fix
   rounds (the narrowest role, ~105 KB observed); a hard token ceiling via
   the Workflow `budget` API when a turn sets one ("+500k" style directives).

## Standing mechanics

- Scripts select roles via `agentType` (see `.claude/agents/README.md`);
  escalate with `opts.model` per the security rule there.
- Keep (prompt, opts) byte-identical for executed calls when editing a
  halted workflow's script — the resume cache matches the longest unchanged
  prefix.
- Atomic commit per task is the unit of resumability: anything committed is
  never re-paid.
