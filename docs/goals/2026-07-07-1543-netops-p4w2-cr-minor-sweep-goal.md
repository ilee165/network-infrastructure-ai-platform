GOAL: Knock out the 9 deferred CodeRabbit test-hardening minors from PR #119's final review (CR5, CR7-12, CR14-15 — replied+deferred in the PR's resolved threads, tracked in memory `p4-build-progress.md`), each a genuine but low-risk test gap in the P4-W2 app-dependency-topology code, plus leave one durable tracked note for CR4 (the ApplicationsPage edit-PATCH lost-update — a design gap, not a test gap; do not implement optimistic concurrency, just document it). Headline: Hardened.

**PREFLIGHT — do this before anything else.** This sweep touches files that exist ONLY on `feat/p4-w2-app-dependency-topology` / PR #119 — NOT yet on `main`. Run `git log main --oneline -1 -- backend/app/api/v1/applications.py`. If empty (file absent from main), **STOP and report**: PR #119 (plus the separate `p4w2-impact-ip-reach` round holding its merge) must land on main first; do not branch off a stale main or invent the missing files. If present, proceed.

**Read first.** Repo root R = `D:/Multi-Agent workflow/network-infrastructure-ai-platform`.

- docs/goals/2026-07-07-1543-netops-p4w2-cr-minor-sweep-rider.md — the 9-item ledger with current anchors, one item per phase.
- PR #119 (github.com/ilee165/network-infrastructure-ai-platform/pull/119) resolved review threads — each item's original CodeRabbit finding + this project's disposition reply (already posted).
- The 9 target files (exact anchors + test names in the rider) — all under `backend/tests/` and `frontend/src/__tests__/`.
- docs/roadmap/p4-tasks/W2-T3-manual-application-tagging.md `## Risks` section — where the CR4 note goes.

**Posture.** New branch off `main` (post-merge), e.g. `fix/p4-w2-cr-minor-sweep`. Test-only changes — no production code edits except the one-line doc note for CR4 (no new backend/frontend behavior). No schema change, no new endpoints, no new UI. Each of the 9 items is independent — no shared state between phases; order doesn't matter beyond doc tidiness. No `git push` until told.

**Phases.** Nine content phases (one per CR item) + a CR4 doc-note phase + a close-out phase in the rider. Each: read the exact current anchor (line numbers may have shifted since PR #119 HEAD `685b248` — locate by function/test name if so) → write the named test → gates green → one conventional commit ending "(rider PN)".

**Verification.**
- Each new/modified test passes in isolation and the full relevant test file passes: `pytest <file> -v` in transcript per phase.
- Full backend + frontend suites green at the end: `pytest`, `ruff check .`, `ruff format --check .`, `mypy`, `lint-imports` (backend/, its .venv); `npm run test`, `npm run lint`, `npm run typecheck` (frontend/).
- `docs/roadmap/p4-tasks/W2-T3-manual-application-tagging.md` diff shows exactly the CR4 note added, nothing else.

**Stop when** all 9 CR items have a passing named test, the CR4 note is added, both full gate suites are green in the transcript, and every phase is committed — or stop after 20 turns and report what remains.
