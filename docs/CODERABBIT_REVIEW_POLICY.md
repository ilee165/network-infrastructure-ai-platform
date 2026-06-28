# CodeRabbit PR Review Policy

This document defines how CodeRabbit is used to review pull requests in this
repository, the boundaries of its authority, and how to handle out-of-scope
review comments. It is the human-readable companion to `.coderabbit.yaml`, which
machine-enforces the same contract.

## Authority model

| Role | Authority |
| --- | --- |
| **Claude Code** | **Implementation authority.** Owns design, architecture, module boundaries, refactors, naming, formatting, and documentation. |
| **CodeRabbit** | **Advisory reviewer.** Bounded to four domains. Never gates merge. Never co-authors. |

CodeRabbit catches defects the author may have missed. It does not redesign,
restyle, or rename. Implementation decisions are not up for re-litigation in
review.

## CodeRabbit authority — in scope

CodeRabbit may comment **only** on:

- ✅ **Correctness** — logic errors, unhandled edge cases, broken control flow,
  race conditions, incorrect API usage, data corruption, null/None handling.
- ✅ **Security** — injection, authn/authz flaws, secret/credential leakage,
  unsafe deserialization, SSRF/path traversal, missing trust-boundary
  validation, audit-trail gaps, weaknesses in the ChangeRequest/four-eyes flow.
- ✅ **Test gaps** — untested code paths, missing failure-case tests, assertions
  that don't verify the claimed behavior, tests that pass regardless of the
  code under test.
- ✅ **Performance regressions** — new N+1 queries, unbounded memory growth,
  accidental O(n²)+ on hot paths, blocking I/O in async paths, missing
  pagination/streaming.

Each in-scope comment must name its domain and describe a **concrete,
demonstrable failure** (input → wrong outcome), not a preference.

## CodeRabbit forbidden — out of scope

CodeRabbit must **not** comment on:

- ❌ Architecture changes or alternative designs
- ❌ Refactors or "cleaner way to write this"
- ❌ Style / formatting (ruff and eslint own this)
- ❌ Naming of variables, functions, files, or modules
- ❌ Documentation rewrites or wording
- ❌ Speculative / "you might also want to" improvements

## Rejection protocol

Reject any review comment that falls outside the four in-scope domains.

1. **Identify scope.** If a comment is not clearly correctness, security, a test
   gap, or a performance regression, it is out of scope.
2. **Reject, don't debate.** Resolve the thread without changing code. A short
   note is sufficient:

   > Out of scope per `docs/CODERABBIT_REVIEW_POLICY.md` (advisory review is
   > limited to correctness, security, test gaps, performance regressions).

3. **Borderline cases.** If a comment is framed as style/naming but points at a
   real correctness or security failure, treat it as in scope and act on the
   underlying defect — not the cosmetic wrapper.
4. **No merge gating.** CodeRabbit is configured with
   `request_changes_workflow: false`; it cannot block a merge. A green human
   review plus passing CI gates remain the merge requirements.

## Configuration

The contract above is enforced in `.coderabbit.yaml`:

- `tone_instructions` — short global steer (250-char limit).
- `reviews.profile: chill` — suppresses nitpick/opinion comments.
- `reviews.path_instructions` — the full authority model applied to every file,
  with sharpened guidance on `backend/app/security/**` and `**/tests/**`.
- `reviews.request_changes_workflow: false` — advisory only.

To change the policy, edit both files together so the machine-enforced config
and this document stay in sync.
