# W1-T2 — Bare Celery dispatch sweep and static ratchet

| Field | Contract |
|---|---|
| Owner | `wf-implementer` |
| Depends on | W0-T5 / ADR-0059 |
| Review | sonnet spec + quality |
| Status | Proposed |

## Objective and scope

Inventory every Celery publication site, migrate it to the ADR-0059 hardened
wrapper without changing queue/routing semantics, and add a blocking AST gate.
Out: changing task business behavior or introducing new queues.

## Requirements and contracts

1. Record the before/after site inventory; any exception is path+symbol scoped,
   justified, and tested. Target is an empty allowlist.
2. The wrapper validates allowlisted task/queue pairs, redacts errors, and
   preserves countdown/ETA/idempotency identifiers needed by existing callers.
3. The checker rejects `.send_task`, direct `apply_async`, and `.delay` outside
   the wrapper/allowlist, including aliases, multiline calls, and nested paths.
4. CI invokes the checker in a blocking gate. A committed fixture plants each
   forbidden syntax and the negative-control test asserts non-zero.

## Test and gate plan

Start with checker fixtures that fail before implementation. Run checker unit
tests, all worker/task dispatch tests, import-linter, ruff, mypy, and full unit
suite. Mutation proof: remove one AST visitor branch and confirm its syntax
fixture fails. Keep the planted-call red evidence.

## Exit criteria

- [ ] Zero unjustified bare publication sites; routing behavior preserved.
- [ ] Blocking static gate catches syntax variants and its negative control bites.
- [ ] Site inventory and wrapper contract are documented.
- [ ] D16 passes; one atomic commit.
