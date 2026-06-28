# Summary

<!-- What does this PR change and why? Link the milestone (M0-M5) and any issues. -->

## Type of change

- [ ] Feature
- [ ] Bug fix
- [ ] Refactor
- [ ] Documentation only
- [ ] CI / build / deployment

## Development standards checklist (CLAUDE.md)

Every feature must include tests, documentation, and API documentation; architecture
changes require an ADR; security is reviewed on every change.

- [ ] **Tests** — unit tests added/updated under `backend/tests/` (mirroring `app/`)
      or as colocated vitest files in `frontend/`; unit tests pass without
      Postgres/Neo4j/Redis/network.
- [ ] **Documentation** — `docs/` and/or `README.md` updated for any behavior,
      structure, or operational change.
- [ ] **API documentation** — OpenAPI surface (router docstrings, Pydantic schemas,
      response models) updated for any `/api/v1` change, or N/A.
- [ ] **Security review** — secrets handling, authn/z, audit coverage, and input
      validation considered; no credentials or secrets in code, fixtures, or logs.
- [ ] **ADR** — added/updated in `docs/adr/` if this changes architecture
      (decisions D1-D16, module boundaries, new vendors/agents/capabilities), or N/A.

## Quality gates (run locally before requesting review)

- [ ] Backend: `ruff check .`, `ruff format --check .`, `mypy`, `lint-imports`,
      `pytest` (from `backend/`)
- [ ] Frontend: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`
      (from `frontend/`)
- [ ] Module-boundary rules respected (`docs/architecture/REPO-STRUCTURE.md` section 3)

## Review scope (CodeRabbit)

CodeRabbit is an advisory reviewer scoped to **correctness, security, test gaps,
and performance regressions** only. Comments on architecture, refactors, style,
naming, documentation, or speculative improvements are out of scope and are
rejected per [`docs/CODERABBIT_REVIEW_POLICY.md`](../docs/CODERABBIT_REVIEW_POLICY.md).

## Security notes

<!-- Findings from the security review above, or "none". State-changing behavior
     must go through the ChangeRequest approval flow (D11) - call out anything
     that touches it. -->

## Screenshots / output

<!-- UI changes: before/after screenshots. CLI/API changes: example output. Optional. -->
