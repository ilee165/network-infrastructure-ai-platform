# P4 W4 Evaluation Evidence Ledger

| | |
|---|---|
| **Scope** | W4-T1 vendor/plugin conformance and routing; W4-T2 application-dependency derivation; W4-T3 report conformance and redaction |
| **Final revalidation lifecycle/status (W4-T4 only)** | **PENDING — T4 has not revalidated all three landed suites at one final release HEAD** |

This ledger is seeded by W4-T0A and intentionally makes no green, passing, or
bite-proof claim. T1, T2, and T3 are logically independent, but execute
sequentially on the shared branch because they write this file. Each task may
fill only its named section below with evidence available before its atomic
commit: task status, focused commands/results, bite test node IDs, and the
blocking-CI collection path. A task cannot record the SHA of the commit that
will contain its own section. W4-T4 alone owns the top-level lifecycle/status,
the landed task commit SHAs, the single final release HEAD, and the final
blocking run/job results after all three implementations land; it must not
rewrite the task-owned sections.

## W4-T1 — Vendor/plugin conformance and routing

**Section owner:** W4-T1 only

| Evidence field | T1 value |
|---|---|
| Task status | **PASS (task-local)** — the pinned P3 10-vendor matrix is preserved; `f5_bigip` and `vmware` are the only P4 vendor additions; the routing roster and per-agent allow-lists remain the recorded nine-agent P3 baseline. Final release-HEAD revalidation remains T4-owned. |
| Focused verification command(s) | `cd backend && .venv/bin/pytest tests/plugins/test_conformance.py tests/plugins/test_*_conformance.py tests/agents/eval/test_p4_vendor_conformance.py tests/agents/eval/test_m3_exit_criteria.py tests/agents/eval/test_p3_routing_no_regression.py -q`; `cd backend && .venv/bin/pytest --collect-only -q tests/agents/eval/test_p4_vendor_conformance.py`; `cd backend && .venv/bin/pytest tests/agents/eval/test_p4_vendor_conformance.py::test_vendor_conformance_module_substitution_is_rejected tests/agents/eval/test_p4_vendor_conformance.py::test_missing_vmware_interface_spec_is_rejected -q` |
| Focused verification result(s) | `512 passed in 4.62s`; `10 tests collected in 0.06s`; bite nodes `2 passed in 0.09s`. Vendor delta: exactly `f5_bigip` + `vmware`; routing delta: none. |
| Bite test node IDs | `tests/agents/eval/test_p4_vendor_conformance.py::test_vendor_conformance_module_substitution_is_rejected`; `tests/agents/eval/test_p4_vendor_conformance.py::test_missing_vmware_interface_spec_is_rejected` |
| Blocking-CI collection path (workflow/job/selector) | `.github/workflows/ci.yml` → `backend-gates` reusable workflow → `.github/workflows/backend-gates.yml` job `backend`, step `Test (pytest + coverage)` → unfiltered `pytest -n 4 --cov=app --cov-report=term -q`, which collects `tests/agents/eval/test_p4_vendor_conformance.py`. |

## W4-T2 — Application-dependency derivation

**Section owner:** W4-T2 only

| Evidence field | T2 value |
|---|---|
| Task status | **PASS (task-local)** — the independently authored estate/expected graph scores exact endpoint precision `1.0`, recall `1.0`, and full canonical equality; all four source suppressions and the valid planted wrong edge are rejected inside green. PostgreSQL/Neo4j execution remains blocking-CI and final release-HEAD revalidation remains T4-owned. |
| Focused verification command(s) | `cd backend && .venv/bin/pytest tests/agents/eval/test_app_derivation_eval.py -q`; `cd backend && .venv/bin/pytest tests/pg/test_app_derivation_eval_pg.py tests/integration/test_app_derivation_eval_graph.py -q`; `cd backend && .venv/bin/pytest tests/engines/topology/test_app_derivation.py tests/engines/topology/test_app_derivation_store.py tests/engines/topology/test_applications_layer.py tests/knowledge/test_topology_impact.py -m 'not integration' -q`; exact graph collection plus `ci/scripts/check-graph-integration-selection.py`; touched-test Ruff/format/mypy. |
| Focused verification result(s) | Corpus `17 passed in 0.09s`; adjacent derivation/impact `54 passed, 6 deselected in 2.95s`; local real-store nodes `2 skipped in 0.03s` because the explicit test stores are unavailable; graph manifest guard `13 exact collected nodes`; Ruff/format and touched-test mypy green. |
| Bite test node IDs | `tests/agents/eval/test_app_derivation_eval.py::test_planted_wrong_edge_rejects_the_real_corpus_precision_gate`; `tests/agents/eval/test_app_derivation_eval.py::test_suppressing_each_estate_input_source_rejects_recall[f5]`; `tests/agents/eval/test_app_derivation_eval.py::test_suppressing_each_estate_input_source_rejects_recall[vmware]`; `tests/agents/eval/test_app_derivation_eval.py::test_suppressing_each_estate_input_source_rejects_recall[dns]`; `tests/agents/eval/test_app_derivation_eval.py::test_suppressing_each_estate_input_source_rejects_recall[manual]`; `tests/agents/eval/test_app_derivation_eval.py::test_real_corpus_provenance_mutation_is_rejected_with_perfect_endpoints` |
| Blocking-CI collection path (workflow/job/selector) | Unit corpus: `.github/workflows/ci.yml` → `backend-gates` → `.github/workflows/backend-gates.yml` job `backend`, unfiltered `pytest -n 4`, with the live destructive node fail-safe skipped under xdist. PG round trip: job `pg-integration` → `pytest tests/pg/ -m integration`. Persisted graph/impact consumer: job `graph-integration` → selector `integration and (neo4j or redis)` → exact node in `ci/manifests/graph-integration-nodes.txt`, enforced by `check-graph-integration-selection.py` and the JUnit no-skip guard. |

## W4-T3 — Report conformance and redaction

**Section owner:** W4-T3 only

| Evidence field | Pending value |
|---|---|
| Task status | PENDING — not yet executed |
| Focused verification command(s) | PENDING |
| Focused verification result(s) | PENDING |
| Bite test node IDs | PENDING |
| Blocking-CI collection path (workflow/job/selector) | PENDING |

## W4-T4 — Final release-HEAD revalidation

**Section owner:** W4-T4 only

| Final revalidation field | T4-owned value |
|---|---|
| Final release HEAD | PENDING |

The single final release HEAD above governs every row. After the atomic task
commits land, T4 records each task's now-known commit SHA and a blocking CI
run/job that collected and executed that suite at the final release HEAD.
Task-local focused evidence cannot be copied forward as final evidence.

| Suite | Landed task commit SHA | Blocking run/job URL | Result |
|---|---|---|---|
| W4-T1 vendor/plugin conformance + routing | PENDING | PENDING | PENDING |
| W4-T2 application-dependency derivation | PENDING | PENDING | PENDING |
| W4-T3 report conformance + redaction | PENDING | PENDING | PENDING |
