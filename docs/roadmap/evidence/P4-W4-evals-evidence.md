# P4 W4 Evaluation Evidence Ledger

| | |
|---|---|
| **Scope** | W4-T1 vendor/plugin conformance and routing; W4-T2 application-dependency derivation; W4-T3 report conformance and redaction |
| **Final revalidation lifecycle/status (W4-T4 only)** | **PASS — all three landed suites revalidated by blocking CI at the single candidate release HEAD below** |

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

| Evidence field | T3 value |
|---|---|
| Task status | **PASS (task-local)** — the four W3 golden row sets reconstruct exact fixed payloads; the independently authored manifest pins every required completeness anchor and row; real PDF extraction, determinism, clean scanning, isolated deny-header/PEM plants, formula neutralization, and SHA-256 non-false-positive boundaries pass. The real PostgreSQL fail-closed persistence nodes are collected but skipped locally because PostgreSQL is unavailable; their execution remains blocking-CI. Final release-HEAD revalidation remains T4-owned. |
| Focused verification command(s) | `cd backend && LD_LIBRARY_PATH=/tmp/netops-p4-w4-native/root/usr/lib/x86_64-linux-gnu FONTCONFIG_FILE=/tmp/netops-p4-w4-native/fonts.conf NETOPS_REQUIRE_REPORT_PDF_EVAL=1 .venv/bin/pytest tests/agents/eval/test_report_conformance.py -q`; the same required native environment with `.venv/bin/pytest tests/engines/reports tests/workers/test_report_tasks.py -q`; `cd backend && .venv/bin/pytest tests/pg/test_reports_pg.py -q`; `cd backend && .venv/bin/pytest --collect-only -q tests/agents/eval/test_report_conformance.py tests/pg/test_reports_pg.py`; `cd backend && .venv/bin/pytest tests/scripts/test_ci_egress_hardening.py tests/scripts/test_coverage_ci_contract.py tests/scripts/test_ci_decomposition.py -q`; touched-test Ruff/format/mypy; exact `uv pip compile pyproject.toml --extra dev --universal --generate-hashes --python-version 3.12 --output-file requirements.lock.txt`. |
| Focused verification result(s) | Focused required-native eval `49 passed in 10.19s` with zero skips; independently rerun adjacent report/worker suite `187 passed in 35.99s` with zero skips; workflow contracts `42 passed in 7.12s`; local PG file `10 skipped in 0.02s` only because its explicit PostgreSQL fixture was unavailable; exact combined collection `59 tests collected in 0.03s`; Ruff/format and touched-test mypy green; lock reproducibly resolves `140` packages with only hash-locked `pypdf==6.14.2` added. |
| Bite test node IDs | Completeness schema/rows: `tests/agents/eval/test_report_conformance.py::test_manifest_loader_bites_when_a_declared_anchor_is_deleted[compliance_posture-daily-posture-days-and-gaps]`; `tests/agents/eval/test_report_conformance.py::test_each_completeness_anchor_bites_when_observed_evidence_is_removed[change]`; `tests/agents/eval/test_report_conformance.py::test_each_completeness_anchor_bites_when_observed_evidence_is_removed[compliance_posture]`; `tests/agents/eval/test_report_conformance.py::test_each_completeness_anchor_bites_when_observed_evidence_is_removed[access_review]`; `tests/agents/eval/test_report_conformance.py::test_each_completeness_anchor_bites_when_observed_evidence_is_removed[audit_integrity]`; `tests/agents/eval/test_report_conformance.py::test_audit_attestation_timestamp_must_equal_payload_generated_at`. PDF/redaction/scanner: `tests/agents/eval/test_report_conformance.py::test_pdf_semantic_comparator_bites_on_deleted_or_reordered_logical_units`; `tests/agents/eval/test_report_conformance.py::test_enabled_redaction_rejects_each_exact_plant[authorization-sections[0].columns[0]-deny_field_name:authorization]`; `tests/agents/eval/test_report_conformance.py::test_enabled_redaction_rejects_each_exact_plant[pem-sections[0].rows[0][1]-value_pattern:pem_private_key]`; `tests/agents/eval/test_report_conformance.py::test_disabled_bound_filter_makes_each_plant_visible_in_both_real_formats[authorization-deny-header:authorization]`; `tests/agents/eval/test_report_conformance.py::test_disabled_bound_filter_makes_each_plant_visible_in_both_real_formats[pem-value-format:pem-private-key]`; `tests/agents/eval/test_report_conformance.py::test_independent_scanner_accepts_bytes_only_and_imports_no_filter_oracles`. Workflow: `tests/agents/eval/test_report_conformance.py::test_workflow_contract_bites_when_each_native_package_is_removed[libpango-1.0-0]`; `tests/agents/eval/test_report_conformance.py::test_workflow_contract_bites_when_required_flag_is_removed`; `tests/agents/eval/test_report_conformance.py::test_workflow_contract_bites_when_backend_pytest_is_filtered[--ignore=tests/agents/eval/test_report_conformance.py]`; `tests/agents/eval/test_report_conformance.py::test_workflow_contract_bites_when_native_install_moves_after_pytest`. PostgreSQL: `tests/pg/test_reports_pg.py::test_redaction_failure_is_fail_closed_on_pg[deny-header]`; `tests/pg/test_reports_pg.py::test_redaction_failure_is_fail_closed_on_pg[pem-cell]`. |
| Blocking-CI collection path (workflow/job/selector) | Unit/PDF eval: `.github/workflows/ci.yml` → `backend-gates` reusable workflow → `.github/workflows/backend-gates.yml` job `backend`, step `Install report PDF native dependencies` → step `Test (pytest + coverage)` with `NETOPS_REQUIRE_REPORT_PDF_EVAL: "1"` → exact unfiltered `pytest -n 4 --cov=app --cov-report=term -q`, which collects `tests/agents/eval/test_report_conformance.py`. Real persistence: `.github/workflows/backend-gates.yml` job `pg-integration` → `pytest tests/pg/ -m integration`, which collects both `test_redaction_failure_is_fail_closed_on_pg` plants against PostgreSQL. |

## W4-T4 — Final release-HEAD revalidation

**Section owner:** W4-T4 only

| Final revalidation field | T4-owned value |
|---|---|
| Final release HEAD | `71cd249ddf0f9b0526575082d5646473df3ac0ca` — CI-evidenced code candidate; the following T4 closeout commit is docs-only and regular CI does not trigger for it |

The single final release HEAD above governs every row. After the atomic task
commits land, T4 records each task's now-known commit SHA and a blocking CI
run/job that collected and executed that suite at the final release HEAD.
Task-local focused evidence cannot be copied forward as final evidence.

| Suite | Landed task commit SHA | Blocking run/job URL | Result |
|---|---|---|---|
| W4-T1 vendor/plugin conformance + routing | `d09dca19` | [`backend` job 88661288726](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29838591933/job/88661288726) | **PASS** |
| W4-T2 application-dependency derivation | `d6feeb41` | [`backend` 88661288726](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29838591933/job/88661288726); [`pg-integration` 88661288634](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29838591933/job/88661288634); [`graph-integration` 88661288574](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29838591933/job/88661288574) | **PASS** |
| W4-T3 report conformance + redaction | `cf23cdab` | [`backend` 88661288726](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29838591933/job/88661288726); [`pg-integration` 88661288634](https://github.com/ilee165/network-infrastructure-ai-platform/actions/runs/29838591933/job/88661288634) | **PASS** |
