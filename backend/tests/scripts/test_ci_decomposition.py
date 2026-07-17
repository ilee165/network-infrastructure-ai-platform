"""Structural bite proofs for the Wave 7 T4 CI decomposition."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"
_ACTION_DIR = _REPO_ROOT / ".github" / "actions"

_ROOT_WORKFLOW = "ci.yml"
_REUSABLE_OWNERS = {
    "backend-gates.yml": {
        "backend",
        "pg-integration",
        "graph-integration",
        "coverage-combined",
    },
    "drift-gates.yml": {"lockfile", "config-drift", "contract-drift"},
    "platform-gates.yml": {"infra", "drill-bite-proofs", "observability"},
}
_CALLS = {
    "backend-gates": "./.github/workflows/backend-gates.yml",
    "drift-gates": "./.github/workflows/drift-gates.yml",
    "platform-gates": "./.github/workflows/platform-gates.yml",
}
_ROOT_JOBS = {
    "backend-gates",
    "frontend",
    "security-scan",
    "docker",
    "docker-publish",
    "platform-gates",
    "kind-harness",
    "kind-harness-ha",
    "kms-emulators",
    "packet-analysis-bite-proof",
    "drift-gates",
    "pg-test-routing",
    "all-gates",
}
_ALL_GATES_NEEDS = [
    "backend-gates",
    "frontend",
    "security-scan",
    "docker",
    "platform-gates",
    "kms-emulators",
    "packet-analysis-bite-proof",
    "drift-gates",
]
_FLATTENED_NEEDS = {
    "backend-gates": ["backend", "pg-integration", "graph-integration", "coverage-combined"],
    "frontend": ["frontend"],
    "security-scan": ["security-scan"],
    "docker": ["docker"],
    "platform-gates": ["infra", "drill-bite-proofs", "observability"],
    "kms-emulators": ["kms-emulators"],
    "packet-analysis-bite-proof": ["packet-analysis-bite-proof"],
    "drift-gates": ["lockfile", "config-drift", "contract-drift"],
}
_ORIGINAL_BLOCKING_GATES = {
    "backend",
    "frontend",
    "security-scan",
    "docker",
    "infra",
    "kms-emulators",
    "pg-integration",
    "graph-integration",
    "coverage-combined",
    "packet-analysis-bite-proof",
    "lockfile",
    "observability",
    "drill-bite-proofs",
    "config-drift",
    "contract-drift",
}
_RETRY_ENV = {
    "PIP_RETRIES": "0",
    "NPM_CONFIG_FETCH_RETRIES": "0",
    "UV_HTTP_RETRIES": "0",
}
_CHECKOUT = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
_LOCAL_ACTIONS = {
    "python": "./.github/actions/setup-python",
    "node": "./.github/actions/setup-node",
    "tools": "./.github/actions/setup-tools",
}
_SETUP_ACTION_PINS = {
    "setup-python": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "setup-node": "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
    "setup-tools": "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310",
}
_PYTHON_JOBS = {
    "backend",
    "kms-emulators",
    "pg-integration",
    "graph-integration",
    "coverage-combined",
    "lockfile",
    "config-drift",
    "contract-drift",
}
_PYTHON_CACHED_JOBS = {
    "backend",
    "pg-integration",
    "graph-integration",
    "config-drift",
    "contract-drift",
}
_NODE_JOBS = {"frontend", "lockfile", "contract-drift"}
_TOOLS_JOBS = {
    "infra",
    "kind-harness",
    "drill-bite-proofs",
    "kind-harness-ha",
    "observability",
}
_PROMTOOL_JOBS = {"drill-bite-proofs", "kind-harness-ha", "observability"}


def _load_yaml(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path} must contain a YAML mapping"
    return document


def _documents() -> dict[str, dict[str, Any]]:
    names = {_ROOT_WORKFLOW, *_REUSABLE_OWNERS}
    return {name: _load_yaml(_WORKFLOW_DIR / name) for name in names}


def _jobs(document: dict[str, Any]) -> dict[str, Any]:
    jobs = document.get("jobs")
    assert isinstance(jobs, dict)
    return jobs


def _workflow_call_trigger(document: dict[str, Any]) -> Any:
    # PyYAML's YAML-1.1 resolver parses the plain key ``on`` as boolean true.
    trigger = document.get("on", document.get(True))
    assert isinstance(trigger, dict)
    assert "workflow_call" in trigger
    return trigger.get("workflow_call")


def _all_runner_jobs(documents: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    runner_jobs: dict[str, dict[str, Any]] = {}
    for document in documents.values():
        for job_name, job in _jobs(document).items():
            if "runs-on" not in job:
                continue
            assert job_name not in runner_jobs, f"duplicate runner job: {job_name}"
            runner_jobs[job_name] = job
    return runner_jobs


def _named_step(job: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [step for step in job.get("steps", []) if step.get("name") == name]
    assert len(matches) == 1, f"expected exactly one step named {name!r}"
    return matches[0]


def _assert_pinned_action_uses(action: dict[str, Any], expected_pin: str) -> None:
    runs = action["runs"]
    assert runs["using"] == "composite"
    uses = [step.get("uses") for step in runs["steps"]]
    assert expected_pin in uses
    for used_action in uses:
        if isinstance(used_action, str) and not used_action.startswith("./"):
            assert "@" in used_action
            assert len(used_action.rsplit("@", 1)[1]) == 40


def _assert_exact_ownership(documents: dict[str, dict[str, Any]]) -> None:
    root_jobs = _jobs(documents[_ROOT_WORKFLOW])
    assert set(root_jobs) == _ROOT_JOBS
    for call_name, target in _CALLS.items():
        call = root_jobs[call_name]
        assert call["uses"] == target
        assert call["permissions"] == {"contents": "read"}
        allowed_call_keys = {
            "name",
            "uses",
            "with",
            "secrets",
            "strategy",
            "needs",
            "if",
            "concurrency",
            "permissions",
        }
        assert set(call) <= allowed_call_keys

    observed: set[str] = set()
    for workflow_name, expected_jobs in _REUSABLE_OWNERS.items():
        reusable = documents[workflow_name]
        assert _workflow_call_trigger(reusable) is None
        actual_jobs = set(_jobs(reusable))
        assert actual_jobs == expected_jobs
        assert observed.isdisjoint(actual_jobs)
        observed.update(actual_jobs)
    assert observed == set().union(*_REUSABLE_OWNERS.values())
    assert observed.isdisjoint(root_jobs)

    backend_jobs = _jobs(documents["backend-gates.yml"])
    assert set(backend_jobs["pg-integration"]["services"]) == {"postgres"}
    assert set(backend_jobs["graph-integration"]["services"]) == {
        "postgres",
        "neo4j",
        "redis",
    }


def _assert_flattened_wiring(documents: dict[str, dict[str, Any]]) -> None:
    root_jobs = _jobs(documents[_ROOT_WORKFLOW])
    assert root_jobs["all-gates"]["needs"] == _ALL_GATES_NEEDS
    assert list(_FLATTENED_NEEDS) == _ALL_GATES_NEEDS
    assert {gate for gates in _FLATTENED_NEEDS.values() for gate in gates} == (
        _ORIGINAL_BLOCKING_GATES
    )
    for call_name, workflow_path in _CALLS.items():
        workflow_name = Path(workflow_path).name
        assert set(_FLATTENED_NEEDS[call_name]) == _REUSABLE_OWNERS[workflow_name]
    assert root_jobs["docker-publish"]["needs"] == [
        "backend-gates",
        "frontend",
        "docker",
    ]
    backend_jobs = _jobs(documents["backend-gates.yml"])
    assert backend_jobs["coverage-combined"]["needs"] == [
        "backend",
        "pg-integration",
        "graph-integration",
    ]

    assert "kind-harness" not in root_jobs["all-gates"]["needs"]
    assert "kind-harness-ha" not in root_jobs["all-gates"]["needs"]
    kind_step = _named_step(
        root_jobs["kind-harness"],
        "Run kind harness (create → CNI self-test → apply → assert → teardown)",
    )
    assert kind_step["continue-on-error"] is True
    assert (
        _named_step(
            root_jobs["kind-harness-ha"],
            "Run HA kind harness (create → CNI self-test → operators → apply → "
            "HA-ready → assert → teardown)",
        )["continue-on-error"]
        is True
    )
    assert (
        _named_step(root_jobs["kind-harness"], "mTLS extract_secret.py tests (no cluster)")["run"]
        == "python3 ci/mtls/test_extract_secret.py"
    )


def _assert_retry_env(documents: dict[str, dict[str, Any]]) -> None:
    for workflow_name, document in documents.items():
        assert document.get("env") == _RETRY_ENV, f"retry env drifted in {workflow_name}"


def _assert_composites_and_pins(documents: dict[str, dict[str, Any]]) -> None:
    runner_jobs = _all_runner_jobs(documents)
    expected_by_action = {
        _LOCAL_ACTIONS["python"]: _PYTHON_JOBS,
        _LOCAL_ACTIONS["node"]: _NODE_JOBS,
        _LOCAL_ACTIONS["tools"]: _TOOLS_JOBS,
    }
    observed_by_action = {action: set() for action in expected_by_action}
    checkout_count = 0

    for job_name, job in runner_jobs.items():
        steps = job.get("steps", [])
        checkout_indexes = [i for i, step in enumerate(steps) if step.get("uses") == _CHECKOUT]
        checkout_count += len(checkout_indexes)
        for index, step in enumerate(steps):
            uses = step.get("uses")
            assert not (
                isinstance(uses, str)
                and uses.startswith(
                    ("actions/setup-python@", "actions/setup-node@", "azure/setup-helm@")
                )
            ), f"{job_name} bypasses a local setup composite"
            if uses not in observed_by_action:
                continue
            observed_by_action[uses].add(job_name)
            assert checkout_indexes and checkout_indexes[0] < index, (
                f"{job_name} must checkout before invoking {uses}"
            )

    assert checkout_count == 19
    for action, expected_jobs in expected_by_action.items():
        assert observed_by_action[action] == expected_jobs

    for job_name in _PYTHON_JOBS:
        step = next(
            step
            for step in runner_jobs[job_name]["steps"]
            if step.get("uses") == _LOCAL_ACTIONS["python"]
        )
        cache = step.get("with", {}).get("cache", "")
        dependency_path = step.get("with", {}).get("cache-dependency-path", "")
        if job_name in _PYTHON_CACHED_JOBS:
            assert cache == "pip"
            assert dependency_path == "backend/pyproject.toml"
        else:
            assert cache == ""
            assert dependency_path == ""

    for job_name in _TOOLS_JOBS:
        step = next(
            step
            for step in runner_jobs[job_name]["steps"]
            if step.get("uses") == _LOCAL_ACTIONS["tools"]
        )
        assert (step.get("with", {}).get("install-promtool") == "true") is (
            job_name in _PROMTOOL_JOBS
        )

    for action_name, expected_pin in _SETUP_ACTION_PINS.items():
        action = _load_yaml(_ACTION_DIR / action_name / "action.yml")
        _assert_pinned_action_uses(action, expected_pin)

    tools_text = (_ACTION_DIR / "setup-tools" / "action.yml").read_text(encoding="utf-8")
    assert "version: v3.16.2" in tools_text
    assert "PROM_VERSION=2.53.2" in tools_text
    assert "60c126740c9cf1206b1e72150dd17914f1c3309bb7dc78a31d4670197ed4fa69" in tools_text
    assert "install-verified-tarball.sh" in tools_text


def test_repository_ci_is_decomposed_without_losing_gate_ownership() -> None:
    documents = _documents()
    _assert_exact_ownership(documents)
    _assert_flattened_wiring(documents)
    _assert_retry_env(documents)
    _assert_composites_and_pins(documents)


def test_exact_ownership_contract_bites_when_a_gate_moves_to_the_wrong_workflow() -> None:
    documents = _documents()
    mutated = copy.deepcopy(documents)
    backend = _jobs(mutated["backend-gates.yml"])
    _jobs(mutated["platform-gates.yml"])["backend"] = backend.pop("backend")
    with pytest.raises(AssertionError):
        _assert_exact_ownership(mutated)


def test_flattened_needs_contract_bites_when_a_called_family_is_dropped() -> None:
    documents = _documents()
    mutated = copy.deepcopy(documents)
    _jobs(mutated[_ROOT_WORKFLOW])["all-gates"]["needs"].remove("platform-gates")
    with pytest.raises(AssertionError):
        _assert_flattened_wiring(mutated)


def test_retry_env_contract_bites_inside_a_called_workflow() -> None:
    documents = _documents()
    mutated = copy.deepcopy(documents)
    del mutated["drift-gates.yml"]["env"]["PIP_RETRIES"]
    with pytest.raises(AssertionError):
        _assert_retry_env(mutated)


def test_composite_pin_contract_bites_on_a_floating_setup_action(tmp_path: Path) -> None:
    documents = _documents()
    source = _ACTION_DIR / "setup-python" / "action.yml"
    mutated = source.read_text(encoding="utf-8").replace(
        _SETUP_ACTION_PINS["setup-python"], "actions/setup-python@v6", 1
    )
    assert mutated != source.read_text(encoding="utf-8")
    action_dir = tmp_path / "setup-python"
    action_dir.mkdir()
    (action_dir / "action.yml").write_text(mutated, encoding="utf-8")

    # The repository helper remains green; the same pin predicate must reject
    # the planted floating reference directly.
    _assert_composites_and_pins(documents)
    action = _load_yaml(action_dir / "action.yml")
    with pytest.raises(AssertionError):
        _assert_pinned_action_uses(action, _SETUP_ACTION_PINS["setup-python"])


def test_checkout_order_contract_bites_when_a_composite_moves_first() -> None:
    documents = _documents()
    mutated = copy.deepcopy(documents)
    backend_steps = _jobs(mutated["backend-gates.yml"])["backend"]["steps"]
    backend_steps[0], backend_steps[1] = backend_steps[1], backend_steps[0]
    with pytest.raises(AssertionError):
        _assert_composites_and_pins(mutated)
