"""Ratchets for honest cross-job backend coverage semantics (Wave 7 F8)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml
from coverage import CoverageData

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PYPROJECT = _REPO_ROOT / "backend" / "pyproject.toml"
_WORKFLOW_FILES = {
    "root": _REPO_ROOT / ".github" / "workflows" / "ci.yml",
    "backend": _REPO_ROOT / ".github" / "workflows" / "backend-gates.yml",
}
_DOWNLOAD_ACTION = "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131"

_PRODUCERS = {
    "backend": {
        "test_step": "Test (pytest + coverage)",
        "upload_step": "Upload unit raw coverage",
        "context": "unit",
        "data_file": ".coverage.unit",
        "artifact": "backend-coverage-unit-raw",
    },
    "pg-integration": {
        "test_step": "PG test layer (alembic upgrade head + W4 controls) — RED gate",
        "upload_step": "Upload pg-integration raw coverage",
        "context": "pg-integration",
        "data_file": ".coverage.pg-integration",
        "artifact": "backend-coverage-pg-integration-raw",
    },
    "graph-integration": {
        "test_step": "Exact graph integration layer — RED gate",
        "upload_step": "Upload graph-integration raw coverage",
        "context": "graph-integration",
        "data_file": ".coverage.graph-integration",
        "artifact": "backend-coverage-graph-integration-raw",
    },
}


def _workflow_texts() -> dict[str, str]:
    return {name: path.read_text(encoding="utf-8") for name, path in _WORKFLOW_FILES.items()}


def _workflow_jobs(workflow_texts: dict[str, str]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for _workflow_name, workflow_text in workflow_texts.items():
        parsed = yaml.safe_load(workflow_text)
        assert isinstance(parsed, dict)
        jobs = parsed.get("jobs")
        assert isinstance(jobs, dict)
        overlap = merged.keys() & jobs.keys()
        assert not overlap, f"duplicate jobs across workflows: {sorted(overlap)}"
        merged.update(jobs)
    return merged


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [step for step in job["steps"] if step.get("name") == name]
    assert len(matches) == 1, f"expected exactly one {name!r} step"
    return matches[0]


def _assert_official_action_is_sha_pinned(step: dict[str, Any], action: str) -> None:
    assert re.fullmatch(rf"{re.escape(action)}@[0-9a-f]{{40}}", step["uses"])


def _assert_coverage_contract(pyproject_text: str, workflow_texts: dict[str, str]) -> None:
    pyproject = tomllib.loads(pyproject_text)
    run_config = pyproject["tool"]["coverage"]["run"]
    assert run_config["branch"] is True
    assert run_config["parallel"] is True
    assert run_config["relative_files"] is True
    assert run_config["source"] == ["app"]
    assert run_config["context"] == "${COVERAGE_CONTEXT-local}"
    omit = run_config["omit"]
    assert any("alembic" in pattern for pattern in omit), "migration omit is required"
    assert any("generated" in pattern for pattern in omit), "generated-code omit is required"
    assert "fail_under" not in pyproject["tool"]["coverage"].get("report", {})

    jobs = _workflow_jobs(workflow_texts)
    artifacts: set[str] = set()

    for job_name, expected in _PRODUCERS.items():
        job = jobs[job_name]
        test_step = _step(job, expected["test_step"])
        assert test_step["working-directory"] == "backend"
        assert test_step["env"]["COVERAGE_CONTEXT"] == expected["context"]
        assert test_step["env"]["COVERAGE_FILE"] == expected["data_file"]
        assert "--cov=app" in test_step["run"]
        assert "--cov-fail-under" not in test_step["run"]

        upload = _step(job, expected["upload_step"])
        _assert_official_action_is_sha_pinned(upload, "actions/upload-artifact")
        assert upload["with"]["name"] == expected["artifact"]
        assert upload["with"]["path"] == f"backend/{expected['data_file']}*"
        assert upload["with"]["include-hidden-files"] is True
        assert upload["with"]["if-no-files-found"] == "error"
        assert expected["artifact"] not in artifacts
        artifacts.add(expected["artifact"])

    graph_junit = _step(jobs["graph-integration"], "Upload graph-integration JUnit")
    assert graph_junit["with"]["name"] == "graph-integration-junit"

    combined = jobs["coverage-combined"]
    assert combined["needs"] == list(_PRODUCERS)
    for expected in _PRODUCERS.values():
        download = _step(combined, f"Download {expected['context']} raw coverage")
        assert download["uses"] == _DOWNLOAD_ACTION
        assert download["with"]["name"] == expected["artifact"]
        assert download["with"]["path"] == f"backend/.coverage-input/{expected['context']}"

    combine_step = _step(combined, "Combine coverage and enforce headline floor")
    assert combine_step["working-directory"] == "backend"
    combine_run = combine_step["run"]
    expected_context_literal = '{"unit", "pg-integration", "graph-integration"}'
    tokens = [
        "coverage combine",
        expected_context_literal,
        "measured_contexts()",
        "coverage xml",
        "coverage report",
    ]
    positions = [combine_run.index(token) for token in tokens]
    assert positions == sorted(positions), "combine, context guard, XML, report order changed"
    context_failure = (
        "measured = set(data.measured_contexts())\n"
        "missing = expected - measured\n"
        "if missing:\n"
        '    raise SystemExit(f"missing coverage contexts: {sorted(missing)}")'
    )
    assert context_failure in combine_run, "missing producer context must terminate the gate"
    assert all(expected["data_file"] in combine_run for expected in _PRODUCERS.values())

    threshold_matches: list[tuple[str, float]] = []
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            run_block = step.get("run")
            if not isinstance(run_block, str):
                continue
            for match in re.finditer(r"--(?:cov-)?fail-under(?:=|\s+)(\d+(?:\.\d+)?)", run_block):
                threshold_matches.append((job_name, float(match.group(1))))
    assert threshold_matches == [("coverage-combined", 101.0)]

    xml_upload = _step(combined, "Upload combined coverage XML")
    _assert_official_action_is_sha_pinned(xml_upload, "actions/upload-artifact")
    assert xml_upload["with"]["name"] == "backend-coverage-xml"
    assert xml_upload["with"]["path"] == "backend/coverage.xml"
    for job_name, job in jobs.items():
        if job_name == "coverage-combined":
            continue
        assert all(
            step.get("with", {}).get("name") != "backend-coverage-xml"
            for step in job.get("steps", [])
        )

    assert jobs["backend-gates"]["uses"] == "./.github/workflows/backend-gates.yml"
    assert "backend-gates" in jobs["all-gates"]["needs"]


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _clean_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("COV_CORE_") or name in {"COVERAGE_PROCESS_START", "PYTEST_ADDOPTS"}:
            env.pop(name)
    return env


def _assert_contexts(data_file: Path, expected: set[str]) -> None:
    data = CoverageData(basename=str(data_file))
    data.read()
    measured = set(data.measured_contexts())
    assert expected <= measured, f"missing coverage contexts: {sorted(expected - measured)}"


def test_repository_coverage_contract() -> None:
    _assert_coverage_contract(
        _PYPROJECT.read_text(encoding="utf-8"),
        _workflow_texts(),
    )


@pytest.mark.parametrize(
    ("target", "replacement", "in_pyproject"),
    [
        ("branch = true", "branch = false", True),
        ("backend-coverage-graph-integration-raw", "backend-coverage-graph-raw", False),
        ("include-hidden-files: true", "include-hidden-files: false", False),
        ("--fail-under=101", "--fail-under=89", False),
        ("run: npm test", "run: npm test --cov-fail-under=90", False),
        (
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
            "actions/download-artifact@0000000000000000000000000000000000000000",
            False,
        ),
        (
            'raise SystemExit(f"missing coverage contexts: {sorted(missing)}")',
            'print(f"missing coverage contexts: {sorted(missing)}")',
            False,
        ),
        (
            "backend-gates, frontend, security-scan",
            "frontend, security-scan",
            False,
        ),
    ],
)
def test_repository_coverage_contract_bites_on_mutation(
    target: str,
    replacement: str,
    in_pyproject: bool,
) -> None:
    pyproject_text = _PYPROJECT.read_text(encoding="utf-8")
    workflow_texts = _workflow_texts()
    if in_pyproject:
        original = pyproject_text
        mutated_workflows = workflow_texts
    else:
        matching = [name for name, text in workflow_texts.items() if target in text]
        assert matching, f"mutation anchor disappeared: {target}"
        mutated_workflows = dict(workflow_texts)
        workflow_name = matching[0]
        original = workflow_texts[workflow_name]
        mutated_workflows[workflow_name] = original.replace(target, replacement, 1)
    assert target in original, f"mutation anchor disappeared: {target}"
    mutated = original.replace(target, replacement, 1)

    with pytest.raises((AssertionError, KeyError, ValueError)):
        _assert_coverage_contract(
            mutated if in_pyproject else pyproject_text,
            workflow_texts if in_pyproject else mutated_workflows,
        )


def test_parallel_raw_files_combine_with_job_contexts_and_branch_coverage(
    tmp_path: Path,
) -> None:
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample" / "__init__.py").write_text(
        "def classify(value: bool) -> str:\n    if value:\n        return 'yes'\n    return 'no'\n",
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_unit.py").write_text(
        "from sample import classify\n\ndef test_true():\n    assert classify(True) == 'yes'\n",
        encoding="utf-8",
    )
    (tests / "test_pg.py").write_text(
        "from sample import classify\n\ndef test_false():\n    assert classify(False) == 'no'\n",
        encoding="utf-8",
    )
    (tests / "test_graph.py").write_text(
        "from sample import classify\n\ndef test_graph():\n    assert classify(True) == 'yes'\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[tool.coverage.run]\n"
        "branch = true\n"
        "parallel = true\n"
        "relative_files = true\n"
        'source = ["sample"]\n'
        'context = "${COVERAGE_CONTEXT-local}"\n',
        encoding="utf-8",
    )

    inputs = tmp_path / ".coverage-input"
    contexts = {
        "unit": ("test_unit.py", ["-n", "2"]),
        "pg-integration": ("test_pg.py", []),
        "graph-integration": ("test_graph.py", []),
    }
    for context, (test_file, extra_args) in contexts.items():
        output_dir = inputs / context
        output_dir.mkdir(parents=True)
        data_file = output_dir / f".coverage.{context}"
        env = _clean_subprocess_env()
        env["COVERAGE_CONTEXT"] = context
        env["COVERAGE_FILE"] = str(data_file)
        result = _run(
            [
                sys.executable,
                "-m",
                "pytest",
                *extra_args,
                f"tests/{test_file}",
                "--cov=sample",
                "--cov-report=",
                "-q",
            ],
            cwd=tmp_path,
            env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert list(output_dir.glob(f".coverage.{context}*"))

    combined_file = tmp_path / ".coverage"
    env = _clean_subprocess_env()
    env["COVERAGE_FILE"] = str(combined_file)
    combine = _run(
        [
            sys.executable,
            "-m",
            "coverage",
            "combine",
            "--keep",
            *(str(inputs / context) for context in contexts),
        ],
        cwd=tmp_path,
        env=env,
    )
    assert combine.returncode == 0, combine.stdout + combine.stderr
    _assert_contexts(combined_file, set(contexts))

    report = _run(
        [sys.executable, "-m", "coverage", "report", "--fail-under=100"],
        cwd=tmp_path,
        env=env,
    )
    assert report.returncode == 0, report.stdout + report.stderr
    assert "Branch" in report.stdout

    xml = _run(
        [sys.executable, "-m", "coverage", "xml", "-o", "coverage.xml"],
        cwd=tmp_path,
        env=env,
    )
    assert xml.returncode == 0, xml.stdout + xml.stderr
    assert 'branch-rate="1"' in (tmp_path / "coverage.xml").read_text(encoding="utf-8")

    missing_dir = tmp_path / "missing-graph"
    missing_dir.mkdir()
    missing_file = missing_dir / ".coverage"
    missing_env = _clean_subprocess_env()
    missing_env["COVERAGE_FILE"] = str(missing_file)
    missing_combine = _run(
        [
            sys.executable,
            "-m",
            "coverage",
            "combine",
            "--keep",
            str(inputs / "unit"),
            str(inputs / "pg-integration"),
        ],
        cwd=tmp_path,
        env=missing_env,
    )
    assert missing_combine.returncode == 0, missing_combine.stdout + missing_combine.stderr
    with pytest.raises(AssertionError, match="graph-integration"):
        _assert_contexts(missing_file, set(contexts))
