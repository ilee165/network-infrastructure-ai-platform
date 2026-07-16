"""Unit proofs for the graph-integration JUnit execution/skip guard."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GUARD = _REPO_ROOT / "ci" / "scripts" / "check-graph-integration-junit.py"


def _run_guard(tmp_path: Path, *, manifest: str, junit: str) -> subprocess.CompletedProcess[str]:
    manifest_path = tmp_path / "manifest.txt"
    junit_path = tmp_path / "junit.xml"
    manifest_path.write_text(manifest, encoding="utf-8")
    junit_path.write_text(junit, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(_GUARD),
            "--manifest",
            str(manifest_path),
            "--junit",
            str(junit_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_junit_guard_accepts_exact_function_and_class_nodes(tmp_path: Path) -> None:
    result = _run_guard(
        tmp_path,
        manifest=(
            "tests/integration/test_graph_redis.py::test_real_redis\n"
            "tests/knowledge/test_impact.py::TestLive::test_live_impact\n"
        ),
        junit=(
            "<testsuites><testsuite>"
            '<testcase classname="tests.integration.test_graph_redis" '
            'name="test_real_redis" />'
            '<testcase classname="tests.knowledge.test_impact.TestLive" '
            'name="test_live_impact" />'
            "</testsuite></testsuites>"
        ),
    )

    assert result.returncode == 0, result.stderr
    assert "2 exact nodes, zero skips" in result.stdout


def test_junit_guard_rejects_selected_skip(tmp_path: Path) -> None:
    node = "tests/integration/test_graph_redis.py::test_real_redis"
    result = _run_guard(
        tmp_path,
        manifest=f"{node}\n",
        junit=(
            "<testsuites><testsuite>"
            '<testcase classname="tests.integration.test_graph_redis" '
            'name="test_real_redis"><skipped /></testcase>'
            "</testsuite></testsuites>"
        ),
    )

    assert result.returncode == 1
    assert "selected graph-integration tests skipped" in result.stderr
    assert node in result.stderr


def test_junit_guard_rejects_executed_node_drift(tmp_path: Path) -> None:
    result = _run_guard(
        tmp_path,
        manifest="tests/integration/test_graph_redis.py::test_expected\n",
        junit=(
            "<testsuites><testsuite>"
            '<testcase classname="tests.integration.test_graph_redis" '
            'name="test_unexpected" />'
            "</testsuite></testsuites>"
        ),
    )

    assert result.returncode == 1
    assert "executed graph-integration nodes differ from the manifest" in result.stderr
    assert "test_expected" in result.stderr
    assert "test_unexpected" in result.stderr
