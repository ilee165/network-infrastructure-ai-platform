"""Proofs for exact graph-integration collection-manifest comparison."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GUARD = _REPO_ROOT / "ci" / "scripts" / "check-graph-integration-selection.py"
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "backend-gates.yml"


def _run_guard(
    tmp_path: Path, *, expected: str, collected: str
) -> subprocess.CompletedProcess[str]:
    expected_path = tmp_path / "expected.txt"
    collected_path = tmp_path / "collected.txt"
    expected_path.write_text(expected, encoding="utf-8")
    collected_path.write_text(collected, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(_GUARD),
            "--expected",
            str(expected_path),
            "--collected",
            str(collected_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_selection_guard_rejects_duplicate_checked_manifest_node(tmp_path: Path) -> None:
    node = "tests/integration/test_graph_redis.py::test_real_redis"
    result = _run_guard(
        tmp_path,
        expected=f"{node}\n{node}\n",
        collected=f"{node}\n",
    )

    assert result.returncode == 1
    assert "expected graph-integration manifest contains duplicate node IDs" in result.stderr


def test_selection_guard_compares_plain_sorted_exact_lists(tmp_path: Path) -> None:
    first = "tests/a.py::test_a"
    second = "tests/b.py::test_b"
    result = _run_guard(
        tmp_path,
        expected=f"{second}\n{first}\n",
        collected=f"{first}\n{second}\n",
    )

    assert result.returncode == 0, result.stderr
    assert "2 exact collected nodes" in result.stdout


def test_workflow_does_not_deduplicate_before_selection_guard() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    graph_step = workflow.split("- name: Exact graph integration layer — RED gate", 1)[1].split(
        "- name: Upload graph-integration JUnit", 1
    )[0]

    assert "sort -u" not in graph_step
    assert "check-graph-integration-selection.py" in graph_step
    assert '--expected "${manifest}"' in graph_step
