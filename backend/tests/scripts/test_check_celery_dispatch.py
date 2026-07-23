from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts import check_celery_dispatch

BACKEND = Path(__file__).parents[2]
FIXTURES = BACKEND / "tests" / "fixtures" / "celery_dispatch_ratchet"


def _kinds(path: str) -> set[str]:
    return {violation.kind for violation in check_celery_dispatch.scan_paths([FIXTURES / path])}


def test_dispatch_ratchet_rejects_send_task_alias_and_multiline_forms() -> None:
    assert _kinds("send_task_alias.py") == {"send_task"}


def test_dispatch_ratchet_rejects_apply_async_outside_wrapper() -> None:
    assert _kinds("apply_async_nested.py") == {"apply_async"}


def test_dispatch_ratchet_rejects_delay_outside_wrapper() -> None:
    assert _kinds("delay_nested.py") == {"delay"}


def test_dispatch_ratchet_rejects_bound_publication_method_alias() -> None:
    assert _kinds("bound_method_alias.py") == {"send_task"}


def test_dispatch_ratchet_rejects_imported_task_alias_direct_call() -> None:
    assert _kinds("imported_task_alias.py") == {"task_call"}


def test_dispatch_ratchet_rejects_imported_task_object_publication_method() -> None:
    assert _kinds("imported_task_method.py") == {"task_call"}


def test_dispatch_ratchet_accepts_ordinary_imported_function_alias() -> None:
    assert _kinds("ordinary_function_alias.py") == set()


def test_dispatch_ratchet_checks_nested_paths() -> None:
    violations = check_celery_dispatch.scan_paths(
        [FIXTURES / "apply_async_nested.py", FIXTURES / "delay_nested.py"]
    )
    assert {(item.kind, item.symbol) for item in violations} == {
        ("apply_async", "Publisher.publish"),
        ("delay", "publish"),
    }


def test_dispatch_ratchet_accepts_only_path_symbol_scoped_exceptions(tmp_path: Path) -> None:
    source = tmp_path / "legacy.py"
    source.write_text(
        "def allowed():\n    client.delay(1)\n\ndef denied():\n    client.delay(2)\n",
        encoding="utf-8",
    )
    exception = check_celery_dispatch.ExceptionScope(source.resolve(), "allowed", "delay")
    violations = check_celery_dispatch.scan_paths([source], exceptions=frozenset({exception}))
    assert [(item.symbol, item.kind) for item in violations] == [("denied", "delay")]


def test_dispatch_ratchet_wrapper_exemption_requires_exact_canonical_path(
    tmp_path: Path,
) -> None:
    spoof = tmp_path / "nested" / "app" / "workers" / "dispatch.py"
    spoof.parent.mkdir(parents=True)
    spoof.write_text(
        "def durable_dispatch():\n    celery_app.send_task('discovery.run')\n",
        encoding="utf-8",
    )
    assert [(item.symbol, item.kind) for item in check_celery_dispatch.scan_paths([spoof])] == [
        ("durable_dispatch", "send_task")
    ]
    assert check_celery_dispatch.scan_paths([BACKEND / "app" / "workers" / "dispatch.py"]) == []


@pytest.mark.parametrize(
    ("fixture", "branch"),
    [
        ("send_task_alias.py", "send_task"),
        ("apply_async_nested.py", "apply_async"),
        ("delay_nested.py", "delay"),
        ("bound_method_alias.py", "bound_method_alias"),
        ("imported_task_alias.py", "imported_task_alias"),
        ("imported_task_method.py", "imported_task_method"),
    ],
)
def test_dispatch_ratchet_mutating_each_visitor_branch_makes_fixture_fail(
    monkeypatch: pytest.MonkeyPatch, fixture: str, branch: str
) -> None:
    if branch in check_celery_dispatch.FORBIDDEN_METHODS:
        monkeypatch.setattr(
            check_celery_dispatch,
            "FORBIDDEN_METHODS",
            check_celery_dispatch.FORBIDDEN_METHODS - {branch},
        )
    else:
        monkeypatch.setattr(check_celery_dispatch, f"TRACK_{branch.upper()}", False)
    assert check_celery_dispatch.scan_paths([FIXTURES / fixture]) == []


def test_dispatch_ratchet_inventory_has_zero_unjustified_bare_sites() -> None:
    assert check_celery_dispatch.scan_paths([BACKEND / "app"]) == []


def test_dispatch_ratchet_blocking_ci_step_executes_the_negative_control() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(BACKEND / "scripts" / "check_celery_dispatch.py"),
            "--negative-control",
        ],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert {"send_task", "apply_async", "delay"} <= set(result.stdout.split())
