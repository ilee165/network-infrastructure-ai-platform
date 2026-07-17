"""Behavioral and structural bite proofs for Wave 7 F9 CI egress hardening."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_RETRY = _REPO_ROOT / "ci" / "scripts" / "retry-egress.sh"
_VERIFIED_INSTALL = _REPO_ROOT / "ci" / "scripts" / "install-verified-tarball.sh"
_NPM_AUDIT_FETCH = _REPO_ROOT / "ci" / "scripts" / "fetch-npm-audit.sh"


def _bash_executable() -> str:
    """Use a native Bash that can resolve the worktree on each test platform."""
    if os.name == "nt":
        candidates = (
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Git" / "bin" / "bash.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "bin" / "bash.exe",
        )
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
    return shutil.which("bash") or "bash"


_BASH = _bash_executable()

_KUBECONFORM_SHA256 = "95f14e87aa28c09d5941f11bd024c1d02fdc0303ccaa23f61cef67bc92619d73"
_KUBE_LINTER_SHA256 = "852f89a48ff6adc62347477f780889bb9eb046dd16057da0ee4e8e5b0c1b6e3e"

_EGRESS_PATTERNS = (
    re.compile(
        r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?\s+-m\s+)?"
        r"pip(?:3(?:\.\d+)?)?\s+install(?:\s|$)"
    ),
    re.compile(r"(?:^|\s)npm\s+ci(?:\s|$)"),
    re.compile(r"(?:^|\s)npm\s+audit(?:\s|$)"),
    re.compile(r"(?:^|\s)uv\s+pip\s+compile(?:\s|$)"),
    re.compile(r"(?:^|\s)pip-audit(?:\s|$)"),
    re.compile(r"(?:^|\s)osv-scanner(?:\s|$)"),
)


def _run_bash(
    script: Path,
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [_BASH, script.as_posix(), *args],
        cwd=_REPO_ROOT,
        env=merged,
        check=False,
        capture_output=True,
        text=True,
    )


def _write_bash(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env bash\nset -u\n" + body, encoding="utf-8", newline="\n")
    path.chmod(0o755)
    return path


def _counter_script(tmp_path: Path, body: str) -> tuple[Path, Path]:
    counter = tmp_path / "attempts.txt"
    script = _write_bash(
        tmp_path / "command.sh",
        f"counter='{counter.as_posix()}'\n"
        "count=0\n"
        'if [ -f "$counter" ]; then count=$(cat "$counter"); fi\n'
        "count=$((count + 1))\n"
        'printf "%s" "$count" > "$counter"\n' + body,
    )
    return script, counter


def _attempts(counter: Path) -> int:
    return int(counter.read_text(encoding="utf-8"))


def test_wrong_digest_fails_before_tar_or_install(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.write_text("trusted tool bytes", encoding="utf-8")
    archive = tmp_path / "tool.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(payload, arcname="tool")

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    tar_calls = tmp_path / "tar-calls.txt"
    _write_bash(
        stub_dir / "tar",
        f"printf called >> '{tar_calls.as_posix()}'\nexit 97\n",
    )
    destination = tmp_path / "installed-tool"
    env = {"PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}"}

    result = _run_bash(
        _VERIFIED_INSTALL,
        archive.as_uri(),
        "0" * 64,
        "tool",
        destination.as_posix(),
        env=env,
    )

    assert result.returncode != 0
    assert not tar_calls.exists(), result.stdout + result.stderr
    assert not destination.exists()
    assert "checksum" in (result.stdout + result.stderr).lower()


def test_correct_digest_extracts_and_installs_requested_member(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.write_text("verified tool bytes", encoding="utf-8")
    archive = tmp_path / "tool.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(payload, arcname="tool")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    destination = tmp_path / "installed-tool"

    result = _run_bash(
        _VERIFIED_INSTALL,
        archive.as_uri(),
        digest,
        "tool",
        destination.as_posix(),
        env={"RETRY_EGRESS_BACKOFF_SECONDS": "0"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert destination.read_text(encoding="utf-8") == "verified tool bytes"
    if os.name != "nt":
        assert destination.stat().st_mode & stat.S_IXUSR


def test_verified_installer_download_uses_bounded_retry() -> None:
    installer = _VERIFIED_INSTALL.read_text(encoding="utf-8")
    assert re.search(
        r'retry-egress\.sh" --timeout-seconds 180 -- \\\n\s+curl -fsSL',
        installer,
    )


def test_persistent_503_exhausts_exactly_three_attempts(tmp_path: Path) -> None:
    command, counter = _counter_script(
        tmp_path,
        'echo "curl: (22) The requested URL returned error: 503" >&2\nexit 22\n',
    )
    result = _run_bash(
        _RETRY,
        "--timeout-seconds",
        "5",
        "--",
        "bash",
        command.as_posix(),
        env={"RETRY_EGRESS_BACKOFF_SECONDS": "0"},
    )

    assert result.returncode == 22
    assert _attempts(counter) == 3
    output = result.stdout + result.stderr
    assert output.count("attempt 1/3") == 1
    assert output.count("attempt 2/3") == 1
    assert output.count("attempt 3/3") == 1


def test_assertion_failure_is_not_retried_and_preserves_status(tmp_path: Path) -> None:
    command, counter = _counter_script(
        tmp_path,
        'echo "ASSERTION FAILED" >&2\nexit 7\n',
    )
    result = _run_bash(
        _RETRY,
        "--timeout-seconds",
        "5",
        "--",
        "bash",
        command.as_posix(),
        env={"RETRY_EGRESS_BACKOFF_SECONDS": "0"},
    )

    assert result.returncode == 7
    assert _attempts(counter) == 1


def test_transient_503_recovers_on_third_attempt(tmp_path: Path) -> None:
    command, counter = _counter_script(
        tmp_path,
        'if [ "$count" -lt 3 ]; then\n'
        '  echo "registry returned HTTP 503" >&2\n'
        "  exit 22\n"
        "fi\n"
        'echo "download complete"\n',
    )
    result = _run_bash(
        _RETRY,
        "--timeout-seconds",
        "5",
        "--",
        "bash",
        command.as_posix(),
        env={"RETRY_EGRESS_BACKOFF_SECONDS": "0"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _attempts(counter) == 3


def test_http_404_is_not_retried(tmp_path: Path) -> None:
    command, counter = _counter_script(
        tmp_path,
        'echo "HTTP 404 Not Found" >&2\nexit 22\n',
    )
    result = _run_bash(
        _RETRY,
        "--timeout-seconds",
        "5",
        "--",
        "bash",
        command.as_posix(),
        env={"RETRY_EGRESS_BACKOFF_SECONDS": "0"},
    )

    assert result.returncode == 22
    assert _attempts(counter) == 1


def test_npm_audit_findings_are_fetched_once_for_the_local_gate(tmp_path: Path) -> None:
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    counter = tmp_path / "npm-attempts.txt"
    _write_bash(
        stub_dir / "npm",
        f"counter='{counter.as_posix()}'\n"
        "count=0\n"
        'if [ -f "$counter" ]; then count=$(cat "$counter"); fi\n'
        'printf "%s" "$((count + 1))" > "$counter"\n'
        "printf '%s\\n' "
        '\'{"auditReportVersion":2,"vulnerabilities":{"demo":{}},"metadata":{}}\'\n'
        "exit 1\n",
    )
    output = tmp_path / "npm-audit.json"
    result = _run_bash(
        _NPM_AUDIT_FETCH,
        output.as_posix(),
        env={
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "RETRY_EGRESS_BACKOFF_SECONDS": "0",
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert _attempts(counter) == 1
    assert '"vulnerabilities"' in output.read_text(encoding="utf-8")


def test_npm_audit_stderr_does_not_corrupt_report_json(tmp_path: Path) -> None:
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    _write_bash(
        stub_dir / "npm",
        'echo "npm warning registry notice" >&2\n'
        "printf '%s\\n' "
        '\'{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}\'\n'
        "exit 1\n",
    )
    output = tmp_path / "npm-audit.json"
    result = _run_bash(
        _NPM_AUDIT_FETCH,
        output.as_posix(),
        env={
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "RETRY_EGRESS_BACKOFF_SECONDS": "0",
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(output.read_text(encoding="utf-8"))["auditReportVersion"] == 2


def test_npm_audit_persistent_503_exhausts_attempt_three(tmp_path: Path) -> None:
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    counter = tmp_path / "npm-attempts.txt"
    _write_bash(
        stub_dir / "npm",
        f"counter='{counter.as_posix()}'\n"
        "count=0\n"
        'if [ -f "$counter" ]; then count=$(cat "$counter"); fi\n'
        'printf "%s" "$((count + 1))" > "$counter"\n'
        "printf '%s\\n' "
        '\'{"error":{"code":"E503","summary":"HTTP 503 Service Unavailable"}}\'\n'
        "exit 1\n",
    )
    output = tmp_path / "npm-audit.json"
    result = _run_bash(
        _NPM_AUDIT_FETCH,
        output.as_posix(),
        env={
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "RETRY_EGRESS_BACKOFF_SECONDS": "0",
        },
    )

    assert result.returncode != 0
    assert _attempts(counter) == 3
    assert not output.exists()


def _jobs(workflow_text: str) -> dict[str, Any]:
    document = yaml.safe_load(workflow_text)
    assert isinstance(document, dict)
    jobs = document.get("jobs")
    assert isinstance(jobs, dict)
    return jobs


def _steps(job: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [step for step in job.get("steps", []) if step.get("name") == name]


def _run_blocks(workflow_text: str) -> Iterator[tuple[str, str, str]]:
    for job_name, job in _jobs(workflow_text).items():
        for step in job.get("steps", []):
            run = step.get("run")
            if isinstance(run, str):
                yield job_name, str(step.get("name", "<unnamed>")), run


def _executable_lines(run: str) -> Iterator[str]:
    for raw in run.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            yield line


def _unwrapped_egress_lines(run: str) -> list[str]:
    unwrapped: list[str] = []
    for line in _executable_lines(run):
        # A quoted continuation is message/argument text, not a command token.
        if line.startswith(('"', "'")):
            continue
        if any(pattern.search(line) for pattern in _EGRESS_PATTERNS) and (
            "retry-egress.sh" not in line
        ):
            unwrapped.append(line)
    return unwrapped


def _assert_workflow_hardened(workflow_text: str) -> None:
    document = yaml.safe_load(workflow_text)
    assert document["env"] == {
        "PIP_RETRIES": "0",
        "NPM_CONFIG_FETCH_RETRIES": "0",
        "UV_HTTP_RETRIES": "0",
    }
    jobs = _jobs(workflow_text)
    unwrapped: list[str] = []
    for job_name, step_name, run in _run_blocks(workflow_text):
        for line in _unwrapped_egress_lines(run):
            unwrapped.append(f"{job_name}/{step_name}: {line}")
        for line in _executable_lines(run):
            assert not re.search(r"(?:^|\s)npx\s+openapi-typescript(?:\s|$)", line)
    assert not unwrapped, "unwrapped workflow egress:\n" + "\n".join(unwrapped)

    binary_steps = (
        ("infra", "Install kubeconform", _KUBECONFORM_SHA256),
        ("infra", "Install kube-linter", _KUBE_LINTER_SHA256),
        ("observability", "Install kubeconform", _KUBECONFORM_SHA256),
    )
    for job_name, step_name, digest in binary_steps:
        matches = _steps(jobs[job_name], step_name)
        assert len(matches) == 1
        run = matches[0]["run"]
        assert "install-verified-tarball.sh" in run
        assert digest in run
        assert "curl " not in run
        assert "tar " not in run

    fetch = _steps(jobs["frontend"], "Fetch dependency audit (npm audit, retryable egress)")
    gate = _steps(jobs["frontend"], "Dependency audit (npm audit) — RED gate")
    assert len(fetch) == len(gate) == 1
    assert "fetch-npm-audit.sh" in fetch[0]["run"]
    assert "npm-audit-gate.mjs" not in fetch[0]["run"]
    assert "npm-audit-gate.mjs" in gate[0]["run"]
    assert "retry-egress.sh" not in gate[0]["run"]
    assert "npm audit" not in gate[0]["run"]

    forbidden_assertions = (
        "pytest ",
        "ruff ",
        "mypy",
        "git diff",
        "sha256sum",
        "coverage report",
        "npm-audit-gate.mjs",
    )
    for _job_name, _step_name, run in _run_blocks(workflow_text):
        for line in _executable_lines(run):
            if any(token in line for token in forbidden_assertions):
                assert "retry-egress.sh" not in line


def test_repository_workflow_egress_is_hardened() -> None:
    _assert_workflow_hardened(_WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "variant",
    [
        "pip install package",
        "pip3 install package",
        "python -m pip install package",
        "python3 -m pip install package",
        "python3.12 -m pip install package",
        "npm ci --ignore-scripts",
        "npm audit --json",
        "uv pip compile pyproject.toml",
        "pip-audit --strict",
        "osv-scanner scan .",
    ],
)
def test_structural_scanner_detects_unwrapped_syntax_variants(variant: str) -> None:
    assert _unwrapped_egress_lines(variant) == [variant]


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        ("retry-egress.sh", "retry-disabled.sh"),
        (_KUBECONFORM_SHA256, "0" * 64),
        (
            "node scripts/npm-audit-gate.mjs < npm-audit.json",
            "bash ci/scripts/retry-egress.sh -- node scripts/npm-audit-gate.mjs < npm-audit.json",
        ),
    ],
)
def test_workflow_contract_bites_on_mutation(target: str, replacement: str) -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    assert target in workflow
    mutated = workflow.replace(target, replacement, 1)
    with pytest.raises(AssertionError):
        _assert_workflow_hardened(mutated)


def test_helper_scripts_have_valid_bash_syntax() -> None:
    for script in (_RETRY, _VERIFIED_INSTALL, _NPM_AUDIT_FETCH):
        result = subprocess.run(
            [_BASH, "-n", script.as_posix()],
            cwd=_REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
