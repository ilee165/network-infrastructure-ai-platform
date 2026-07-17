"""Behavioral bite proofs for the shared render-twice helpers."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_EXTRACTOR = _REPO_ROOT / "ci" / "lib" / "extract-rendered-secret.py"
_COMMON = _REPO_ROOT / "ci" / "lib" / "render-twice-common.sh"
_RENDER_SCRIPTS = {
    "cnpg": _REPO_ROOT / "ci" / "cnpg" / "render-twice.sh",
    "mtls": _REPO_ROOT / "ci" / "mtls" / "render-twice.sh",
    "redis": _REPO_ROOT / "ci" / "redis-sentinel" / "render-twice.sh",
}
_LEGACY_HELPERS = {
    _REPO_ROOT / "ci" / "cnpg" / "extract_stringdata.py",
    _REPO_ROOT / "ci" / "mtls" / "extract_secret.py",
    _REPO_ROOT / "ci" / "mtls" / "test_extract_secret.py",
}


def _bash_executable() -> str:
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


def _run_extractor(
    tmp_path: Path,
    mode: str,
    manifest: str,
    secret_name: str = "target-secret",
    key: str = "credential",
) -> subprocess.CompletedProcess[bytes]:
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text(manifest, encoding="utf-8", newline="\n")
    return subprocess.run(
        [sys.executable, str(_EXTRACTOR), mode, str(rendered), secret_name, key],
        cwd=_REPO_ROOT,
        check=False,
        capture_output=True,
    )


def _secret(*, name: str, block: str, key: str, value: str) -> str:
    return f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: {name}\n{block}:\n  {key}: {value}\n"


def test_data_mode_strictly_decodes_secret_bytes(tmp_path: Path) -> None:
    expected = b"certificate\x00bytes\n"
    manifest = _secret(
        name="target-secret",
        block="data",
        key="credential",
        value=base64.b64encode(expected).decode("ascii"),
    )

    result = _run_extractor(tmp_path, "data", manifest)

    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == expected


def test_data_mode_rejects_corrupt_base64(tmp_path: Path) -> None:
    manifest = _secret(
        name="target-secret",
        block="data",
        key="credential",
        value="not!base64",
    )

    result = _run_extractor(tmp_path, "data", manifest)

    assert result.returncode == 1
    assert result.stdout == b""
    assert b"valid base64" in result.stderr


@pytest.mark.parametrize(
    ("rendered", "expected"),
    [
        ("plain-value", b"plain-value"),
        ('"quoted value"', b"quoted value"),
        ("'single quoted value'", b"single quoted value"),
    ],
)
def test_stringdata_mode_returns_plain_or_quoted_value(
    tmp_path: Path, rendered: str, expected: bytes
) -> None:
    manifest = _secret(
        name="target-secret",
        block="stringData",
        key="credential",
        value=rendered,
    )

    result = _run_extractor(tmp_path, "stringData", manifest)

    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == expected


def test_secret_kind_and_direct_metadata_name_are_both_required(tmp_path: Path) -> None:
    decoy_configmap = (
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: target-secret\n"
        "data:\n"
        f"  credential: {base64.b64encode(b'WRONG-KIND').decode()}\n"
    )
    decoy_nested_name = (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: another-secret\n"
        "  ownerReferences:\n"
        "    - apiVersion: v1\n"
        "      kind: Secret\n"
        "      name: target-secret\n"
        "data:\n"
        f"  credential: {base64.b64encode(b'WRONG-NAME').decode()}\n"
    )
    real = _secret(
        name="target-secret",
        block="data",
        key="credential",
        value=base64.b64encode(b"right-secret").decode(),
    )

    result = _run_extractor(
        tmp_path,
        "data",
        "---\n" + decoy_configmap + "---\n" + decoy_nested_name + "---\n" + real,
    )

    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == b"right-secret"


def test_duplicate_matching_secrets_are_blocking(tmp_path: Path) -> None:
    """Two rendered Secrets with the target name must fail, not first-match."""
    first = _secret(name="target-secret", block="stringData", key="credential", value="first")
    second = _secret(name="target-secret", block="stringData", key="credential", value="second")

    result = _run_extractor(tmp_path, "stringData", first + "---\n" + second)

    assert result.returncode == 1
    assert b"matched 2 rendered documents" in result.stderr


def test_duplicate_direct_key_is_blocking(tmp_path: Path) -> None:
    """A duplicated key inside the target block must fail: a first-match read can
    disagree with the last-wins value Kubernetes would actually deploy."""
    manifest = (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: target-secret\n"
        "stringData:\n"
        "  credential: first\n"
        "  credential: last-wins-in-kubernetes\n"
    )

    result = _run_extractor(tmp_path, "stringData", manifest)

    assert result.returncode == 1
    assert b"duplicate key 'credential'" in result.stderr


def test_missing_key_is_blocking(tmp_path: Path) -> None:
    manifest = _secret(
        name="target-secret",
        block="data",
        key="another-key",
        value=base64.b64encode(b"value").decode(),
    )

    result = _run_extractor(tmp_path, "data", manifest)

    assert result.returncode == 1
    assert b"credential" in result.stderr
    assert b"target-secret" in result.stderr


def test_render_scripts_use_one_shared_helper_and_explicit_extractor_modes() -> None:
    assert _EXTRACTOR.is_file()
    assert _COMMON.is_file()
    assert not any(path.exists() for path in _LEGACY_HELPERS)

    common = _COMMON.read_text(encoding="utf-8")
    for duplicated_fragment in ("mktemp -d", "command -v python3", "ok()", "bad()"):
        assert common.count(duplicated_fragment) == 1

    expected_modes = {"cnpg": "stringData", "mtls": "data", "redis": "stringData"}
    for name, script in _RENDER_SCRIPTS.items():
        text = script.read_text(encoding="utf-8")
        assert "render-twice-common.sh" in text
        assert f"extract_rendered_secret {expected_modes[name]}" in text
        assert "render_twice_require_nonempty" in text
        assert "render_twice_finish" in text
        for duplicated_fragment in ("mktemp -d", "command -v python3", "ok()", "bad()"):
            assert duplicated_fragment not in text


def test_shared_nonempty_and_failure_summary_checks_bite(tmp_path: Path) -> None:
    probe = tmp_path / "probe.sh"
    probe.write_text(
        "#!/usr/bin/env bash\n"
        f"source '{_COMMON.as_posix()}'\n"
        "render_twice_init\n"
        ': > "${WORK}/empty.yaml"\n'
        'if render_twice_require_nonempty "${WORK}/empty.yaml"; then exit 91; fi\n'
        'bad "planted render violation"\n'
        'if render_twice_finish "test render" "test guard"; then exit 92; fi\n'
        'echo "bite-observed"\n',
        encoding="utf-8",
        newline="\n",
    )

    result = subprocess.run(
        [_BASH, probe.as_posix()],
        cwd=_REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "empty manifest" in result.stderr
    assert "planted render violation" in result.stderr
    assert "found 1 violation" in result.stderr
    assert "bite-observed" in result.stdout


def test_shared_shell_helpers_have_valid_bash_syntax() -> None:
    for script in (*_RENDER_SCRIPTS.values(), _COMMON):
        result = subprocess.run(
            [_BASH, "-n", script.as_posix()],
            cwd=_REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
