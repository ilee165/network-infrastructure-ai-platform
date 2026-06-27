#!/usr/bin/env python3
"""Tests for extract_secret.py — the N9 (metadata-scoped name) + N10 (strict
base64) hardening from PR #76.

Run: python3 -m pytest ci/mtls/test_extract_secret.py   (stdlib + pytest only).
Also runnable as a plain script (no pytest) for the CI infra job:
    python3 ci/mtls/test_extract_secret.py
"""

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("extract_secret", _HERE / "extract_secret.py")
assert _spec and _spec.loader
extract_secret = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extract_secret)


def _run(tmp_path: Path, text: str, name: str, key: str, capsys=None) -> tuple[int, bytes]:
    """Invoke main() against a rendered manifest; return (rc, captured stdout bytes)."""
    path = tmp_path / "rendered.yaml"
    path.write_text(text, encoding="utf-8")
    argv = ["extract_secret.py", str(path), name, key]
    old_argv = sys.argv
    sys.argv = argv
    # Capture the raw stdout bytes (main writes via sys.stdout.buffer).
    import io

    buf = io.BytesIO()
    real_stdout = sys.stdout

    class _Wrap:
        def __init__(self, b: io.BytesIO) -> None:
            self.buffer = b

    sys.stdout = _Wrap(buf)  # type: ignore[assignment]
    try:
        rc = extract_secret.main()
    finally:
        sys.stdout = real_stdout
        sys.argv = old_argv
    return rc, buf.getvalue()


def _secret_doc(name: str, key: str, value_b64: str, extra_names: str = "") -> str:
    return (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        f"  name: {name}\n"
        f"{extra_names}"
        "data:\n"
        f"  {key}: {value_b64}\n"
    )


def test_extracts_metadata_name_match(tmp_path):
    secret = "hello-world"
    doc = _secret_doc("netops-db-client-tls", "tls.crt", base64.b64encode(secret.encode()).decode())
    rc, out = _run(tmp_path, doc, "netops-db-client-tls", "tls.crt")
    assert rc == 0
    assert out == secret.encode()


def test_n9_does_not_match_unrelated_name_field(tmp_path):
    """N9: a Secret whose metadata.name differs but which carries an unrelated
    `name:` (e.g. an ownerReference) equal to the target must NOT be selected."""
    secret = "right-secret"
    # This Secret's metadata.name is the WRONG one, but it has an ownerReferences
    # entry whose `name:` equals the target — the old 'any name:' match would pick
    # it. The metadata-scoped match must skip it.
    decoy = (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        "  name: some-other-secret\n"
        "  ownerReferences:\n"
        "    - apiVersion: v1\n"
        "      kind: ConfigMap\n"
        "      name: netops-db-client-tls\n"
        "data:\n"
        "  tls.crt: " + base64.b64encode(b"WRONG").decode() + "\n"
    )
    real = _secret_doc("netops-db-client-tls", "tls.crt", base64.b64encode(secret.encode()).decode())
    rc, out = _run(tmp_path, decoy + "\n---\n" + real, "netops-db-client-tls", "tls.crt")
    assert rc == 0, "should find the REAL Secret by metadata.name, not the decoy"
    assert out == secret.encode(), "must not return the decoy's WRONG value (N9)"


def test_n10_strict_base64_rejects_corruption(tmp_path):
    """N10: a corrupt (non-base64) data value must FAIL the gate, not silently
    decode to mangled bytes."""
    doc = _secret_doc("netops-db-client-tls", "tls.crt", "not!valid!base64!!")
    rc, out = _run(tmp_path, doc, "netops-db-client-tls", "tls.crt")
    assert rc == 1, "corrupt base64 must return non-zero (N10)"
    assert out == b""


def test_missing_secret_returns_nonzero(tmp_path):
    doc = _secret_doc("netops-db-client-tls", "tls.crt", base64.b64encode(b"x").decode())
    rc, _ = _run(tmp_path, doc, "no-such-secret", "tls.crt")
    assert rc == 1


def _main() -> int:
    import tempfile

    failures = 0
    for fn in (
        test_extracts_metadata_name_match,
        test_n9_does_not_match_unrelated_name_field,
        test_n10_strict_base64_rejects_corruption,
        test_missing_secret_returns_nonzero,
    ):
        with tempfile.TemporaryDirectory() as d:
            try:
                fn(Path(d))
                print(f"PASS: {fn.__name__}")
            except AssertionError as exc:  # noqa: PERF203
                print(f"FAIL: {fn.__name__}: {exc}", file=sys.stderr)
                failures += 1
    if failures:
        print(f"== {failures} test(s) failed ==", file=sys.stderr)
        return 1
    print("all extract_secret tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
