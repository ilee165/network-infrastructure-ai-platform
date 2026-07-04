"""Guard: the shared api/worker image stages ship NO tshark (ADR-0049 blocker 7).

The executor-split closes the unconfined-parse hole only while tshark's
CVE-bearing C dissectors exist solely in the ``packet-analysis`` image stage.
The synchronous ``GET /captures/{id}/analysis`` endpoint is fail-closed when
``packet_sandbox_posture_enforced`` is on precisely because the API pod has no
tshark — so "just install tshark on the api pod" would silently reopen the
exact unconfined parse ADR-0049 closed. This test pins the Dockerfile stage
split: any tshark reference appearing in a non-``packet-analysis`` stage's
instructions fails the suite.
"""

from __future__ import annotations

import re
from pathlib import Path

# backend/tests/engines/packet/ -> repo root is four levels up.
_REPO_ROOT = Path(__file__).resolve().parents[4]
_DOCKERFILE = _REPO_ROOT / "deploy" / "docker" / "backend.Dockerfile"

_FROM_RE = re.compile(r"^\s*FROM\s+\S+(?:\s+AS\s+(?P<name>\S+))?\s*$", re.IGNORECASE)


def _stages() -> dict[str, list[str]]:
    """Split the backend Dockerfile into per-stage instruction lines.

    Comment lines are dropped so prose *mentioning* tshark (e.g. the header
    explaining the stage split) never trips the guard — only instructions do.
    """
    stages: dict[str, list[str]] = {}
    current: str | None = None
    for raw in _DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _FROM_RE.match(line)
        if match:
            current = match.group("name") or f"<anonymous-{len(stages)}>"
            stages[current] = []
            continue
        if current is not None:
            stages[current].append(line)
    return stages


def test_shared_api_worker_stages_install_no_tshark() -> None:
    """No stage other than ``packet-analysis`` may reference tshark/wireshark."""
    stages = _stages()
    # Structural pin: the expected stages exist (a rename must update this guard
    # deliberately, not dodge it).
    assert {"builder", "runtime", "packet-analysis"} <= stages.keys()
    for name, lines in stages.items():
        if name == "packet-analysis":
            continue
        body = "\n".join(lines).lower()
        assert "tshark" not in body and "wireshark" not in body, (
            f"Dockerfile stage {name!r} references tshark/wireshark — the shared "
            "api/worker image must never carry the dissectors (ADR-0049 blocker 7); "
            "tshark belongs ONLY in the packet-analysis stage."
        )


def test_packet_analysis_stage_does_install_tshark() -> None:
    """Positive control: the guard's parser actually sees the tshark install."""
    body = "\n".join(_stages()["packet-analysis"]).lower()
    assert "tshark" in body
