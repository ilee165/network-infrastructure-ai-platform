"""Sandbox runtime posture hook (ADR-0031 §2 — the ``wf-implementer`` half of W3).

Pins the fail-closed contract: :func:`assert_sandbox_posture` refuses to let the
analysis worker spawn tshark when the OS-isolation posture is wrong (root UID,
CAP_NET_RAW in the permitted set, or a writable root filesystem). The OS calls
(``os.geteuid``, ``/proc/self/status``, ``/proc/self/mounts``) are mocked through
the module seams so the test runs on any host (including the non-Linux CI box).
"""

from __future__ import annotations

import pytest

from app.engines.packet import posture
from app.engines.packet.posture import CAP_NET_RAW_BIT, PostureError, assert_sandbox_posture

# A CapPrm mask WITH and WITHOUT NET_RAW (bit 13).
_CAP_WITH_NET_RAW = f"CapPrm:\t{(1 << CAP_NET_RAW_BIT):016x}\n"
_CAP_NO_CAPS = "CapPrm:\t0000000000000000\n"
_MOUNTS_RO = "rootfs / rootfs ro,relatime 0 0\n"
_MOUNTS_RW = "rootfs / rootfs rw,relatime 0 0\n"


def _patch(monkeypatch: pytest.MonkeyPatch, *, uid: int, status: str, mounts: str) -> None:
    monkeypatch.setattr(posture, "_effective_uid", lambda: uid)

    def _fake_read(path: str) -> str:
        if path == "/proc/self/status":
            return status
        if path == "/proc/self/mounts":
            return mounts
        return ""

    monkeypatch.setattr(posture, "_read_proc", _fake_read)


def test_posture_passes_when_hardened(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-root + no NET_RAW + read-only rootfs => no error (tshark may spawn)."""
    _patch(monkeypatch, uid=10001, status=_CAP_NO_CAPS, mounts=_MOUNTS_RO)
    assert_sandbox_posture(enforced=True)  # does not raise


def test_posture_disabled_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    """enforced=False short-circuits — the eager test/CI runner has no OS controls."""
    _patch(monkeypatch, uid=0, status=_CAP_WITH_NET_RAW, mounts=_MOUNTS_RW)
    assert_sandbox_posture(enforced=False)  # does not raise despite a bad posture


def test_posture_refuses_when_running_as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, uid=0, status=_CAP_NO_CAPS, mounts=_MOUNTS_RO)
    with pytest.raises(PostureError, match="root"):
        assert_sandbox_posture(enforced=True)


def test_posture_refuses_when_cap_net_raw_permitted(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, uid=10001, status=_CAP_WITH_NET_RAW, mounts=_MOUNTS_RO)
    with pytest.raises(PostureError, match="CAP_NET_RAW"):
        assert_sandbox_posture(enforced=True)


def test_posture_refuses_when_rootfs_writable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, uid=10001, status=_CAP_NO_CAPS, mounts=_MOUNTS_RW)
    with pytest.raises(PostureError, match="readOnlyRootFilesystem"):
        assert_sandbox_posture(enforced=True)


def test_posture_failclosed_on_missing_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing /proc (non-Linux host) reads as a posture failure, not a pass."""
    _patch(monkeypatch, uid=0, status="", mounts="")
    with pytest.raises(PostureError):
        assert_sandbox_posture(enforced=True)


def test_posture_error_carries_no_secret_material(monkeypatch: pytest.MonkeyPatch) -> None:
    """The failure message names only the failed control — no caps mask, no paths."""
    _patch(monkeypatch, uid=0, status=_CAP_WITH_NET_RAW, mounts=_MOUNTS_RW)
    with pytest.raises(PostureError) as exc_info:
        assert_sandbox_posture(enforced=True)
    message = str(exc_info.value)
    # All three controls reported, but no raw bitmask hex leaks into the message.
    assert "root" in message
    assert "CAP_NET_RAW" in message
    assert "readOnlyRootFilesystem" in message
    assert f"{(1 << CAP_NET_RAW_BIT):016x}" not in message
