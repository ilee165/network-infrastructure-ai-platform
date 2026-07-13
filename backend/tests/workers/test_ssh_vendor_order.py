"""Wave 5 T1: SSH vendor try-order prefers known inventory vendor."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.plugins.base import Capability
from app.workers.tasks.discovery import _ssh_vendor_candidates


def test_preferred_vendor_is_first() -> None:
    registry = MagicMock()
    registry.vendor_ids.return_value = ["cisco_ios", "eos", "junos", "cisco_nxos"]

    def _plugin(vid: str) -> MagicMock:
        p = MagicMock()
        p.supports.return_value = True
        return p

    registry.get_plugin.side_effect = _plugin
    ordered = _ssh_vendor_candidates(registry, preferred_vendor="junos")
    assert ordered[0] == "junos"
    assert set(ordered) == {"cisco_ios", "eos", "junos", "cisco_nxos"}


def test_unknown_preferred_keeps_registry_order() -> None:
    registry = MagicMock()
    registry.vendor_ids.return_value = ["cisco_ios", "eos"]
    p = MagicMock()
    p.supports.return_value = True
    registry.get_plugin.return_value = p
    assert _ssh_vendor_candidates(registry, preferred_vendor="nope") == [
        "cisco_ios",
        "eos",
    ]


def test_skips_vendors_without_ssh_discovery() -> None:
    registry = MagicMock()
    registry.vendor_ids.return_value = ["a", "b"]

    def _plugin(vid: str) -> MagicMock:
        p = MagicMock()
        p.supports.side_effect = lambda cap: vid == "b" and cap is Capability.DISCOVERY_SSH
        return p

    registry.get_plugin.side_effect = _plugin
    assert _ssh_vendor_candidates(registry) == ["b"]
