"""Arista EOS run through the reusable plugin conformance suite (M1-11).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
:func:`make_conformance_cases`.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from app.plugins.base import DiscoverySnmpCapability, PluginCapability
from app.plugins.vendors.eos.plugin import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    EosPlugin,
)
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    FixtureSnmpTransport,
    make_conformance_cases,
)

FIXTURES = Path(__file__).parent / "fixtures" / "eos"

#: Bundled recorded outputs keyed by exact device command.
_FIXTURE_FILES = {
    "show version": "show_version.txt",
    "show interfaces": "show_interfaces.txt",
    "show ip route": "show_ip_route.txt",
    "show lldp neighbors detail": "show_lldp_neighbors_detail.txt",
    "show running-config": "show_running_config.txt",
    "show ip bgp summary": "show_ip_bgp_summary.txt",
    "show ip ospf neighbor": "show_ip_ospf_neighbor.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
}

#: Recorded system-MIB values for SNMP discovery (same lab leaf switch).
_SNMP_FIXTURE_VALUES = {
    SNMP_OID_SYSDESCR: (
        "Arista Networks EOS version 4.28.3M running on an Arista Networks DCS-7050TX-64"
    ),
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.30065.1.3011.7050",
    SNMP_OID_SYSNAME: "leaf01.example.net",
}


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    if issubclass(impl, DiscoverySnmpCapability):
        return impl(FixtureSnmpTransport(_SNMP_FIXTURE_VALUES), uuid4())
    responses = {
        command: (FIXTURES / filename).read_text(encoding="utf-8")
        for command, filename in _FIXTURE_FILES.items()
    }
    return impl(FixtureReplayTransport(responses), uuid4())


CASES = make_conformance_cases(EosPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_eos_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """All declared capabilities have typed interfaces — each must get
    both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in EosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids


def test_cdp_not_declared() -> None:
    """EOS does not implement CDP — NEIGHBORS_CDP must not be in the capability set."""
    from app.plugins.base import Capability

    assert Capability.NEIGHBORS_CDP not in EosPlugin.capabilities
