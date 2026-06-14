"""cisco_iosxe run through the reusable plugin conformance suite (M1-07).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
:func:`make_conformance_cases`. New plugins (eos, …) copy this module and
swap the plugin class and fixture map.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from app.plugins.base import DiscoverySnmpCapability, PluginCapability
from app.plugins.vendors.cisco_iosxe.plugin import (
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    CiscoIosXePlugin,
)
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    FixtureSnmpTransport,
    make_conformance_cases,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_iosxe"

#: Bundled recorded outputs keyed by exact device command.
_FIXTURE_FILES = {
    "show version": "show_version.txt",
    "show interfaces": "show_interfaces.txt",
    "show ip route": "show_ip_route.txt",
    "show cdp neighbors detail": "show_cdp_neighbors_detail.txt",
    "show lldp neighbors detail": "show_lldp_neighbors_detail.txt",
    "show running-config": "show_running_config.txt",
    "show ip bgp summary": "show_ip_bgp_summary.txt",
    "show ip ospf neighbor": "show_ip_ospf_neighbor.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
}

#: Recorded system-MIB values for SNMP discovery (Cat9k).
_SNMP_FIXTURE_VALUES = {
    SNMP_OID_SYSDESCR: (
        "Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_IOSXE), "
        "Version 17.6.4, RELEASE SOFTWARE (fc1)"
    ),
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.9.1.2957",
    SNMP_OID_SYSNAME: "core-sw01.example.net",
}


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    if issubclass(impl, DiscoverySnmpCapability):
        return impl(FixtureSnmpTransport(_SNMP_FIXTURE_VALUES), uuid4())
    responses = {
        command: (FIXTURES / filename).read_text(encoding="utf-8")
        for command, filename in _FIXTURE_FILES.items()
    }
    return impl(FixtureReplayTransport(responses), uuid4())


CASES = make_conformance_cases(CiscoIosXePlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_cisco_iosxe_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """All declared capabilities have typed interfaces — each must get
    both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in CiscoIosXePlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids
