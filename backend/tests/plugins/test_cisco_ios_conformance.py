"""cisco_ios run through the reusable plugin conformance suite (M1-07).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
:func:`make_conformance_cases`. New plugins (cisco_iosxe, eos, …) copy this
module and swap the plugin class and fixture map.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

import pytest

from app.plugins.base import (
    Capability,
    ChangePlan,
    ChangeResult,
    ConfigDeployCapability,
    ConfigRestoreCapability,
    DiscoverySnmpCapability,
    PluginCapability,
)
from app.plugins.vendors.cisco_ios.plugin import (
    SHOW_RUNNING_CONFIG,
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    CiscoIosPlugin,
)
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    FixtureSnmpTransport,
    make_conformance_cases,
)

FIXTURES = Path(__file__).parent / "fixtures"
_RUNNING_CONFIG = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")

#: Bundled recorded outputs keyed by exact device command — the same fixture
#: files the cisco_ios parser tests replay.
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

#: Recorded system-MIB values for SNMP discovery (same lab switch).
_SNMP_FIXTURE_VALUES = {
    SNMP_OID_SYSDESCR: (
        "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
        "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)"
    ),
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.9.1.716",
    SNMP_OID_SYSNAME: "dist-sw01.example.net",
}


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    if issubclass(impl, DiscoverySnmpCapability):
        return impl(FixtureSnmpTransport(_SNMP_FIXTURE_VALUES), uuid4())
    responses = {
        command: (FIXTURES / filename).read_text(encoding="utf-8")
        for command, filename in _FIXTURE_FILES.items()
    }
    return impl(FixtureReplayTransport(responses), uuid4())


class _ConfigWriteFixtureTransport:
    """Recorded :class:`ConfigWriteTransport` for the change-write conformance case.

    A minimal running-config state machine: ``send_config`` replaces the running
    config with the applied lines (restore/replace semantics) so verify-after
    confirms the intended end-state — no device, no network (D16).
    """

    def __init__(self, running: str) -> None:
        self._running = running

    def send_command(self, command: str) -> str:
        if command == SHOW_RUNNING_CONFIG:
            return self._running
        raise AssertionError(f"unexpected command sent to device: {command!r}")

    def send_config(self, lines: Sequence[str]) -> str:
        self._running = "\n".join(lines) + "\n"
        return ""


def _executing_plan() -> ChangePlan:
    return ChangePlan(
        change_request_id=uuid4(), cr_state="executing", baseline_content_hash="sha-fixture"
    )


def _invoke_restore(impl: type[PluginCapability]) -> ChangeResult:
    # Device starts on a *different* config so the restore actually applies.
    transport = _ConfigWriteFixtureTransport("hostname DIFFERENT\n!\nend\n")
    cap = impl(transport, uuid4())
    assert isinstance(cap, ConfigRestoreCapability)

    class _Snapshot:
        content = _RUNNING_CONFIG
        content_hash = "sha-fixture-snapshot"

    return cap.restore(_Snapshot(), plan=_executing_plan())


def _invoke_deploy(impl: type[PluginCapability]) -> ChangeResult:
    transport = _ConfigWriteFixtureTransport(_RUNNING_CONFIG)
    cap = impl(transport, uuid4())
    assert isinstance(cap, ConfigDeployCapability)
    fragment = "interface Loopback0\n description conformance fixture\n"
    return cap.deploy(fragment, plan=_executing_plan())


CASES = make_conformance_cases(
    CiscoIosPlugin(),
    capability_factory=_make_capability,
    change_write_invokers={
        Capability.CONFIG_RESTORE: _invoke_restore,
        Capability.CONFIG_DEPLOY: _invoke_deploy,
    },
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_cisco_ios_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """All declared capabilities have typed interfaces — each must get
    both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in CiscoIosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids
