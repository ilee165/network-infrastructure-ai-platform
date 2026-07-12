"""cisco_iosxe run through the reusable plugin conformance suite (M1-07).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
:func:`make_conformance_cases`. New plugins (eos, …) copy this module and
swap the plugin class and fixture map.
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
from app.plugins.vendors.cisco_iosxe.plugin import (
    SHOW_RUNNING_CONFIG,
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
_RUNNING_CONFIG = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")

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


class _ConfigWriteFixtureTransport:
    """Recorded :class:`ConfigWriteTransport` for the change-write conformance case.

    A minimal running-config state machine modelling the REAL IOS-XE write surfaces
    (no device, no network — D16):

    - ``send_config`` MERGES the lines into the running config (union, no deletion)
      — the deploy apply surface (send_config_set / configure terminal).
    - ``replace_config`` REPLACES the running config with exactly the lines
      — the restore apply / rollback surface (configure replace + commit-confirm).

    so verify-after confirms the intended end-state for both capabilities.
    """

    def __init__(self, running: str) -> None:
        self._running = running

    def send_command(self, command: str) -> str:
        if command == SHOW_RUNNING_CONFIG:
            return self._running
        raise AssertionError(f"unexpected command sent to device: {command!r}")

    def send_config(self, lines: Sequence[str]) -> str:
        present = self._running.splitlines()
        present_set = set(present)
        merged = present + [line for line in lines if line not in present_set]
        self._running = "\n".join(merged) + "\n"
        return ""

    def replace_config(self, lines: Sequence[str]) -> str:
        self._running = "\n".join(lines) + "\n"
        return ""

    def confirm_config(self) -> str:
        return ""

    def rollback_config(self, n: int = 1) -> str:
        raise NotImplementedError("use replace_config for baseline rollback")


def _executing_plan() -> ChangePlan:
    return ChangePlan(
        change_request_id=uuid4(), cr_state="executing", baseline_content_hash="sha-fixture"
    )


def _invoke_restore(impl: type[PluginCapability]) -> ChangeResult:
    # Device drifted on a *non-management* line (hostname) so the restore applies.
    drifted = _RUNNING_CONFIG.replace("hostname core-sw01", "hostname DRIFTED")
    transport = _ConfigWriteFixtureTransport(drifted)
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
    CiscoIosXePlugin(),
    capability_factory=_make_capability,
    change_write_invokers={
        Capability.CONFIG_RESTORE: _invoke_restore,
        Capability.CONFIG_DEPLOY: _invoke_deploy,
    },
)


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
