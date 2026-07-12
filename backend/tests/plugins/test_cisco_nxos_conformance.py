"""cisco_nxos run through the reusable plugin conformance suite (ADR-0025 §7).

Mirrors ``test_cisco_ios_conformance.py``: builds a capability factory over
the plugin's bundled NX-OS fixtures, then parametrizes over
:func:`make_conformance_cases`. Fixtures are sanitized public NX-OS CLI samples
(no credentials, no real addresses) clearly labeled in each file header.
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
from app.plugins.vendors.cisco_nxos.plugin import (
    SHOW_RUNNING_CONFIG,
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    CiscoNxosPlugin,
)
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    FixtureSnmpTransport,
    make_conformance_cases,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cisco_nxos"
_RUNNING_CONFIG = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")

#: Bundled recorded outputs keyed by exact device command.
_FIXTURE_FILES = {
    "show version": "show_version.txt",
    "show interface": "show_interface.txt",
    "show ip route vrf all": "show_ip_route_vrf_all.txt",
    "show cdp neighbors detail": "show_cdp_neighbors_detail.txt",
    "show lldp neighbors detail": "show_lldp_neighbors_detail.txt",
    "show running-config": "show_running_config.txt",
    "show ip bgp summary vrf all": "show_ip_bgp_summary_vrf_all.txt",
    "show ip ospf neighbor vrf all": "show_ip_ospf_neighbor_vrf_all.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
    # vPC is the one P1 command that uses the ``| json`` escape hatch (ADR-0025 §3/§8).
    "show vpc | json": "show_vpc_json.txt",
}

#: Recorded system-MIB values for SNMP discovery.
_SNMP_FIXTURE_VALUES = {
    SNMP_OID_SYSDESCR: (
        "Cisco NX-OS(tm) nxos64-cs, Software (nxos64-cs-release), "
        "Version 9.3(8), RELEASE SOFTWARE Copyright (c) 2002-2021"
    ),
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.9.12.3.1.3.1282",
    SNMP_OID_SYSNAME: "nxos-spine01",
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

    Models the NX-OS write surfaces (no device, no network):
    - ``send_config`` MERGES lines (union, no deletion) — the deploy apply surface.
    - ``replace_config`` REPLACES the running config — the restore / rollback surface.
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
    # Device drifted on a non-management line (hostname) only, so the restore
    # applies but the delta does not touch the management path (the guardrail
    # would otherwise refuse a mgmt-path change).
    drifted = _RUNNING_CONFIG.replace("hostname nxos-spine01", "hostname DRIFTED")
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
    fragment = "interface loopback0\n description conformance fixture\n"
    return cap.deploy(fragment, plan=_executing_plan())


CASES = make_conformance_cases(
    CiscoNxosPlugin(),
    capability_factory=_make_capability,
    change_write_invokers={
        Capability.CONFIG_RESTORE: _invoke_restore,
        Capability.CONFIG_DEPLOY: _invoke_deploy,
    },
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_cisco_nxos_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """All declared capabilities have typed interfaces — each must get
    both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in CiscoNxosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids
