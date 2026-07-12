"""Juniper JunOS run through the reusable plugin conformance suite (ADR-0026).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
``make_conformance_cases``.  JunOS specifics:

- ``| display json`` structured output replaces TextFSM screen-scraping.
- No CDP — ``NEIGHBORS_CDP`` is not declared.
- ``CONFIG_RESTORE`` / ``CONFIG_DEPLOY`` bind to the JunOS
  ``candidate config + commit confirmed + rollback N`` transaction (ADR-0026 §3).
- Fixtures are source-derived, not live-recorded (ADR-0024 §5 convention).
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
from app.plugins.vendors.junos.plugin import (
    SHOW_CONFIGURATION_SET,
    SNMP_OID_SYSDESCR,
    SNMP_OID_SYSNAME,
    SNMP_OID_SYSOBJECTID,
    JunosPlugin,
)
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    FixtureSnmpTransport,
    make_conformance_cases,
)

FIXTURES = Path(__file__).parent / "fixtures" / "junos"
_RUNNING_CONFIG = (FIXTURES / "show_configuration_display_set.txt").read_text(encoding="utf-8")

#: Bundled recorded outputs keyed by exact device command (display json form).
_FIXTURE_FILES = {
    "show version | display json": "show_version_display_json.txt",
    "show interfaces | display json": "show_interfaces_display_json.txt",
    "show route | display json": "show_route_display_json.txt",
    "show lldp neighbors | display json": "show_lldp_neighbors_display_json.txt",
    "show configuration | display set": "show_configuration_display_set.txt",
    "show bgp neighbor | display json": "show_bgp_neighbor_display_json.txt",
    "show ospf neighbor | display json": "show_ospf_neighbor_display_json.txt",
    "show configuration firewall | display json": "show_configuration_firewall_display_json.txt",
}

#: Recorded system-MIB values for SNMP discovery.
_SNMP_FIXTURE_VALUES = {
    SNMP_OID_SYSDESCR: "Juniper Networks, Inc. MX480 internet router, kernel JUNOS 23.1R1.8",
    SNMP_OID_SYSOBJECTID: "1.3.6.1.4.1.2636.1.1.1.2.65",
    SNMP_OID_SYSNAME: "juniper-mx01.example.net",
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
    """Recorded :class:`ConfigWriteTransport` for the JunOS change-write conformance case.

    A minimal running-config state machine modelling the JunOS write surfaces
    (no device, no network — D16):

    - ``send_command("show configuration | display set")`` returns current config.
    - ``send_config(lines)`` MERGES the lines into the running config (union, no deletion)
      — models ``load merge`` + ``commit confirmed`` → confirm (deploy path).
    - ``replace_config(lines)`` REPLACES the running config with exactly the lines
      — models ``load override`` + ``commit confirmed`` → confirm (restore + rollback).
    """

    def __init__(self, running: str) -> None:
        self._running = running

    def send_command(self, command: str) -> str:
        if command == SHOW_CONFIGURATION_SET:
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
        return ""


def _executing_plan() -> ChangePlan:
    return ChangePlan(
        change_request_id=uuid4(), cr_state="executing", baseline_content_hash="sha-fixture"
    )


def _invoke_restore(impl: type[PluginCapability]) -> ChangeResult:
    # Device drifted on a *non-management* line so the restore applies.
    drifted = _RUNNING_CONFIG.replace(
        "set system host-name juniper-mx01", "set system host-name DRIFTED"
    )
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
    fragment = "set interfaces lo0 unit 0 family inet address 10.255.0.1/32\n"
    return cap.deploy(fragment, plan=_executing_plan())


CASES = make_conformance_cases(
    JunosPlugin(),
    capability_factory=_make_capability,
    change_write_invokers={
        Capability.CONFIG_RESTORE: _invoke_restore,
        Capability.CONFIG_DEPLOY: _invoke_deploy,
    },
)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_junos_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """All declared capabilities have typed interfaces — each must get
    both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in JunosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids


def test_cdp_not_declared() -> None:
    """JunOS does not implement CDP — NEIGHBORS_CDP must not be in the capability set."""
    assert Capability.NEIGHBORS_CDP not in JunosPlugin.capabilities
