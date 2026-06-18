"""Arista EOS run through the reusable plugin conformance suite (M1-11).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
:func:`make_conformance_cases`.
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
from app.plugins.vendors.eos.plugin import (
    SHOW_RUNNING_CONFIG,
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
_RUNNING_CONFIG = (FIXTURES / "show_running_config.txt").read_text(encoding="utf-8")

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


class _ConfigWriteFixtureTransport:
    """Recorded :class:`ConfigWriteTransport` for the EOS change-write conformance case.

    A minimal running-config state machine modelling the REAL EOS write surfaces
    (no device, no network — D16):

    - ``send_config`` MERGES the lines into the running config (union, no deletion)
      — the deploy apply surface (config session commit).
    - ``replace_config`` REPLACES the running config with exactly the lines
      — the restore apply / rollback surface (configure replace / baseline session).

    EOS comment headers (``! Command: ...`` / ``! device: ...``) are present in the
    fixture file and stripped by :func:`_normalize_config` before equality comparison.
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


def _executing_plan() -> ChangePlan:
    return ChangePlan(
        change_request_id=uuid4(), cr_state="executing", baseline_content_hash="sha-fixture"
    )


def _invoke_restore(impl: type[PluginCapability]) -> ChangeResult:
    # Device drifted on a *non-management* line (hostname) so the restore applies.
    drifted = _RUNNING_CONFIG.replace("hostname leaf01", "hostname DRIFTED")
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
    fragment = "interface Loopback0\n   description conformance fixture\n"
    return cap.deploy(fragment, plan=_executing_plan())


CASES = make_conformance_cases(
    EosPlugin(),
    capability_factory=_make_capability,
    change_write_invokers={
        Capability.CONFIG_RESTORE: _invoke_restore,
        Capability.CONFIG_DEPLOY: _invoke_deploy,
    },
)


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
    assert Capability.NEIGHBORS_CDP not in EosPlugin.capabilities
