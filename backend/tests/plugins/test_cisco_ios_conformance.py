"""cisco_ios run through the reusable plugin conformance suite (M1-07).

The template every vendor plugin test package follows: build a capability
factory over the plugin's bundled fixtures, then parametrize over
:func:`make_conformance_cases`. New plugins (cisco_iosxe, eos, …) copy this
module and swap the plugin class and fixture map.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from app.plugins.base import PluginCapability
from app.plugins.vendors.cisco_ios.plugin import CiscoIosPlugin
from tests.plugins.conformance import (
    ConformanceCase,
    FixtureReplayTransport,
    make_conformance_cases,
)

FIXTURES = Path(__file__).parent / "fixtures"

#: Bundled recorded outputs keyed by exact device command — the same fixture
#: files the cisco_ios parser tests replay.
_FIXTURE_FILES = {
    "show interfaces": "show_interfaces.txt",
    "show ip route": "show_ip_route.txt",
    "show cdp neighbors detail": "show_cdp_neighbors_detail.txt",
    "show lldp neighbors detail": "show_lldp_neighbors_detail.txt",
    "show running-config": "show_running_config.txt",
}


def _make_capability(impl: type[PluginCapability]) -> PluginCapability:
    responses = {
        command: (FIXTURES / filename).read_text(encoding="utf-8")
        for command, filename in _FIXTURE_FILES.items()
    }
    return impl(FixtureReplayTransport(responses), uuid4())


CASES = make_conformance_cases(CiscoIosPlugin(), capability_factory=_make_capability)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_cisco_ios_conformance(case: ConformanceCase) -> None:
    case.run()


def test_suite_covers_every_declared_capability() -> None:
    """All five declared capabilities have typed interfaces — each must get
    both an implementation case and a bundled-fixture case."""
    ids = {case.id for case in CASES}
    for capability in CiscoIosPlugin.capabilities:
        assert f"implementation:{capability.value}" in ids
        assert f"fixtures:{capability.value}" in ids
