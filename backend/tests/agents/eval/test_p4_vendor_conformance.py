"""P4 W4-T1 vendor conformance + routing no-regression (deterministic CI).

The vendor/plugin matrix and the supervisor's specialist roster are separate
contracts.  P4 adds the F5 BIG-IP and VMware plugins, while routing remains the
same nine-agent matrix recorded for P3.  The real-LLM routing-quality run stays
manual in ``test_routing_eval.py``; this module proves its new cases are wired to
real vendor capabilities and live routing targets without requiring a model.
"""

from __future__ import annotations

import importlib
import json
import runpy
from pathlib import Path
from typing import Any

import pytest

from app.agents import build_default_registry
from app.agents.framework.supervisor import SUPERVISOR_NAME
from app.plugins.base import Capability, VendorPlugin
from app.plugins.registry import get_default_registry
from app.plugins.vendors.vmware.plugin import VmwarePlugin
from tests.plugins import conformance as plugin_conformance
from tests.plugins import test_vmware_conformance as vmware_conformance
from tests.plugins.conformance import ConformanceCase, make_conformance_cases

pytestmark = [pytest.mark.eval]

_FIXTURE_DIR = Path(__file__).parent / "fixtures"
_MATRIX_PATH = _FIXTURE_DIR / "p4_vendor_conformance_matrix.json"
_ROUTING_EVAL_PATH = Path(__file__).with_name("test_routing_eval.py")

_EXPECTED_WAVE3_CAPABILITIES = {
    "f5_bigip": {
        "adc_services",
        "config_backup_archive",
        "config_restore_archive",
        "discovery_api",
        "ha_status",
        "interfaces",
        "routes",
    },
    "vmware": {"discovery_api", "virtualization_inventory"},
}

_EXPECTED_ROUTING_CASES = {
    "p4-f5-bigip-adc-inventory": ("f5_bigip", Capability.ADC_SERVICES, "discovery"),
    "p4-vmware-virtualization-inventory": (
        "vmware",
        Capability.VIRTUALIZATION_INVENTORY,
        "discovery",
    ),
}


def _load_matrix() -> dict[str, Any]:
    return json.loads(_MATRIX_PATH.read_text(encoding="utf-8"))


def _load_p3_routing_baseline(matrix: dict[str, Any]) -> dict[str, Any]:
    path = _FIXTURE_DIR / matrix["_meta"]["p3_routing_baseline"]
    return json.loads(path.read_text(encoding="utf-8"))


def _live_routing_matrix() -> dict[str, dict[str, str]]:
    return {
        agent.name: {tool.name: tool.classification.value for tool in agent.tools}
        for agent in build_default_registry().list()
        if agent.name != SUPERVISOR_NAME
    }


def _assert_fixture_case_completeness(plugin: VendorPlugin, cases: list[ConformanceCase]) -> None:
    helper = getattr(plugin_conformance, "assert_fixture_case_completeness", None)
    assert callable(helper), (
        "tests.plugins.conformance must expose the opt-in assert_fixture_case_completeness helper"
    )
    helper(plugin, cases)


def _run_pinned_conformance_matrix(matrix: dict[str, Any]) -> None:
    """Validate module ownership, then run every pinned vendor's real cases."""
    expected = matrix["p3_baseline"] | matrix["p4_additions"]
    registry = get_default_registry()
    results: dict[str, str] = {}

    assert set(registry.vendor_ids()) == set(expected)
    for vendor_id, record in sorted(expected.items()):
        live_capabilities = {
            capability.value for capability in registry.capabilities_for(vendor_id)
        }
        assert live_capabilities == set(record["capabilities"])

        canonical_module = f"tests.plugins.test_{vendor_id}_conformance"
        assert record["conformance_module"] == canonical_module, (
            f"{vendor_id}: conformance_module must be canonical {canonical_module!r}; "
            f"got {record['conformance_module']!r}"
        )
        module = importlib.import_module(canonical_module)
        cases: list[ConformanceCase] = module.CASES
        ids = {case.id for case in cases}
        assert ids >= {f"implementation:{capability}" for capability in record["capabilities"]}
        for case in cases:
            case.run()
        results[vendor_id] = "passed"

    assert results == {vendor_id: record["result"] for vendor_id, record in expected.items()}


def test_p4_vendor_matrix_extends_p3_by_exactly_f5_and_vmware() -> None:
    """The current vendor roster is the pinned P3 matrix plus two named additions."""
    matrix = _load_matrix()
    baseline = matrix["p3_baseline"]
    additions = matrix["p4_additions"]
    registry = get_default_registry()

    assert set(additions) == set(_EXPECTED_WAVE3_CAPABILITIES)
    assert {case["id"] for case in matrix["routing_cases"]} == set(_EXPECTED_ROUTING_CASES)
    assert set(registry.vendor_ids()) - set(baseline) == set(additions), (
        "live vendor delta from the pinned P3 baseline must be exactly "
        f"f5_bigip + vmware; live={list(registry.vendor_ids())} "
        f"baseline={sorted(baseline)}"
    )
    assert set(registry.vendor_ids()) == set(baseline) | set(additions)

    for vendor_id, expected in _EXPECTED_WAVE3_CAPABILITIES.items():
        recorded = set(additions[vendor_id]["capabilities"])
        live = {capability.value for capability in registry.capabilities_for(vendor_id)}
        assert recorded == expected
        assert live == expected


def test_every_installed_plugin_runs_real_pinned_conformance_cases() -> None:
    """Re-run conformance cases for the complete P3+P4 installed-plugin matrix."""
    _run_pinned_conformance_matrix(_load_matrix())


def test_vendor_conformance_module_substitution_is_rejected() -> None:
    """Bite proof: a same-capability vendor module cannot certify another vendor."""
    matrix = _load_matrix()
    matrix["p3_baseline"]["bluecat"]["conformance_module"] = (
        "tests.plugins.test_infoblox_conformance"
    )

    with pytest.raises(AssertionError, match=r"bluecat.*canonical.*test_bluecat_conformance"):
        _run_pinned_conformance_matrix(matrix)


def test_routing_roster_and_allow_lists_match_the_recorded_p3_baseline() -> None:
    """P4 adds vendor drivers, not a tenth routable agent or new agent tools."""
    matrix = _load_matrix()
    baseline = _load_p3_routing_baseline(matrix)
    live = _live_routing_matrix()

    assert set(live) == set(baseline["roster"])
    assert len(live) == matrix["_meta"]["expected_routing_roster_count"] == 9
    assert live == baseline["allow_lists"]
    assert not (set(matrix["p4_additions"]) & set(live)), (
        "vendor plugins are drivers and must not become routable specialists"
    )


@pytest.mark.parametrize("case", _load_matrix()["routing_cases"], ids=lambda case: case["id"])
def test_vendor_surface_case_declares_live_capability_and_existing_target(
    case: dict[str, str],
) -> None:
    """Each new prompt names a real vendor surface and a live existing specialist."""
    declared = _EXPECTED_ROUTING_CASES[case["id"]]
    vendor_id, capability, expected_specialist = declared
    live_roster = set(_live_routing_matrix())
    registry = get_default_registry()

    assert (case["vendor_id"], Capability(case["capability"]), case["expected_specialist"]) == (
        vendor_id,
        capability,
        expected_specialist,
    )
    assert capability in registry.capabilities_for(vendor_id)
    assert expected_specialist in live_roster
    assert vendor_id not in live_roster
    assert case["prompt"].strip()


def test_manual_routing_eval_consumes_the_vendor_surface_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opt-in real-LLM consumer includes the same deterministic case corpus."""
    monkeypatch.setenv("NETOPS_RUN_ROUTING_EVAL", "1")
    namespace = runpy.run_path(str(_ROUTING_EVAL_PATH))
    manual_cases = {tuple(case) for case in namespace["_CASES"]}
    expected = {
        (case["prompt"], case["expected_specialist"]) for case in _load_matrix()["routing_cases"]
    }
    assert expected <= manual_cases, (
        f"manual routing eval is missing P4 vendor case(s): {sorted(expected - manual_cases)}"
    )


@pytest.mark.parametrize(
    ("vendor_id", "module_name"),
    [
        ("f5_bigip", "tests.plugins.test_f5_bigip_conformance"),
        ("vmware", "tests.plugins.test_vmware_conformance"),
    ],
)
def test_wave3_plugins_opt_in_to_fixture_case_completeness(
    vendor_id: str, module_name: str
) -> None:
    """Every capability declared by the two P4 plugins has a fixture family."""
    registry = get_default_registry()
    plugin = registry.get_plugin(vendor_id)
    module = importlib.import_module(module_name)
    _assert_fixture_case_completeness(plugin, module.CASES)


def test_missing_vmware_interface_spec_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bite proof: silent fixture-family omission is rejected inside green."""
    monkeypatch.delitem(
        plugin_conformance._INTERFACE_SPECS,
        Capability.VIRTUALIZATION_INVENTORY,
    )
    plugin = VmwarePlugin()
    cases = make_conformance_cases(
        plugin,
        capability_factory=vmware_conformance._make_capability,
    )

    with pytest.raises(AssertionError, match=r"vmware.*virtualization_inventory"):
        _assert_fixture_case_completeness(plugin, cases)
