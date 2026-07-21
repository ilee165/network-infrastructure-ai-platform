"""Exact application-derivation corpus gate (P4 W4-T2, ADR-0052)."""

from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
from typing import Any

import pytest
from pydantic import ValidationError

from tests.agents.eval import app_derivation_eval as app_eval

pytestmark = pytest.mark.eval


def _one_edge_graph() -> dict[str, Any]:
    return {
        "applications": [
            {
                "key": "origin:f5:device-1:/Common/payroll.example.com",
                "name": "payroll.example.com",
                "description": "Payroll VIP",
                "fqdns": ["payroll.example.com"],
                "origin": "derived",
                "origin_ref": "f5:device-1:/Common/payroll.example.com",
                "owner": None,
            }
        ],
        "edges": [
            {
                "app_key": "origin:f5:device-1:/Common/payroll.example.com",
                "target_label": "IPAddress",
                "target_key": "interface-1",
                "sources": ["f5"],
                "provenance_by_source": {
                    "f5": [
                        {"kind": "virtual_server", "ref": "vs-1"},
                        {"kind": "pool", "ref": "pool-1"},
                        {"kind": "member", "ref": "/Common/web01:443"},
                        {"kind": "interface", "ref": "interface-1"},
                    ]
                },
                "compact_provenance": [
                    "f5:virtual_server:vs-1",
                    "f5:pool:pool-1",
                    "f5:member:/Common/web01:443",
                    "f5:interface:interface-1",
                ],
                "derived_at": "2026-07-20T12:00:00+00:00",
            }
        ],
    }


def test_exact_graph_score_uses_exact_arithmetic_and_accepts_full_equality() -> None:
    expected = _one_edge_graph()

    result = app_eval.evaluate_graph(expected, expected)

    assert result.precision == Fraction(1, 1)
    assert result.recall == Fraction(1, 1)
    assert result.graph_equal is True
    assert result.accepted is True


def test_planted_valid_wrong_endpoint_lowers_precision_and_is_rejected() -> None:
    expected = _one_edge_graph()
    actual = deepcopy(expected)
    wrong = deepcopy(actual["edges"][0])
    wrong["target_key"] = "interface-wrong"
    actual["edges"].append(wrong)

    result = app_eval.evaluate_graph(actual, expected)

    assert result.precision == Fraction(1, 2)
    assert result.recall == Fraction(1, 1)
    assert result.accepted is False


def test_metadata_mutation_with_identical_endpoints_fails_full_graph_equality() -> None:
    expected = _one_edge_graph()
    actual = deepcopy(expected)
    actual["edges"][0]["provenance_by_source"]["f5"][1]["ref"] = "pool-corrupt"

    result = app_eval.evaluate_graph(actual, expected)

    assert result.precision == Fraction(1, 1)
    assert result.recall == Fraction(1, 1)
    assert result.graph_equal is False
    assert result.accepted is False


def test_empty_endpoint_sets_are_scored_explicitly() -> None:
    empty: dict[str, Any] = {"applications": [], "edges": []}
    expected = _one_edge_graph()

    empty_match = app_eval.evaluate_graph(empty, empty)
    missed = app_eval.evaluate_graph(empty, expected)
    unexpected = app_eval.evaluate_graph(expected, empty)

    assert (empty_match.precision, empty_match.recall, empty_match.accepted) == (
        Fraction(1, 1),
        Fraction(1, 1),
        True,
    )
    assert (missed.precision, missed.recall, missed.accepted) == (
        Fraction(1, 1),
        Fraction(0, 1),
        False,
    )
    assert (unexpected.precision, unexpected.recall, unexpected.accepted) == (
        Fraction(0, 1),
        Fraction(1, 1),
        False,
    )


def _suppress_source(estate: dict[str, Any], source: str) -> dict[str, Any]:
    mutated = deepcopy(estate)
    if source == "f5":
        mutated["virtual_servers"] = []
        mutated["pools"] = []
    elif source == "vmware":
        mutated["virtual_machines"] = []
        mutated["hypervisor_hosts"] = []
    elif source == "dns":
        mutated["dns_records"] = []
    elif source == "manual":
        mutated["manual_dependencies"] = []
    else:  # pragma: no cover - test helper has a closed parametrization
        raise AssertionError(source)
    return mutated


def test_input_estate_contains_no_expected_output_oracle_and_graph_matches_contract() -> None:
    estate = app_eval.load_estate()
    contract = app_eval.load_expected_contract()
    expected = app_eval.load_expected_graph()

    assert set(estate["_meta"]) == {
        "collected_at",
        "manual_derived_at",
        "t0",
        "t1",
        "projection_at",
        "wrong_edge_target",
    }
    result = app_eval.derive_corpus(estate)
    score = app_eval.evaluate_graph(result.graph, expected)

    assert score.precision == score.recall == Fraction(1, 1)
    assert score.graph_equal is True
    assert score.accepted is True
    assert result.plan.stats.model_dump(mode="json") == contract["expected_stats"]


def test_estate_adapter_rejects_missing_fields_and_invalid_nested_members() -> None:
    missing_protocol = app_eval.load_estate()
    del missing_protocol["virtual_servers"][0]["protocol"]
    with pytest.raises(KeyError, match="protocol"):
        app_eval.build_estate_rows(missing_protocol)

    invalid_member = app_eval.load_estate()
    invalid_member["pools"][0]["members"][0]["availability"] = "invented-state"
    with pytest.raises(ValidationError, match="availability"):
        app_eval.build_estate_rows(invalid_member)


def test_manual_rows_have_one_fixed_actor_matching_user_provenance() -> None:
    estate = app_eval.load_estate()
    actor_id = estate["manual_actor"]["id"]

    assert {row["created_by"] for row in estate["applications"]} == {actor_id}
    assert {row["created_by"] for row in estate["manual_dependencies"]} == {actor_id}
    assert {
        step["ref"]
        for row in estate["manual_dependencies"]
        for step in row["provenance"]
        if step["kind"] == "user"
    } == {actor_id}

    rows = app_eval.build_estate_rows(estate)
    assert {str(row.created_by) for row in rows.applications} == {actor_id}
    assert {str(row.created_by) for row in rows.manual_dependencies} == {actor_id}


def test_corpus_has_source_exclusive_edges_and_manual_rows_are_seeded_union() -> None:
    result = app_eval.derive_corpus(app_eval.load_estate())

    exclusive = {
        source
        for edge in result.graph["edges"]
        if len(edge["sources"]) == 1
        for source in edge["sources"]
    }
    assert exclusive == {"f5", "vmware", "dns", "manual"}
    assert all(dependency.source != "manual" for dependency in result.plan.dependencies)
    assert any("manual" in edge["sources"] for edge in result.graph["edges"])


def test_interactions_manual_wins_route_domain_and_explicit_exclusions() -> None:
    estate = app_eval.load_estate()
    graph = app_eval.derive_corpus(estate).graph
    meta = app_eval.load_expected_contract()
    applications = {app["key"]: app for app in graph["applications"]}
    edges = {
        (edge["app_key"], edge["target_label"], edge["target_key"]): edge for edge in graph["edges"]
    }

    retail = applications[meta["retail_app_key"]]
    assert retail == meta["retail_manual_wins_payload"]
    shared = edges[tuple(meta["shared_edge_key"])]
    assert shared["sources"] == ["dns", "f5", "manual"]

    route_edge = edges[tuple(meta["route_fqdn_vmware_edge_key"])]
    assert route_edge["sources"] == ["vmware"]
    assert route_edge["provenance_by_source"]["vmware"][2] == {
        "kind": "member",
        "ref": "/Common/rd2-routevm:443",
    }
    assert tuple(meta["route_domain_forbidden_edge_key"]) not in edges

    for app_key in meta["edge_free_exclusion_app_keys"]:
        assert app_key in applications
        assert not any(edge[0] == app_key for edge in edges)


def test_every_edge_carries_exact_source_provenance_and_fixed_watermark() -> None:
    graph = app_eval.derive_corpus(app_eval.load_estate()).graph

    for edge in graph["edges"]:
        assert edge["sources"] == sorted(edge["sources"])
        assert sorted(edge["provenance_by_source"]) == edge["sources"]
        compact = [
            f"{source}:{step['kind']}:{step['ref']}"
            for source in edge["sources"]
            for step in edge["provenance_by_source"][source]
        ]
        assert edge["compact_provenance"] == compact
        assert edge["derived_at"].endswith("+00:00")


def test_planted_wrong_edge_rejects_the_real_corpus_precision_gate() -> None:
    estate = app_eval.load_estate()
    expected = app_eval.load_expected_graph()
    actual = deepcopy(app_eval.derive_corpus(estate).graph)
    wrong = deepcopy(actual["edges"][0])
    wrong["target_label"], wrong["target_key"] = estate["_meta"]["wrong_edge_target"]
    estate_targets = {
        *(("Device", row["id"]) for row in estate["devices"]),
        *(("IPAddress", row["id"]) for row in estate["interfaces"]),
    }
    assert (wrong["target_label"], wrong["target_key"]) in estate_targets
    actual["edges"].append(wrong)

    result = app_eval.evaluate_graph(actual, expected)

    assert result.precision < Fraction(1, 1)
    assert result.recall == Fraction(1, 1)
    assert result.accepted is False


@pytest.mark.parametrize("source", ["f5", "vmware", "dns", "manual"])
def test_suppressing_each_estate_input_source_rejects_recall(source: str) -> None:
    estate = app_eval.load_estate()
    contract = app_eval.load_expected_contract()
    expected = app_eval.load_expected_graph()
    baseline = app_eval.derive_corpus(estate).graph
    actual = app_eval.derive_corpus(_suppress_source(estate, source)).graph
    exclusive_key = tuple(contract["source_exclusive_edge_keys"][source])
    baseline_edges = {
        (edge["app_key"], edge["target_label"], edge["target_key"]): edge
        for edge in baseline["edges"]
    }
    actual_edges = {
        (edge["app_key"], edge["target_label"], edge["target_key"]): edge
        for edge in actual["edges"]
    }

    assert baseline_edges[exclusive_key]["sources"] == [source]
    assert exclusive_key not in actual_edges
    assert all(source not in edge["sources"] for edge in actual["edges"])
    assert all(source not in edge["provenance_by_source"] for edge in actual["edges"])
    assert all(
        not any(ref.startswith(f"{source}:") for ref in edge["compact_provenance"])
        for edge in actual["edges"]
    )

    result = app_eval.evaluate_graph(actual, expected)

    assert result.recall < Fraction(1, 1), f"{source} suppression did not create a miss"
    assert result.accepted is False


def test_real_corpus_provenance_mutation_is_rejected_with_perfect_endpoints() -> None:
    expected = app_eval.load_expected_graph()
    actual = deepcopy(app_eval.derive_corpus(app_eval.load_estate()).graph)
    actual["edges"][0]["compact_provenance"][0] += ":corrupt"

    result = app_eval.evaluate_graph(actual, expected)

    assert result.precision == result.recall == Fraction(1, 1)
    assert result.graph_equal is False
    assert result.accepted is False


def test_corpus_is_deterministic_under_input_permutation() -> None:
    estate = app_eval.load_estate()
    reversed_estate = deepcopy(estate)
    for key in (
        "devices",
        "interfaces",
        "virtual_servers",
        "pools",
        "virtual_machines",
        "hypervisor_hosts",
        "dns_records",
        "applications",
        "manual_dependencies",
    ):
        reversed_estate[key].reverse()
    for pool in reversed_estate["pools"]:
        pool["members"].reverse()

    assert app_eval.derive_corpus(estate).graph == app_eval.derive_corpus(reversed_estate).graph
