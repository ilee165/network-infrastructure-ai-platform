"""Tests for the read-only application-impact Troubleshooting tool (P4 W2-T4, P8).

``get_application_impact`` answers "what depends on X" (and, for an application
target, "what does X depend on") over the projected graph, citing per claim the
asserting source(s), the compact provenance refs, and the ``projected_at``
watermark. It is READ_ONLY by classification and degrades to the house
``{"error": ...}`` object on a missing/unreachable graph or an unresolvable
target — a single missing evidence source never aborts a diagnosis.

No Neo4j: the knowledge-client seam is monkeypatched with a fake that answers
the two scoped statements ``_read_impact`` issues.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from neo4j.exceptions import ServiceUnavailable

from app.agents.framework.tools import ToolClassification
from app.agents.troubleshooting import tools as tools_module
from app.agents.troubleshooting.tools import TROUBLESHOOTING_TOOLS, get_application_impact
from app.knowledge.schema import LABEL_APPLICATION, LABEL_DEVICE

PROJECTED_AT = "2026-07-04T10:00:00+00:00"


class _FakeResult:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return self._gen()

    async def _gen(self) -> AsyncIterator[dict[str, Any]]:
        for record in self._records:
            yield record


class _FakeTx:
    def __init__(
        self, dependents: list[dict[str, Any]], dependencies: list[dict[str, Any]]
    ) -> None:
        self._dependents = dependents
        self._dependencies = dependencies

    async def run(self, cypher: str, **_params: Any) -> _FakeResult:
        if "app_labels" in cypher:
            return _FakeResult(self._dependents)
        if "DEPENDS_ON" in cypher:
            return _FakeResult(self._dependencies)
        raise AssertionError(f"unexpected cypher: {cypher}")


class _FakeClient:
    def __init__(
        self,
        dependents: list[dict[str, Any]] | None = None,
        dependencies: list[dict[str, Any]] | None = None,
    ) -> None:
        self._dependents = dependents or []
        self._dependencies = dependencies or []

    async def execute_read(self, work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await work(_FakeTx(self._dependents, self._dependencies), *args, **kwargs)


class _DeadClient:
    async def execute_read(self, *_args: Any, **_kwargs: Any) -> Any:
        raise ServiceUnavailable("neo4j is down")


def _dependent_record(app_key: str, target_key: str) -> dict[str, Any]:
    return {
        "app_labels": [LABEL_APPLICATION],
        "app_props": {
            "pg_id": app_key,
            "name": f"app-{app_key}",
            "last_projected_at": PROJECTED_AT,
        },
        "target_labels": [LABEL_DEVICE],
        "target_props": {"pg_id": target_key, "last_projected_at": PROJECTED_AT},
        "rel_props": {
            "sources": ["manual", "f5"],
            "provenance": ["manual:user:u1", "f5:adc_vs:/Common/vs_x"],
            "derived_at": PROJECTED_AT,
            "last_projected_at": PROJECTED_AT,
        },
    }


class TestGetApplicationImpactTool:
    async def test_get_application_impact_cites_source_refs_and_watermark_per_claim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            tools_module,
            "_knowledge_client",
            lambda: _FakeClient(dependents=[_dependent_record("a1", "dev-1")]),
        )
        raw = await get_application_impact.ainvoke({"target": "device:dev-1"})
        body = json.loads(raw)
        # The watermark ("as of run X") is cited at the top of the answer.
        assert body["as_of"] == PROJECTED_AT
        assert body["dependents"], "a dependent app was projected"
        for claim in body["dependents"]:
            # Every dependency claim cites its source(s) + evidence refs.
            assert claim["sources"] == ["manual", "f5"]
            assert claim["provenance"] == ["manual:user:u1", "f5:adc_vs:/Common/vs_x"]
            assert claim["derived_at"] == PROJECTED_AT

    async def test_get_application_impact_returns_error_object_when_graph_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tools_module, "_knowledge_client", lambda: _DeadClient())
        raw = await get_application_impact.ainvoke({"target": "device:dev-1"})
        body = json.loads(raw)
        # A missing/unreachable graph degrades to the house error object, never
        # an exception into the diagnosis loop.
        assert "error" in body
        assert body.get("dependents") is None

    async def test_get_application_impact_rejects_unresolvable_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An unresolvable target string is refused with an error naming the
        # accepted forms — without ever touching the graph.
        def _boom() -> Any:
            raise AssertionError("must not resolve a client for an unparseable target")

        monkeypatch.setattr(tools_module, "_knowledge_client", _boom)
        for bad in ("dev-1", "router:dev-1", "device:"):
            body = json.loads(await get_application_impact.ainvoke({"target": bad}))
            assert "error" in body

    async def test_get_application_impact_registered_read_only_classification(self) -> None:
        assert get_application_impact.classification is ToolClassification.READ_ONLY
        assert get_application_impact in TROUBLESHOOTING_TOOLS
