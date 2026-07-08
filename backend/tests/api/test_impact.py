"""Tests for the topology impact API (P4 W2-T4, rider P7): GET /topology/impact.

Runs in-process over the shared ``tests/api/conftest.py`` fixtures — no
Postgres, Neo4j, or network. The Neo4j read path is a small impact-specific
fake knowledge client injected via ``app.api.deps.get_knowledge_client``: it
answers the dependents query (``app_labels`` in RETURN) and the Application-only
dependencies query, so the endpoint's validation, auth floor, and
schema/provenance serialization are under test rather than stubbed out.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
from fastapi import FastAPI

from app.api import deps
from app.knowledge.schema import LABEL_APPLICATION, LABEL_DEVICE

PROJECTED_AT = "2026-07-04T10:00:00+00:00"


# ---------------------------------------------------------------------------
# Impact-specific fake knowledge client
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        return self._gen()

    async def _gen(self) -> AsyncIterator[dict[str, Any]]:
        for record in self._records:
            yield record


class _FakeImpactTx:
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


class FakeImpactClient:
    def __init__(
        self,
        dependents: list[dict[str, Any]] | None = None,
        dependencies: list[dict[str, Any]] | None = None,
    ) -> None:
        self._dependents = dependents or []
        self._dependencies = dependencies or []

    async def execute_read(self, work: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await work(_FakeImpactTx(self._dependents, self._dependencies), *args, **kwargs)


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


def _dependency_record(target_key: str) -> dict[str, Any]:
    return {
        "target_labels": [LABEL_DEVICE],
        "target_props": {"pg_id": target_key, "last_projected_at": PROJECTED_AT},
        "rel_props": {
            "sources": ["f5"],
            "provenance": ["f5:adc_vs:/Common/vs_x"],
            "derived_at": PROJECTED_AT,
            "last_projected_at": PROJECTED_AT,
        },
    }


def _override(app: FastAPI, client: FakeImpactClient) -> None:
    app.dependency_overrides[deps.get_knowledge_client] = lambda: client


def _http(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://testserver")


IMPACT_URL = "/api/v1/topology/impact"


class TestImpactEndpoint:
    async def test_impact_endpoint_allows_viewer_and_rejects_anonymous(
        self, app: FastAPI, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        _override(app, FakeImpactClient(dependents=[_dependent_record("a1", "dev-1")]))
        async with _http(app) as client:
            ok = await client.get(
                IMPACT_URL,
                params={"target_kind": "device", "target_ref": "dev-1"},
                headers=auth_headers("viewer"),
            )
            assert ok.status_code == 200, ok.text

            anon = await client.get(
                IMPACT_URL, params={"target_kind": "device", "target_ref": "dev-1"}
            )
            assert anon.status_code == 401

    async def test_impact_application_target_serializes_populated_dependencies(
        self, app: FastAPI, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        # An Application target drives the reverse direction: assert a non-empty
        # ``dependencies`` list round-trips through the ``ImpactDependency``
        # (extra="forbid") schema, not just the empty case (PR #119 review).
        _override(app, FakeImpactClient(dependencies=[_dependency_record("dev-7")]))
        async with _http(app) as client:
            resp = await client.get(
                IMPACT_URL,
                params={"target_kind": "application", "target_ref": "app-1"},
                headers=auth_headers("viewer"),
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert [d["target"]["key"] for d in body["dependencies"]] == ["dev-7"]
            dep = body["dependencies"][0]
            assert dep["target"]["label"] == LABEL_DEVICE
            assert dep["sources"] == ["f5"]
            assert dep["provenance"] == ["f5:adc_vs:/Common/vs_x"]

    async def test_impact_endpoint_validates_target_kind_and_depth(
        self, app: FastAPI, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        _override(app, FakeImpactClient())
        async with _http(app) as client:
            headers = auth_headers("viewer")
            bad_kind = await client.get(
                IMPACT_URL, params={"target_kind": "router", "target_ref": "x"}, headers=headers
            )
            assert bad_kind.status_code == 422, bad_kind.text

            over_depth = await client.get(
                IMPACT_URL,
                params={"target_kind": "device", "target_ref": "x", "depth": 99},
                headers=headers,
            )
            assert over_depth.status_code == 422, over_depth.text

            zero_depth = await client.get(
                IMPACT_URL,
                params={"target_kind": "device", "target_ref": "x", "depth": 0},
                headers=headers,
            )
            assert zero_depth.status_code == 422, zero_depth.text

    async def test_impact_endpoint_response_matches_schema_with_provenance(
        self, app: FastAPI, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        _override(app, FakeImpactClient(dependents=[_dependent_record("a1", "dev-1")]))
        async with _http(app) as client:
            response = await client.get(
                IMPACT_URL,
                params={"target_kind": "device", "target_ref": "dev-1", "depth": 3},
                headers=auth_headers("viewer"),
            )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["target"] == {"label": "Device", "key": "dev-1"}
        assert body["depth_used"] == 3
        assert body["projected_at"] == PROJECTED_AT
        assert body["dependencies"] == []
        assert len(body["dependents"]) == 1
        dep = body["dependents"][0]
        assert dep["application"]["key"] == "a1"
        assert dep["target"] == {"label": "Device", "key": "dev-1"}
        # Every impact edge cites its source(s) + a provenance summary (§8).
        assert dep["sources"] == ["manual", "f5"]
        assert dep["provenance"] == ["manual:user:u1", "f5:adc_vs:/Common/vs_x"]
        assert dep["derived_at"] == PROJECTED_AT

    async def test_impact_endpoint_absent_target_is_empty_not_error(
        self, app: FastAPI, auth_headers: Callable[[str], dict[str, str]]
    ) -> None:
        _override(app, FakeImpactClient(dependents=[], dependencies=[]))
        async with _http(app) as client:
            response = await client.get(
                IMPACT_URL,
                params={"target_kind": "application", "target_ref": "missing"},
                headers=auth_headers("viewer"),
            )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["dependents"] == []
        assert body["dependencies"] == []
        assert body["projected_at"] is None
