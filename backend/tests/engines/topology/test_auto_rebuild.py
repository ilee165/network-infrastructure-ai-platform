"""Unit tests for the automated Neo4j rebuild reconciler (P3 W1-T3).

These cover the orchestration seam (staleness gate, textfile emission, the
rebuild vs no-op branch + exit code) WITHOUT any live store — the live
destroy-and-rebuild path is the W4-T4 drill. The metric-emitting full-rebuild
itself is covered by the M2 rebuild suite; here we inject fakes for the Neo4j
client + ``timed_rebuild`` so the reconcile logic is tested in isolation.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from app.engines.topology import auto_rebuild
from app.models.mixins import utcnow


class _FakeClient:
    """Minimal Neo4jClient stand-in: returns a canned freshness, records close()."""

    def __init__(self, freshness: tuple[int, Any]) -> None:
        self._freshness = freshness
        self.closed = False

    async def execute_read(self, work: Any, *args: Any, **kwargs: Any) -> Any:
        return self._freshness

    async def close(self) -> None:
        self.closed = True


# --- staleness gate -------------------------------------------------------


def test_empty_graph_is_always_stale() -> None:
    now = utcnow()
    # node_count 0 (post-recreate) re-projects even with a generous budget.
    assert auto_rebuild._is_stale(0, None, staleness_seconds=3600, now=now) is True


def test_never_projected_is_stale() -> None:
    now = utcnow()
    assert auto_rebuild._is_stale(5, None, staleness_seconds=3600, now=now) is True


def test_zero_budget_forces_rebuild() -> None:
    now = utcnow()
    newest = now - timedelta(seconds=1)
    assert auto_rebuild._is_stale(5, newest, staleness_seconds=0, now=now) is True


def test_fresh_graph_is_not_stale() -> None:
    now = utcnow()
    newest = now - timedelta(seconds=10)
    assert auto_rebuild._is_stale(5, newest, staleness_seconds=300, now=now) is False


def test_aged_graph_is_stale() -> None:
    now = utcnow()
    newest = now - timedelta(seconds=600)
    assert auto_rebuild._is_stale(5, newest, staleness_seconds=300, now=now) is True


# --- textfile emission (the scrapable topology-RTO) -----------------------


def test_write_textfile_emits_topology_rebuild_seconds(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "topology_rebuild_seconds.prom"
    auto_rebuild._write_textfile(str(target), seconds=12.5, nodes=7, edges=9, age_seconds=42.0)
    text = target.read_text(encoding="utf-8")
    # The load-bearing series the W4-T4 drill + G-OBS freshness SLO read.
    assert "topology_rebuild_seconds 12.500000" in text
    assert "topology_rebuild_nodes 7" in text
    assert "topology_rebuild_edges 9" in text
    assert "topology_graph_age_seconds 42.000000" in text
    # No half-written temp file left behind (atomic os.replace).
    assert list((tmp_path / "sub").glob(".topology_rebuild_*")) == []


# --- reconcile: rebuild vs no-op ------------------------------------------


@pytest.mark.asyncio
async def test_reconcile_rebuilds_on_empty_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _FakeClient((0, None))  # empty graph -> must rebuild.
    monkeypatch.setattr(auto_rebuild, "create_client", lambda settings: client)

    called: dict[str, bool] = {"timed_rebuild": False}

    async def _fake_timed_rebuild() -> dict[str, Any]:
        called["timed_rebuild"] = True
        return {"ok": True, "seconds": 3.0, "nodes": 4, "edges": 6}

    monkeypatch.setattr(auto_rebuild, "timed_rebuild", _fake_timed_rebuild)

    target = tmp_path / "topology_rebuild_seconds.prom"
    summary = await auto_rebuild.reconcile(metrics_textfile=str(target), staleness_seconds=300)

    assert called["timed_rebuild"] is True
    assert summary["rebuilt"] is True
    assert summary["seconds"] == 3.0
    assert summary["nodes"] == 4
    assert client.closed is True
    assert target.exists()
    assert "topology_rebuild_seconds 3.000000" in target.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_reconcile_rebuilds_stale_populated_graph_resets_age(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # nodes > 0 but the newest projection is older than the budget: a stale-but-
    # POPULATED graph. reconcile() must re-project AND emit the POST-rebuild age
    # (0), not the stale pre-rebuild age — this is the regression #1 fixes.
    newest = utcnow() - timedelta(seconds=600)
    client = _FakeClient((5, newest))  # populated but expired -> must rebuild.
    monkeypatch.setattr(auto_rebuild, "create_client", lambda settings: client)

    called: dict[str, bool] = {"timed_rebuild": False}

    async def _fake_timed_rebuild() -> dict[str, Any]:
        called["timed_rebuild"] = True
        return {"ok": True, "seconds": 2.0, "nodes": 5, "edges": 8}

    monkeypatch.setattr(auto_rebuild, "timed_rebuild", _fake_timed_rebuild)

    target = tmp_path / "topology_rebuild_seconds.prom"
    summary = await auto_rebuild.reconcile(metrics_textfile=str(target), staleness_seconds=300)

    assert called["timed_rebuild"] is True
    assert summary["rebuilt"] is True
    # The freshly re-projected graph is age 0 — NOT the stale ~600s pre-rebuild age.
    assert summary["graph_age_seconds"] == 0.0
    text = target.read_text(encoding="utf-8")
    assert "topology_graph_age_seconds 0.000000" in text


@pytest.mark.asyncio
async def test_reconcile_noop_when_graph_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    newest = utcnow() - timedelta(seconds=5)
    client = _FakeClient((11, newest))  # fresh graph -> no rebuild.
    monkeypatch.setattr(auto_rebuild, "create_client", lambda settings: client)

    async def _fail_timed_rebuild() -> dict[str, Any]:  # pragma: no cover
        raise AssertionError("timed_rebuild must NOT run when the graph is fresh")

    monkeypatch.setattr(auto_rebuild, "timed_rebuild", _fail_timed_rebuild)

    target = tmp_path / "topology_rebuild_seconds.prom"
    summary = await auto_rebuild.reconcile(metrics_textfile=str(target), staleness_seconds=300)

    assert summary["rebuilt"] is False
    assert summary["nodes"] == 11
    # Even on a no-op tick the textfile is written (continuous series + freshness).
    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "topology_rebuild_seconds 0.000000" in text
    assert "topology_graph_age_seconds" in text


def test_main_returns_nonzero_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(**kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("postgres unreachable")

    monkeypatch.setattr(auto_rebuild, "reconcile", _boom)
    rc = auto_rebuild.main(
        ["--metrics-textfile", str(tmp_path / "m.prom"), "--staleness-seconds", "0"]
    )
    assert rc == 1


def test_main_returns_zero_on_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _ok(**kwargs: Any) -> dict[str, Any]:
        return {
            "ok": True,
            "rebuilt": True,
            "seconds": 1.0,
            "nodes": 2,
            "edges": 3,
            "graph_age_seconds": 0.0,
            "staleness_seconds": 0.0,
        }

    monkeypatch.setattr(auto_rebuild, "reconcile", _ok)
    rc = auto_rebuild.main(
        ["--metrics-textfile", str(tmp_path / "m.prom"), "--staleness-seconds", "0"]
    )
    assert rc == 0
