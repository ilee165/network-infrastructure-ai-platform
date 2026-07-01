"""W3-T0 metrics: the ``netops_*`` series, helper setters, and the no-op degrade.

These assert the series exist with the ADR-0046 §1 names + bounded labels, that the
helper setters move the values, and that every helper is a safe no-op when
``prometheus_client`` is reported absent (the graceful-degrade contract, mirrored
from the KEK gauges). Values are read from the metric objects directly (not by
scraping /metrics) so the assertions are isolated from other tests' increments.
"""

from __future__ import annotations

import importlib

import pytest

from app.core import metrics


def _counter_value(counter: object, **labels: str) -> float:
    """Read a labelled Counter's current total from the metric object."""
    return counter.labels(**labels)._value.get()  # type: ignore[attr-defined]


def test_adr0046_series_names_are_registered() -> None:
    """Every §1 base series exists under its canonical ADR-0046 name."""
    names = {
        metrics.HTTP_REQUESTS_TOTAL,
        metrics.HTTP_REQUEST_DURATION_SECONDS,
        metrics.DISCOVERY_RUNS_TOTAL,
        metrics.DISCOVERY_DURATION_SECONDS,
        metrics.LLM_REQUESTS_TOTAL,
        metrics.LLM_TOKENS_TOTAL,
        metrics.LLM_LATENCY_SECONDS,
        metrics.AGENT_FIRST_TOKEN_SECONDS,
        metrics.CHANGE_REQUESTS_TOTAL,
        metrics.CHANGE_REQUEST_APPROVAL_LATENCY_SECONDS,
        metrics.CELERY_QUEUE_DEPTH,
    }
    # prometheus_client is a hard runtime dep, so the real objects must be present.
    assert None not in names
    # Canonical names the W3-T2 recording rules derive from (ADR-0046 §1).
    assert metrics.HTTP_REQUESTS_TOTAL._name == "netops_http_requests"  # type: ignore[attr-defined]
    assert metrics.DISCOVERY_RUNS_TOTAL._name == "netops_discovery_runs"  # type: ignore[attr-defined]
    assert metrics.CELERY_QUEUE_DEPTH._name == "netops_celery_queue_depth"  # type: ignore[attr-defined]


def test_status_class_buckets_to_class() -> None:
    assert metrics.status_class_for(200) == "2xx"
    assert metrics.status_class_for(404) == "4xx"
    assert metrics.status_class_for(503) == "5xx"


def test_observe_http_request_increments_by_status_class() -> None:
    before = _counter_value(
        metrics.HTTP_REQUESTS_TOTAL, method="GET", route="/probe/{id}", status_class="2xx"
    )
    metrics.observe_http_request(
        method="GET", route="/probe/{id}", status_code=204, duration_seconds=0.01
    )
    after = _counter_value(
        metrics.HTTP_REQUESTS_TOTAL, method="GET", route="/probe/{id}", status_class="2xx"
    )
    assert after == before + 1


def test_observe_discovery_run_increments_status() -> None:
    before = _counter_value(metrics.DISCOVERY_RUNS_TOTAL, status="succeeded")
    metrics.observe_discovery_run(status="succeeded", duration_seconds=1.5)
    assert _counter_value(metrics.DISCOVERY_RUNS_TOTAL, status="succeeded") == before + 1


def test_observe_llm_request_counts_and_tokens() -> None:
    before = _counter_value(metrics.LLM_REQUESTS_TOTAL, profile="local", model="m")
    before_in = _counter_value(metrics.LLM_TOKENS_TOTAL, profile="local", direction="input")
    metrics.observe_llm_request(
        profile="local", model="m", latency_seconds=0.2, input_tokens=10, output_tokens=4
    )
    assert _counter_value(metrics.LLM_REQUESTS_TOTAL, profile="local", model="m") == before + 1
    assert (
        _counter_value(metrics.LLM_TOKENS_TOTAL, profile="local", direction="input")
        == before_in + 10
    )


def test_record_change_request_transition_counts_state() -> None:
    before = _counter_value(metrics.CHANGE_REQUESTS_TOTAL, state="approved")
    metrics.record_change_request_transition(state="approved", approval_latency_seconds=42.0)
    assert _counter_value(metrics.CHANGE_REQUESTS_TOTAL, state="approved") == before + 1


def test_set_celery_queue_depth_sets_gauge() -> None:
    metrics.set_celery_queue_depth(queue="discovery", depth=7)
    assert metrics.CELERY_QUEUE_DEPTH.labels(queue="discovery")._value.get() == 7  # type: ignore[attr-defined]


def test_observe_agent_first_token_records() -> None:
    # Just assert it does not raise and the sample count advances.
    h = metrics.AGENT_FIRST_TOKEN_SECONDS.labels(profile="local")
    before = h._sum.get()  # type: ignore[attr-defined]
    metrics.observe_agent_first_token(profile="local", seconds=0.3)
    assert h._sum.get() == pytest.approx(before + 0.3)  # type: ignore[attr-defined]


def test_helpers_are_noops_when_prometheus_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """With ``_PROM_ENABLED`` false every helper is a safe no-op (slim-install path)."""
    monkeypatch.setattr(metrics, "_PROM_ENABLED", False)
    # None of these touch the (still-real) metric objects, so none raises.
    metrics.observe_http_request(method="GET", route="/x", status_code=200, duration_seconds=0.0)
    metrics.observe_discovery_run(status="failed", duration_seconds=1.0)
    metrics.observe_llm_request(profile="local", model="m", input_tokens=1)
    metrics.observe_agent_first_token(profile="local", seconds=0.1)
    metrics.record_change_request_transition(state="draft")
    metrics.set_celery_queue_depth(queue="docs", depth=3)
    metrics.set_provider_healthy(healthy=True)


def _unregister_module_collectors(mod: object) -> None:
    """Drop the module's collectors from the default REGISTRY so a reload is clean.

    The default REGISTRY persists across an ``importlib.reload``; without this the
    reload re-registers the same series names and prometheus_client raises a
    Duplicated-timeseries error. Tests that reload :mod:`app.core.metrics` must
    clear its collectors first.
    """
    import contextlib

    from prometheus_client import REGISTRY

    for name in mod.__all__:  # type: ignore[attr-defined]
        obj = getattr(mod, name, None)
        # Only the metric OBJECTS are collectors (helpers/strings are not).
        if obj is not None and hasattr(obj, "_name"):
            with contextlib.suppress(KeyError):
                REGISTRY.unregister(obj)


def test_module_imports_without_prometheus(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing the module with ``prometheus_client`` hidden degrades to no-ops.

    Simulates a slim install: the ImportError branch must set every series to
    ``None`` and ``_PROM_ENABLED`` to False without raising at import time.
    """
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "prometheus_client":
            raise ImportError("simulated slim install")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    # Free the names the real module registered so the slim reload's body (and the
    # later restore reload) do not collide on the default REGISTRY.
    _unregister_module_collectors(metrics)
    monkeypatch.setattr(builtins, "__import__", _fake_import)
    slim = importlib.reload(metrics)
    try:
        assert slim._PROM_ENABLED is False
        assert slim.HTTP_REQUESTS_TOTAL is None
        assert slim.CELERY_QUEUE_DEPTH is None
        # Helpers are no-ops, not crashes.
        slim.observe_http_request(method="GET", route="/x", status_code=200, duration_seconds=0.0)
    finally:
        # Restore the real (prometheus-enabled) module for the rest of the suite.
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(metrics)
