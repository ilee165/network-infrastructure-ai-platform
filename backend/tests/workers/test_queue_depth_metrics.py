"""W3-T0 worker metrics: queue-depth sampler + the worker /metrics HTTP server.

``sample_queue_depths`` reads each work queue's Redis backlog (``LLEN``) and sets
the ``netops_celery_queue_depth`` gauge — the queue-stall saturation signal the
W3-T5 fault-injection perturbs. The sampler takes an injected client so it is
unit-testable with a fake (no Redis). ``start_worker_metrics_server`` degrades
gracefully when the port is already bound.
"""

from __future__ import annotations

import pytest

from app.core import metrics
from app.workers import celery_app as celery_app_module
from app.workers.celery_app import WORK_QUEUES, start_worker_metrics_server
from app.workers.tasks.system import sample_queue_depths


class _FakeRedis:
    """Minimal ``llen``-only Redis stand-in keyed by queue name."""

    def __init__(self, depths: dict[str, int]) -> None:
        self._depths = depths

    def llen(self, name: str) -> int:
        return self._depths.get(name, 0)


def _gauge(queue: str) -> float:
    return metrics.CELERY_QUEUE_DEPTH.labels(queue=queue)._value.get()  # type: ignore[attr-defined]


def test_sample_queue_depths_sets_each_queue_gauge() -> None:
    fake = _FakeRedis({"discovery": 12, "config": 3})
    observed = sample_queue_depths(fake, queues=("discovery", "config"))
    assert observed == {"discovery": 12, "config": 3}
    assert _gauge("discovery") == 12
    assert _gauge("config") == 3


def test_sample_queue_depths_covers_all_work_queues() -> None:
    fake = _FakeRedis({})
    observed = sample_queue_depths(fake)
    assert set(observed) == set(WORK_QUEUES)
    # An empty queue records a zero depth (not a missing series).
    for queue in WORK_QUEUES:
        assert _gauge(queue) == 0


def test_worker_metrics_server_starts() -> None:
    # Binding the HTTP server on a free high port succeeds (returns True).
    assert start_worker_metrics_server(9897) is True


def test_worker_metrics_server_degrades_on_bind_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bind failure (port held / permission) degrades to False, never raises.

    Guards the requirement that a metrics-server collision can NEVER take a worker
    down or stop it draining its queue.
    """

    def _boom(_port: int) -> None:
        raise OSError("address already in use")

    monkeypatch.setattr("prometheus_client.start_http_server", _boom)
    assert start_worker_metrics_server(9896) is False


def test_worker_init_signal_starts_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``worker_init`` handler starts the server on the configured port."""
    seen: dict[str, int] = {}
    monkeypatch.setattr(
        celery_app_module,
        "start_worker_metrics_server",
        lambda port: seen.setdefault("port", port) or True,
    )
    celery_app_module._start_metrics_on_worker_init()
    assert seen["port"] == celery_app_module.get_settings().worker_metrics_port
