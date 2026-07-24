"""Contracts for hardened Celery canvas publication."""

from __future__ import annotations

from typing import Any

import pytest
from celery import chord, signature

from app.workers.dispatch import DispatchPublicationError, durable_dispatch_canvas


def _discovery_chord() -> Any:
    return chord(
        [
            signature("discovery.collect_device", args=("run-id", "10.0.0.1")),
            signature("discovery.collect_device", args=("run-id", "10.0.0.2")),
        ],
        signature(
            "discovery.continue_wave",
            args=("run-id", 0, [], {}, {}, ["10.0.0.1", "10.0.0.2"], 1.0),
        ),
    )


def test_canvas_dispatch_preserves_chord_signatures_and_implicit_routing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canvas = _discovery_chord()
    before = dict(canvas)
    published: list[tuple[tuple[object, ...], dict[str, object]]] = []
    sentinel = object()

    def _publish(*args: object, **kwargs: object) -> object:
        published.append((args, kwargs))
        return sentinel

    monkeypatch.setattr(canvas, "apply_async", _publish)

    assert durable_dispatch_canvas(canvas) is sentinel
    assert published == [((), {})]
    assert dict(canvas) == before


def test_canvas_dispatch_preserves_config_chord_task_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canvas = chord(
        [
            signature(
                "config.capture_device",
                args=("device-id", "scheduled", "run-id"),
            )
        ],
        signature(
            "config.finalize_backup_wave",
            args=("run-id", ["device-id"]),
        ),
    )
    before = dict(canvas)
    monkeypatch.setattr(canvas, "apply_async", lambda: "published")

    assert durable_dispatch_canvas(canvas) == "published"
    assert dict(canvas) == before


@pytest.mark.parametrize(
    "canvas",
    [
        chord(
            [signature("system.unapproved")],
            signature("discovery.continue_wave"),
        ),
        chord(
            [signature("config.capture_device", queue="discovery")],
            signature("config.finalize_backup_wave"),
        ),
        chord(
            [signature("discovery.collect_device")],
            signature("config.finalize_backup_wave"),
        ),
        chord(
            [signature("discovery.collect_device")],
            signature("discovery.continue_wave"),
        ).set(queue="system"),
    ],
)
def test_canvas_dispatch_rejects_unapproved_tasks_queues_and_mixed_chords(canvas: Any) -> None:
    with pytest.raises(ValueError, match="canvas_not_allowlisted"):
        durable_dispatch_canvas(canvas)


def test_canvas_dispatch_redacts_broker_exception_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "redis://user:hunter2@broker.internal/0"
    canvas = _discovery_chord()

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(canvas, "apply_async", _fail)
    with pytest.raises(DispatchPublicationError, match="publication_failed") as raised:
        durable_dispatch_canvas(canvas)

    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
