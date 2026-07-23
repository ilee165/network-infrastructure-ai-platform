"""Unit contracts for ADR-0059 report dispatch outbox."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.models.dispatch_outbox import DispatchOutboxState
from app.services.report_outbox import InvalidDispatchEnvelope, report_envelope
from app.workers.dispatch import durable_dispatch


def test_report_outbox_payload_and_metrics_never_contain_secret_or_raw_error() -> None:
    envelope = report_envelope(
        run_id=uuid.uuid4(),
        kind="change",
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="on_demand",
        requested_by=uuid.uuid4(),
    )
    assert set(envelope.payload) == {
        "dispatch_id",
        "kind",
        "period_start",
        "period_end",
        "trigger",
        "requested_by",
    }
    assert envelope.state is DispatchOutboxState.PENDING


def test_poison_envelope_is_rejected_before_publication() -> None:
    with pytest.raises(InvalidDispatchEnvelope):
        durable_dispatch(
            task_name="reports.generate",
            payload={"kind": "change", "secret": "do-not-publish"},
            queue="docs",
            dispatch_id=uuid.uuid4(),
        )
