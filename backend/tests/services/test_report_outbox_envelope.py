"""Strict report outbox dispatch-envelope validation regressions."""

from __future__ import annotations

import uuid
from typing import Any, cast

import pytest

from app.models.dispatch_outbox import DispatchOutbox, DispatchOutboxState
from app.services.report_outbox import InvalidDispatchEnvelope, validate_dispatch_row


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            [
                ["dispatch_id", "{dispatch_id}"],
                ["run_id", "{run_id}"],
            ],
            id="array-of-pairs",
        ),
        pytest.param(["dispatch_id", "run_id"], id="list"),
        pytest.param("raw-secret-hunter2", id="scalar"),
        pytest.param(None, id="null"),
        pytest.param(
            {"dispatch_id": ["not", "a", "uuid"], "run_id": "{run_id}"},
            id="non-string-identifier",
        ),
    ],
)
def test_dispatch_row_rejects_every_non_object_or_bad_identifier_payload(
    payload: object,
) -> None:
    dispatch_id = uuid.uuid4()
    run_id = uuid.uuid4()

    def substitute(value: object) -> object:
        if isinstance(value, str):
            return value.format(dispatch_id=dispatch_id, run_id=run_id)
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        return value

    row = DispatchOutbox(
        id=dispatch_id,
        aggregate_type="report_run",
        aggregate_id=run_id,
        task_name="reports.generate",
        queue="docs",
        payload_json=cast(Any, substitute(payload)),
        state=DispatchOutboxState.CLAIMED.value,
        claim_owner="relay-a",
    )

    with pytest.raises(InvalidDispatchEnvelope, match="invalid_payload_shape"):
        validate_dispatch_row(row)
