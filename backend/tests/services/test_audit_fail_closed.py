"""Wave-2 H11: shared fail-closed KEK audit helper logs and never raises."""

from __future__ import annotations

import pytest
import structlog.testing

from app.services.audit.fail_closed import audit_fail_closed


@pytest.mark.asyncio
async def test_audit_fail_closed_swallows_and_logs() -> None:
    async def boom() -> None:
        raise RuntimeError("audit db down")

    with structlog.testing.capture_logs() as captured:
        # Must not raise — original KeyProviderUnavailable is caller's responsibility.
        await audit_fail_closed(boom, reason_class="timeout")

    events = [row.get("event") for row in captured]
    assert "kek.provider.unavailable.audit_failed" in events
