"""Wave-2 H11: shared fail-closed KEK audit helper logs and never raises."""
from __future__ import annotations

import pytest

from app.services.audit.fail_closed import audit_fail_closed


@pytest.mark.asyncio
async def test_audit_fail_closed_swallows_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    async def boom() -> None:
        raise RuntimeError("audit db down")

    # Must not raise — original KeyProviderUnavailable is caller's responsibility.
    await audit_fail_closed(boom, reason_class="timeout")
