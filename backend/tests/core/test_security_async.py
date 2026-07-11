"""Wave-2: bcrypt helpers run off the event loop (perf #6 / H2)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.core.security import hash_password, hash_password_async, verify_password_async


@pytest.mark.asyncio
async def test_hash_password_async_uses_to_thread() -> None:
    with patch("app.core.security.asyncio.to_thread", new_callable=AsyncMock) as mock_tt:
        mock_tt.return_value = "$2b$12$fakehash"
        result = await hash_password_async("secret")
        assert result == "$2b$12$fakehash"
        mock_tt.assert_awaited()


@pytest.mark.asyncio
async def test_verify_password_async_uses_to_thread() -> None:
    h = hash_password("secret")
    with patch("app.core.security.asyncio.to_thread", new_callable=AsyncMock) as mock_tt:
        mock_tt.return_value = True
        assert await verify_password_async("secret", h) is True
        mock_tt.assert_awaited()
