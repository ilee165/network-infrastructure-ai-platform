"""Wave 5 T6: process-wide supervisor + chat-model cache."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.v1 import agents as agents_api
from app.core.config import Settings
from app.core.security import Role
from app.llm import providers as llm_providers


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    agents_api.clear_supervisor_cache()
    llm_providers.clear_chat_model_cache()
    yield
    agents_api.clear_supervisor_cache()
    llm_providers.clear_chat_model_cache()


@pytest.mark.asyncio
async def test_build_supervisor_caches_second_call() -> None:
    settings = Settings(llm_profile="local", llm_local_model="llama-test")
    fake_graph = object()
    build_calls: list[object] = []

    def _fake_build(llm: object, **kwargs: object) -> object:
        build_calls.append(llm)
        return fake_graph

    with (
        patch(
            "app.api.v1.agents.effective_profile_for_role",
            new=AsyncMock(return_value="local"),
        ),
        patch("app.api.v1.agents.get_chat_model", return_value=MagicMock(name="llm")),
        patch("app.api.v1.agents.build_default_supervisor", side_effect=_fake_build),
        patch("app.api.v1.agents.db.get_sessionmaker") as sm,
    ):
        sm.return_value = MagicMock(return_value=AsyncMock())
        # session context manager
        session_cm = AsyncMock()
        session_cm.__aenter__ = AsyncMock(return_value=MagicMock())
        session_cm.__aexit__ = AsyncMock(return_value=None)
        sm.return_value.return_value = session_cm

        g1 = await agents_api.build_supervisor_for_role(Role.VIEWER, settings)
        g2 = await agents_api.build_supervisor_for_role(Role.VIEWER, settings)

    assert g1 is fake_graph
    assert g2 is fake_graph
    assert len(build_calls) == 1


def test_invalidate_clears_supervisor_and_model_caches() -> None:
    agents_api._SUPERVISOR_GRAPH_CACHE[("local", "m")] = object()  # type: ignore[assignment]
    llm_providers._CHAT_MODEL_CACHE[("local", "m", 0.0)] = MagicMock()  # type: ignore[assignment]
    agents_api.invalidate_llm_runtime_caches()
    assert agents_api._SUPERVISOR_GRAPH_CACHE == {}
    assert llm_providers._CHAT_MODEL_CACHE == {}
