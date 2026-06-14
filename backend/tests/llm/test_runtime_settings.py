"""DB-backed runtime LLM profile resolution (B5).

The LLM registry consults the single ``system_settings`` row at runtime to
pick the effective profile for a role, falling back to env ``Settings`` when
the row is absent or a field is null. Provider API keys and the Ollama
endpoint stay env-only and are never read from the DB here.

No network, no Postgres: an in-memory aiosqlite session holds the row.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings
from app.llm.providers import LLMProfileError
from app.llm.runtime_settings import effective_profile_for_role
from app.models import Base, SystemSetting


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "_env_file": None,
        "env": "dev",
        "secret_key": "unit-test-secret-key",
        "llm_profile": "local",
    }
    base.update(overrides)
    return Settings(**base)


# --------------------------------------------------------------------------- #
# Absent row -> behave exactly as env today                                   #
# --------------------------------------------------------------------------- #
async def test_absent_row_falls_back_to_env_base_profile(session: AsyncSession) -> None:
    settings = _settings(llm_profile="local")
    assert await effective_profile_for_role(session, "reasoning", settings) == "local"
    assert await effective_profile_for_role(session, "fast", settings) == "local"


async def test_absent_row_falls_back_to_env_role_override(session: AsyncSession) -> None:
    settings = _settings(llm_profile="local", llm_role_reasoning="openai")
    assert await effective_profile_for_role(session, "reasoning", settings) == "openai"
    # fast has no env override -> base profile
    assert await effective_profile_for_role(session, "fast", settings) == "local"


# --------------------------------------------------------------------------- #
# DB row overrides env                                                         #
# --------------------------------------------------------------------------- #
async def test_db_base_profile_overrides_env(session: AsyncSession) -> None:
    session.add(SystemSetting(llm_profile="anthropic"))
    await session.flush()
    settings = _settings(llm_profile="local")
    # No role override in the row -> both roles resolve to the DB base profile.
    assert await effective_profile_for_role(session, "reasoning", settings) == "anthropic"
    assert await effective_profile_for_role(session, "fast", settings) == "anthropic"


async def test_db_role_override_beats_env_role_override(session: AsyncSession) -> None:
    session.add(
        SystemSetting(
            llm_profile="local",
            llm_role_reasoning="anthropic",
            llm_role_fast=None,
        )
    )
    await session.flush()
    settings = _settings(llm_profile="local", llm_role_reasoning="openai", llm_role_fast="azure")
    # DB reasoning override wins over the env reasoning override.
    assert await effective_profile_for_role(session, "reasoning", settings) == "anthropic"
    # DB fast override is null -> per-field env fallback reaches the env fast
    # role override (the locked "field is null -> env" contract).
    assert await effective_profile_for_role(session, "fast", settings) == "azure"


async def test_db_base_overrides_env_base_when_no_role_override_anywhere(
    session: AsyncSession,
) -> None:
    """A null DB role with no env role override falls to the DB base over env base."""
    session.add(SystemSetting(llm_profile="openai", llm_role_reasoning=None, llm_role_fast=None))
    await session.flush()
    settings = _settings(llm_profile="local")
    assert await effective_profile_for_role(session, "reasoning", settings) == "openai"
    assert await effective_profile_for_role(session, "fast", settings) == "openai"


# --------------------------------------------------------------------------- #
# Unknown role is a typed error                                               #
# --------------------------------------------------------------------------- #
async def test_unknown_role_raises_llm_profile_error(session: AsyncSession) -> None:
    settings = _settings()
    with pytest.raises(LLMProfileError):
        await effective_profile_for_role(session, "nonsense", settings)
