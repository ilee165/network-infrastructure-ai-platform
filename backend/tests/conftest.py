"""Global test fixtures (D16).

Unit tests must pass without Postgres, Neo4j, Redis, or any network access:
settings are constructed explicitly (no ``.env`` file read), dependency probes
are monkeypatched in the tests that exercise them, and the HTTP client drives
the ASGI app in-process.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi import FastAPI

import app.main as app_main
from app.core.config import Settings, get_settings
from app.main import create_app


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    """Isolate tests from each other's (and the host's) cached settings."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _cap_root_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cap the root logger at WARNING whenever the app configures logging.

    ``create_app()`` calls ``configure_logging`` with the ``env="dev"`` test
    settings, which sets the root logger to DEBUG; rendering every DEBUG
    record through the structlog stdout handler dominates the runtime of
    DB/API-heavy tests. The ``app.main`` reference is wrapped (rather than
    setting the level once here) because every ``create_app()`` call re-runs
    ``configure_logging`` and would undo a one-time cap. Tests that assert on
    DEBUG/INFO records re-lower the level for their own scope via
    ``caplog.set_level``/``caplog.at_level``.
    """
    orig = app_main.configure_logging

    def _configure_then_cap(settings: Settings) -> None:
        orig(settings)
        logging.getLogger().setLevel(logging.WARNING)

    monkeypatch.setattr(app_main, "configure_logging", _configure_then_cap)


@pytest.fixture()
def settings() -> Settings:
    """Deterministic test settings; ``_env_file=None`` disables .env reading."""
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="unit-test-secret-key",
        database_url="postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops_test",
        redis_url="redis://127.0.0.1:6379/0",
        neo4j_uri="bolt://127.0.0.1:7687",
        neo4j_user="neo4j",
        neo4j_password="unit-test-password",
        llm_profile="local",
        ollama_base_url="http://127.0.0.1:11434",
        cors_origins=["http://testserver"],
        access_token_expire_minutes=5,
    )


@pytest.fixture()
def app(settings: Settings) -> FastAPI:
    """The FastAPI app built with injected test settings."""
    return create_app(settings)


@pytest.fixture()
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """In-process async HTTP client against the app (no sockets opened)."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client
