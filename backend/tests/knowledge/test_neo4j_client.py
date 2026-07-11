"""Neo4jClient unit tests against a fake driver (no live Neo4j in the unit gate).

Covers config wiring, lazy connect, session lifecycle, read/write helpers,
bounded retry with backoff on transient errors, health check, and the
module-level singleton accessors (mirroring ``app.db``).
"""

from __future__ import annotations

from typing import Any

import pytest
from neo4j.exceptions import ServiceUnavailable, SessionExpired

import app.knowledge.neo4j_client as neo4j_client
from app.core.config import Settings
from app.knowledge import Neo4jClient

# ---------------------------------------------------------------------------
# Fake driver stack
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, record: dict[str, Any] | None) -> None:
        self._record = record

    async def single(self) -> dict[str, Any] | None:
        return self._record


class FakeTransaction:
    """Records every Cypher query; always answers ``{"ok": 1}``."""

    def __init__(self) -> None:
        self.queries: list[str] = []

    async def run(self, query: str, **params: Any) -> FakeResult:
        self.queries.append(query)
        return FakeResult({"ok": 1})


class FakeSession:
    def __init__(self, driver: FakeDriver) -> None:
        self._driver = driver
        self.closed = False
        driver.sessions.append(self)

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        await self.close()
        return False

    async def close(self) -> None:
        self.closed = True

    async def run(self, query: str, **params: Any) -> FakeResult:
        """Unmanaged auto-commit query (no driver-internal retry, unlike
        ``execute_read``/``execute_write`` on the real driver)."""
        self._driver.calls.append("run")
        if self._driver.outcomes:
            outcome = self._driver.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
        tx = FakeTransaction()
        self._driver.transactions.append(tx)
        return await tx.run(query, **params)

    async def _execute(self, mode: str, work: Any, *args: Any, **kwargs: Any) -> Any:
        self._driver.calls.append(mode)
        if self._driver.outcomes:
            outcome = self._driver.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        tx = FakeTransaction()
        self._driver.transactions.append(tx)
        return await work(tx, *args, **kwargs)

    async def execute_read(self, work: Any, *args: Any, **kwargs: Any) -> Any:
        return await self._execute("read", work, *args, **kwargs)

    async def execute_write(self, work: Any, *args: Any, **kwargs: Any) -> Any:
        return await self._execute("write", work, *args, **kwargs)


class FakeDriver:
    """Scripted driver: each execute_* call pops the next outcome.

    An exception outcome is raised; any other outcome is returned verbatim.
    An empty script runs the work function against a :class:`FakeTransaction`.
    """

    def __init__(self, outcomes: list[Any] | None = None) -> None:
        self.outcomes: list[Any] = list(outcomes or [])
        self.sessions: list[FakeSession] = []
        self.calls: list[str] = []
        self.transactions: list[FakeTransaction] = []
        self.session_kwargs: list[dict[str, Any]] = []
        self.closed = False

    def session(self, **kwargs: Any) -> FakeSession:
        self.session_kwargs.append(kwargs)
        return FakeSession(self)

    async def close(self) -> None:
        self.closed = True


def make_client(
    settings: Settings, driver: FakeDriver, **kwargs: Any
) -> tuple[Neo4jClient, list[Settings]]:
    """Client with an injected fake driver and zero backoff; returns factory call log."""
    factory_calls: list[Settings] = []

    def factory(factory_settings: Settings) -> Any:
        factory_calls.append(factory_settings)
        return driver

    kwargs.setdefault("backoff_base_seconds", 0.0)
    return Neo4jClient(settings, driver_factory=factory, **kwargs), factory_calls


# ---------------------------------------------------------------------------
# Construction / config wiring
# ---------------------------------------------------------------------------


def test_rejects_non_positive_max_attempts(settings: Settings) -> None:
    with pytest.raises(ValueError):
        Neo4jClient(settings, max_attempts=0)


async def test_lazy_connect_factory_called_once_on_first_use(settings: Settings) -> None:
    client, factory_calls = make_client(settings, FakeDriver())
    assert factory_calls == []  # constructing the client opens nothing

    async def _noop(tx: Any) -> int:
        return 1

    await client.execute_read(_noop)
    await client.execute_read(_noop)
    assert factory_calls == [settings]  # one driver, reused across calls


async def test_default_factory_wires_settings(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}
    driver = FakeDriver()

    class StubGraphDatabase:
        @staticmethod
        def driver(uri: str, auth: tuple[str, str] | None = None) -> FakeDriver:
            captured["uri"] = uri
            captured["auth"] = auth
            return driver

    monkeypatch.setattr(neo4j_client, "AsyncGraphDatabase", StubGraphDatabase)
    client = Neo4jClient(settings)
    assert await client.health_check() is True
    assert captured["uri"] == settings.neo4j_uri
    assert captured["auth"] == (settings.neo4j_user, settings.neo4j_password)


def test_repr_never_exposes_password(settings: Settings) -> None:
    client, _ = make_client(settings, FakeDriver())
    assert settings.neo4j_password not in repr(client)


# ---------------------------------------------------------------------------
# Session lifecycle / close
# ---------------------------------------------------------------------------


async def test_session_helper_closes_session(settings: Settings) -> None:
    driver = FakeDriver()
    client, _ = make_client(settings, driver)
    async with client.session() as session:
        assert isinstance(session, FakeSession)
        assert not session.closed
    assert session.closed


async def test_close_is_idempotent_and_skips_unopened_driver(settings: Settings) -> None:
    driver = FakeDriver()
    client, factory_calls = make_client(settings, driver)

    await client.close()  # never connected: nothing created, nothing closed
    assert factory_calls == []
    assert not driver.closed

    async with client.session():
        pass
    await client.close()
    assert driver.closed
    await client.close()  # second close is a no-op


async def test_close_resets_driver_so_next_use_reconnects(settings: Settings) -> None:
    driver = FakeDriver()
    client, factory_calls = make_client(settings, driver)
    async with client.session():
        pass
    await client.close()
    async with client.session():
        pass
    assert len(factory_calls) == 2


# ---------------------------------------------------------------------------
# execute_read / execute_write
# ---------------------------------------------------------------------------


async def test_execute_read_runs_work_with_args(settings: Settings) -> None:
    driver = FakeDriver()
    client, _ = make_client(settings, driver)

    async def work(tx: Any, left: int, *, right: int) -> int:
        return left + right

    assert await client.execute_read(work, 1, right=2) == 3
    assert driver.calls == ["read"]
    assert all(session.closed for session in driver.sessions)


async def test_execute_write_uses_write_mode(settings: Settings) -> None:
    driver = FakeDriver()
    client, _ = make_client(settings, driver)

    async def work(tx: Any) -> str:
        return "written"

    assert await client.execute_write(work) == "written"
    assert driver.calls == ["write"]


# ---------------------------------------------------------------------------
# Retry behavior
# ---------------------------------------------------------------------------


async def test_retries_transient_errors_then_succeeds(settings: Settings) -> None:
    driver = FakeDriver(outcomes=[ServiceUnavailable("down"), SessionExpired("expired")])
    client, _ = make_client(settings, driver, max_attempts=3)

    async def work(tx: Any) -> str:
        return "ok"

    assert await client.execute_read(work) == "ok"
    assert driver.calls == ["read", "read", "read"]
    # every attempt gets a fresh, properly closed session
    assert len(driver.sessions) == 3
    assert all(session.closed for session in driver.sessions)


async def test_retry_is_bounded_and_reraises_last_error(settings: Settings) -> None:
    driver = FakeDriver(outcomes=[ServiceUnavailable("down")] * 5)
    client, _ = make_client(settings, driver, max_attempts=3)

    async def work(tx: Any) -> str:
        return "never"

    with pytest.raises(ServiceUnavailable):
        await client.execute_read(work)
    assert driver.calls == ["read", "read", "read"]


async def test_non_transient_errors_are_not_retried(settings: Settings) -> None:
    driver = FakeDriver(outcomes=[ValueError("bad query")])
    client, _ = make_client(settings, driver, max_attempts=3)

    async def work(tx: Any) -> str:
        return "never"

    with pytest.raises(ValueError):
        await client.execute_write(work)
    assert driver.calls == ["write"]


def test_backoff_delay_grows_exponentially(settings: Settings) -> None:
    client = Neo4jClient(settings, backoff_base_seconds=0.25)
    assert client._backoff_delay(1) == 0.25
    assert client._backoff_delay(2) == 0.5
    assert client._backoff_delay(3) == 1.0


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


async def test_health_check_returns_true_and_runs_return_1(settings: Settings) -> None:
    driver = FakeDriver()
    client, _ = make_client(settings, driver)
    assert await client.health_check() is True
    assert driver.transactions[0].queries == ["RETURN 1 AS ok"]


async def test_health_check_returns_false_when_unreachable_without_retry(
    settings: Settings,
) -> None:
    driver = FakeDriver(outcomes=[ServiceUnavailable("down")] * 3)
    client, _ = make_client(settings, driver, max_attempts=3)
    assert await client.health_check() is False
    # Exactly one unmanaged probe: never the managed execute_read path, whose
    # DRIVER-INTERNAL ServiceUnavailable retry (max_transaction_retry_time,
    # jittered 30s+ sleeps) would blow any probe/pytest-timeout budget.
    assert driver.calls == ["run"]
    assert len(driver.outcomes) == 2  # two scripted failures left -> one attempt


# ---------------------------------------------------------------------------
# Module-level singleton (mirrors app.db engine accessors)
# ---------------------------------------------------------------------------


async def test_get_client_returns_cached_singleton(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(neo4j_client, "_client", None)
    first = neo4j_client.get_client()
    second = neo4j_client.get_client()
    assert first is second


async def test_dispose_client_closes_driver_and_resets(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = FakeDriver()
    client, _ = make_client(settings, driver)
    async with client.session():
        pass
    monkeypatch.setattr(neo4j_client, "_client", client)
    await neo4j_client.dispose_client()
    assert driver.closed
    assert neo4j_client._client is None


async def test_dispose_client_is_safe_when_unused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(neo4j_client, "_client", None)
    await neo4j_client.dispose_client()
    assert neo4j_client._client is None
