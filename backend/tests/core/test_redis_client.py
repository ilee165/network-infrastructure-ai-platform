"""Sentinel-aware Redis client construction (app.core.redis).

Pins the C5 fix (2026-07-10 repo review): enabling the redisSentinel HA tier
renders NETOPS_REDIS_URL as ``sentinel://h0:26379;h1:26379;h2:26379/<db>``,
which ``redis.asyncio.from_url`` rejects with ValueError at parse time — the
API pod crashed at boot. ``create_redis_client`` must accept both schemes
without opening a connection (both clients are lazy), and the Celery app must
carry the Sentinel master name in its transport options.
"""

from __future__ import annotations

import pytest
import redis.asyncio as aioredis

from app.core.config import Settings
from app.core.redis import create_redis_client, parse_sentinel_url

SENTINEL_URL = "sentinel://h0:26379;h1:26379;h2:26379/0"


def _settings(**overrides: object) -> Settings:
    return Settings(**overrides)  # type: ignore[arg-type]


class TestParseSentinelUrl:
    def test_three_hosts_and_db(self) -> None:
        hosts, db = parse_sentinel_url("sentinel://h0:26379;h1:26380;h2/2")
        assert hosts == [("h0", 26379), ("h1", 26380), ("h2", 26379)]
        assert db == 2

    def test_db_defaults_to_zero(self) -> None:
        _, db = parse_sentinel_url("sentinel://h0:26379")
        assert db == 0

    @pytest.mark.parametrize(
        "url",
        [
            "sentinel:///0",  # no hosts
            "sentinel://h0:notaport/0",  # bad port
            "sentinel://h0:26379/notadb",  # bad db
            "sentinel://:26379/0",  # empty host
        ],
    )
    def test_malformed_raises_value_error(self, url: str) -> None:
        with pytest.raises(ValueError, match="malformed sentinel URL"):
            parse_sentinel_url(url)


class TestCreateRedisClient:
    def test_plain_url_builds_client_without_connecting(self) -> None:
        client = create_redis_client(_settings(redis_url="redis://redis:6379/0"))
        assert isinstance(client, aioredis.Redis)

    def test_sentinel_url_builds_master_proxy_without_connecting(self) -> None:
        """The exact URL shape the Helm netops.redisUrl helper renders must not
        raise at construction time (the C5 boot crash)."""
        client = create_redis_client(
            _settings(redis_url=SENTINEL_URL, redis_sentinel_master="netops-redis")
        )
        assert isinstance(client, aioredis.Redis)
        assert client.connection_pool.service_name == "netops-redis"

    def test_sentinel_password_reaches_master_pool(self) -> None:
        client = create_redis_client(_settings(redis_url=SENTINEL_URL, redis_password="s3cret"))
        assert client.connection_pool.connection_kwargs["password"] == "s3cret"


class TestCeleryTransportOptions:
    def test_sentinel_url_sets_master_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.workers import celery_app as celery_module

        monkeypatch.setattr(
            celery_module,
            "get_settings",
            lambda: _settings(redis_url=SENTINEL_URL, redis_password="s3cret"),
        )
        celery = celery_module.create_celery_app()
        assert celery.conf.broker_transport_options["master_name"] == "netops-redis"
        assert celery.conf.broker_transport_options["sentinel_kwargs"] == {"password": "s3cret"}
        assert celery.conf.result_backend_transport_options["master_name"] == "netops-redis"

    def test_plain_url_leaves_transport_options_untouched(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.workers import celery_app as celery_module

        monkeypatch.setattr(celery_module, "get_settings", lambda: _settings())
        celery = celery_module.create_celery_app()
        assert "master_name" not in (celery.conf.broker_transport_options or {})
