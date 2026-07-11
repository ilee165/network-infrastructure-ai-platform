"""Failover-aware Redis client construction (ADR-0044 §1).

The Helm chart renders ``NETOPS_REDIS_URL`` as a
``sentinel://h0:26379;h1:26379;h2:26379/<db>`` URL when the redisSentinel HA
tier is enabled, so clients resolve the CURRENT primary at connect time and
re-point on failover with no config change. Kombu (the Celery broker) parses
that scheme natively, but ``redis.asyncio.from_url`` accepts only
``redis``/``rediss``/``unix`` and raises ``ValueError`` at parse time — which
crashed the API pod at boot the moment the HA tier was enabled.

:func:`create_redis_client` is therefore the single construction seam for every
``redis.asyncio`` client in the app (rate limiter, agent-stream fan-out, ticket
store, readiness probe): a ``sentinel://`` URL builds a
:class:`redis.asyncio.sentinel.Sentinel` and returns ``master_for(...)``; any
other URL goes through ``from_url`` unchanged. The password is never part of
the URL (it is the separate ``NETOPS_REDIS_PASSWORD`` env, ADR-0044 §1) and is
injected here from ``Settings``.
"""

from __future__ import annotations

import redis.asyncio as aioredis
from redis.asyncio.sentinel import Sentinel

from app.core.config import Settings

#: URL scheme prefix the Helm ``netops.redisUrl`` helper emits for the HA tier.
SENTINEL_SCHEME_PREFIX = "sentinel://"


def parse_sentinel_url(url: str) -> tuple[list[tuple[str, int]], int]:
    """Parse ``sentinel://h0:26379;h1:26379/<db>`` into ``([(host, port), ...], db)``.

    Raises:
        ValueError: on a malformed URL (no hosts, a non-numeric port or db) —
            fail loudly at boot rather than dialing a half-parsed coordinate.
    """
    rest = url[len(SENTINEL_SCHEME_PREFIX) :]
    hosts_part, _, db_part = rest.partition("/")
    hosts: list[tuple[str, int]] = []
    for entry in filter(None, hosts_part.split(";")):
        host, _, port = entry.partition(":")
        if not host:
            msg = f"malformed sentinel URL (empty host): {url!r}"
            raise ValueError(msg)
        try:
            hosts.append((host, int(port) if port else 26379))
        except ValueError as exc:
            msg = f"malformed sentinel URL (bad port {port!r}): {url!r}"
            raise ValueError(msg) from exc
    if not hosts:
        msg = f"malformed sentinel URL (no hosts): {url!r}"
        raise ValueError(msg)
    try:
        db = int(db_part) if db_part else 0
    except ValueError as exc:
        msg = f"malformed sentinel URL (bad db {db_part!r}): {url!r}"
        raise ValueError(msg) from exc
    return hosts, db


def create_redis_client(settings: Settings) -> aioredis.Redis:
    """Build the ``redis.asyncio`` client for ``settings.redis_url``.

    ``sentinel://`` URLs return a failover-aware ``master_for`` proxy (primary
    re-resolved on reconnect); other schemes go through ``from_url``. Both are
    lazy — no connection is opened until the first command.
    """
    url = settings.redis_url
    password = settings.redis_password or None
    if url.startswith(SENTINEL_SCHEME_PREFIX):
        hosts, db = parse_sentinel_url(url)
        sentinel_kwargs = {"password": password} if password else {}
        sentinel = Sentinel(hosts, sentinel_kwargs=sentinel_kwargs)  # type: ignore[no-untyped-call]
        master: aioredis.Redis = sentinel.master_for(
            settings.redis_sentinel_master, db=db, password=password
        )
        return master
    client: aioredis.Redis = aioredis.from_url(url, password=password)  # type: ignore[no-untyped-call]
    return client
