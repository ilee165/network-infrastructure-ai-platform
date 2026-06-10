"""NetOpsError hierarchy + RFC 7807 handler tests."""

from __future__ import annotations

import httpx
import pytest
from fastapi import Request

from app.core.config import Settings
from app.core.errors import (
    PROBLEM_CONTENT_TYPE,
    AuthError,
    ConflictError,
    NetOpsError,
    NotFoundError,
    PluginError,
    unhandled_error_handler,
)
from app.main import create_app


@pytest.mark.parametrize(
    ("error_cls", "status", "slug"),
    [
        (NotFoundError, 404, "not-found"),
        (ConflictError, 409, "conflict"),
        (AuthError, 401, "unauthorized"),
        (PluginError, 502, "plugin-failure"),
        (NetOpsError, 500, "internal-error"),
    ],
)
def test_error_hierarchy_problem_shape(
    error_cls: type[NetOpsError], status: int, slug: str
) -> None:
    problem = error_cls("something happened").to_problem(instance="/api/v1/things/1")
    assert problem == {
        "type": f"urn:netops:error:{slug}",
        "title": error_cls.title,
        "status": status,
        "detail": "something happened",
        "instance": "/api/v1/things/1",
    }
    assert issubclass(error_cls, NetOpsError)


async def test_netops_error_renders_problem_json(settings: Settings) -> None:
    app = create_app(settings)

    @app.get("/boom-not-found")
    async def boom() -> None:
        raise NotFoundError("device 42 does not exist")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/boom-not-found")

    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_CONTENT_TYPE
    body = response.json()
    assert body["type"] == "urn:netops:error:not-found"
    assert body["detail"] == "device 42 does not exist"
    assert body["instance"] == "/boom-not-found"


async def test_auth_error_sets_www_authenticate(settings: Settings) -> None:
    app = create_app(settings)

    @app.get("/boom-auth")
    async def boom() -> None:
        raise AuthError()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/boom-auth")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


async def test_unhandled_handler_returns_opaque_500() -> None:
    """Internals (the exception message) must never leak to clients."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/explode",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
    }
    request = Request(scope)
    response = await unhandled_error_handler(
        request, RuntimeError("secret internal detail: db password is hunter2")
    )
    assert response.status_code == 500
    assert b"hunter2" not in response.body
    assert b"An internal error occurred." in response.body
