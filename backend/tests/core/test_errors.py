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
    LLMUpstreamError,
    NetOpsError,
    NotFoundError,
    PluginError,
    translate_llm_error,
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


class TestLLMErrorTranslation:
    """translate_llm_error turns provider/transport failures into a clean 502."""

    def test_llm_upstream_error_is_502(self) -> None:
        problem = LLMUpstreamError("provider unavailable").to_problem()
        assert problem["status"] == 502
        assert problem["type"] == "urn:netops:error:llm-upstream"
        assert issubclass(LLMUpstreamError, NetOpsError)

    def test_translates_transport_error(self) -> None:
        # httpx backs the Ollama transport; a refused connection must surface as
        # a typed 502, not an opaque 500.
        translated = translate_llm_error(httpx.ConnectError("connection refused"))
        assert isinstance(translated, LLMUpstreamError)
        assert translated.status_code == 502

    def test_translates_provider_sdk_error_by_module(self) -> None:
        # Simulate an anthropic.* / openai.* SDK exception without importing the
        # SDK: recognition is by the exception's top-level module.
        for module in ("anthropic._exceptions", "openai", "ollama._types"):
            exc = type("BadRequestError", (Exception,), {"__module__": module})(
                "credit balance is too low"
            )
            assert isinstance(translate_llm_error(exc), LLMUpstreamError), module

    def test_translation_detail_does_not_leak_provider_message(self) -> None:
        exc = type("BadRequestError", (Exception,), {"__module__": "anthropic"})(
            "secret org id org-hunter2 over quota"
        )
        translated = translate_llm_error(exc)
        assert translated is not None
        assert "hunter2" not in translated.detail

    def test_passes_through_netops_error(self) -> None:
        # Already-typed platform errors (incl. RBAC denials) keep their own status.
        assert translate_llm_error(NotFoundError("x")) is None

    def test_passes_through_generic_bug(self) -> None:
        # A genuine code bug must NOT be masked as a provider error — it stays a 500.
        assert (
            translate_llm_error(AttributeError("'NoneType' object has no attribute 'domain'"))
            is None
        )


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
