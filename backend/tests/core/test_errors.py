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
    RateLimitedError,
    SchemaNotReadyError,
    _bounded_traceback,
    _problem_response,
    translate_db_schema_error,
    translate_llm_error,
    unhandled_error_handler,
)
from app.main import create_app


def _bare_request(path: str = "/x") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "headers": [],
            "query_string": b"",
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )


@pytest.mark.parametrize(
    ("retry_after", "expected_header"),
    [(30, "30"), (1, "1"), (0, "1")],
)
def test_rate_limited_always_carries_retry_after(retry_after: int, expected_header: str) -> None:
    """CR4: a 429 ALWAYS carries Retry-After, incl. a boundary 0 (coarse minimum 1)."""
    response = _problem_response(
        RateLimitedError("slow down", retry_after=retry_after), _bare_request()
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == expected_header


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


class TestSchemaNotReadyTranslation:
    """Missing-table DB errors map to a fast operator-facing 503."""

    def test_schema_not_ready_problem_shape(self) -> None:
        problem = SchemaNotReadyError("run alembic").to_problem(instance="/api/v1/auth/login")
        assert problem["status"] == 503
        assert problem["type"] == "urn:netops:error:schema-not-ready"
        assert problem["detail"] == "run alembic"
        assert issubclass(SchemaNotReadyError, NetOpsError)

    def test_translates_undefined_table_by_name(self) -> None:
        exc = type("UndefinedTableError", (Exception,), {"__module__": "asyncpg.exceptions"})(
            'relation "users" does not exist'
        )
        mapped = translate_db_schema_error(exc)
        assert isinstance(mapped, SchemaNotReadyError)
        assert "alembic upgrade head" in mapped.detail

    def test_translates_sqlalchemy_programming_error_wrapper(self) -> None:
        orig = type("UndefinedTableError", (Exception,), {"__module__": "asyncpg.exceptions"})(
            'relation "users" does not exist'
        )
        # Mimic SQLAlchemy's wrapper: outer ProgrammingError with .orig set.
        outer = type("ProgrammingError", (Exception,), {"__module__": "sqlalchemy.exc"})(
            "(sqlalchemy) <class 'asyncpg.exceptions.UndefinedTableError'>: "
            'relation "users" does not exist'
        )
        outer.orig = orig  # type: ignore[attr-defined]
        outer.__cause__ = orig
        mapped = translate_db_schema_error(outer)
        assert isinstance(mapped, SchemaNotReadyError)

    def test_passes_through_unrelated_errors(self) -> None:
        assert translate_db_schema_error(RuntimeError("boom")) is None
        assert translate_db_schema_error(NotFoundError("x")) is None


async def test_unhandled_handler_maps_missing_schema_to_503() -> None:
    """Missing ``users`` must be a fast 503 with the alembic hint, not opaque 500."""
    request = _bare_request("/api/v1/auth/login")
    exc = type("UndefinedTableError", (Exception,), {"__module__": "asyncpg.exceptions"})(
        'relation "users" does not exist'
    )
    response = await unhandled_error_handler(request, exc)
    assert response.status_code == 503
    body = response.body
    assert b"schema-not-ready" in body
    assert b"alembic upgrade head" in body
    assert b"users" not in body  # no raw relation name leak required; detail is fixed


def test_bounded_traceback_truncates_and_omits_locals() -> None:
    """Bounded formatter must stay small and never expand frame locals."""
    try:
        raise RuntimeError("tiny")
    except RuntimeError as exc:
        tb = _bounded_traceback(exc)
    assert "RuntimeError" in tb
    assert "tiny" in tb
    # Cap sanity: even a deep stack is clipped (this one is short).
    assert len(tb) < 4000
