"""NetOpsError hierarchy and FastAPI exception handlers.

Every error surfaces to clients as an RFC 7807 problem-details object
(``application/problem+json``)::

    {
      "type": "urn:netops:error:not-found",
      "title": "Not Found",
      "status": 404,
      "detail": "device 42 does not exist",
      "instance": "/api/v1/devices/42"
    }

Naming convention (REPO-STRUCTURE §4.1): all exceptions are ``<X>Error`` rooted
at :class:`NetOpsError`. M1+: plugin sub-hierarchy (``PluginConnectionError``,
``PluginParseError``) and ``ApprovalRequiredError`` extend this module.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger

PROBLEM_CONTENT_TYPE = "application/problem+json"

_logger = get_logger(__name__)


class NetOpsError(Exception):
    """Base class for all platform errors.

    Subclasses override ``status_code``, ``title`` and ``slug``; ``detail`` is
    supplied per instance and must never contain secrets or stack traces.
    """

    status_code: int = 500
    title: str = "Internal Server Error"
    slug: str = "internal-error"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail if detail is not None else self.title
        super().__init__(self.detail)

    def to_problem(self, instance: str | None = None) -> dict[str, Any]:
        """Render this error as an RFC 7807 problem-details mapping."""
        problem: dict[str, Any] = {
            "type": f"urn:netops:error:{self.slug}",
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
        }
        if instance is not None:
            problem["instance"] = instance
        return problem


class NotFoundError(NetOpsError):
    """A requested resource does not exist."""

    status_code = 404
    title = "Not Found"
    slug = "not-found"


class ConflictError(NetOpsError):
    """The request conflicts with current resource state (e.g. duplicate)."""

    status_code = 409
    title = "Conflict"
    slug = "conflict"


class AuthError(NetOpsError):
    """Authentication failed: missing, invalid, or expired credentials."""

    status_code = 401
    title = "Unauthorized"
    slug = "unauthorized"


class ForbiddenError(NetOpsError):
    """Authenticated but not authorized: the caller's role rank is insufficient."""

    status_code = 403
    title = "Forbidden"
    slug = "forbidden"


class PluginError(NetOpsError):
    """A vendor plugin operation failed (connection, command, or parse)."""

    status_code = 502
    title = "Vendor Plugin Failure"
    slug = "plugin-failure"


def _problem_response(error: NetOpsError, request: Request) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if error.status_code == 401 else None
    return JSONResponse(
        status_code=error.status_code,
        content=error.to_problem(instance=request.url.path),
        media_type=PROBLEM_CONTENT_TYPE,
        headers=headers,
    )


async def netops_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle any :class:`NetOpsError` raised by a route or service."""
    if not isinstance(exc, NetOpsError):  # pragma: no cover - registration guarantees the type
        return await unhandled_error_handler(request, exc)
    if exc.status_code >= 500:
        _logger.error("netops_error", slug=exc.slug, detail=exc.detail, path=request.url.path)
    return _problem_response(exc, request)


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler: log the exception, return an opaque 500 problem.

    The response detail is deliberately generic — internals never leak to
    clients (secure by default).
    """
    _logger.exception("unhandled_exception", path=request.url.path, error=str(exc))
    return _problem_response(NetOpsError("An internal error occurred."), request)


def register_exception_handlers(app: FastAPI) -> None:
    """Install the global exception handlers on *app* (called by ``create_app``)."""
    app.add_exception_handler(NetOpsError, netops_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
