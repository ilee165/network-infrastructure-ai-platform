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

import traceback
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.logging import get_logger

PROBLEM_CONTENT_TYPE = "application/problem+json"

_logger = get_logger(__name__)

#: Operator-facing detail when Postgres is up but Alembic has not been applied.
#: No secrets, no DSN material — just the fix command.
_SCHEMA_NOT_READY_DETAIL: Final = "Database schema is not applied. Run: alembic upgrade head"

#: Cap for the traceback string logged on unhandled exceptions. Large enough to
#: debug, small enough that ConsoleRenderer never pegs a core formatting SQLAlchemy
#: local-variable dumps (which previously stalled the event loop for minutes).
_TRACEBACK_MAX_CHARS: Final = 4000
_TRACEBACK_FRAME_LIMIT: Final = 20


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


class BadRequestError(NetOpsError):
    """The request is well-formed but semantically invalid (e.g. wrong secret).

    Used where the failure must not leak which input was wrong — the generic
    400 detail carries no oracle (e.g. a wrong current password on a self-service
    change).
    """

    status_code = 400
    title = "Bad Request"
    slug = "bad-request"


class UnprocessableEntityError(NetOpsError):
    """The request is syntactically valid but fails a domain validation rule.

    Used where the input parsed fine as JSON/types but is rejected by a
    domain-specific guard the schema cannot express on its own (e.g. a BPF
    capture filter that fails the injection whitelist). Surfaces as 422 — a
    client error to fix the input, not a 502 gateway/plugin failure.
    """

    status_code = 422
    title = "Unprocessable Entity"
    slug = "unprocessable-entity"


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


class PreconditionRequiredError(NetOpsError):
    """The request must be conditional (If-Match) to avoid a lost update (RFC 6585).

    Raised by a write endpoint that mandates optimistic-concurrency control when
    the caller omits the ``If-Match`` header carrying the resource's current
    ETag. Surfaces as ``428 Precondition Required`` — a client error the caller
    fixes by reading the resource, then re-issuing the write conditionally.
    """

    status_code = 428
    title = "Precondition Required"
    slug = "precondition-required"


class StalePreconditionError(ConflictError):
    """The If-Match precondition did not match the current row (optimistic-concurrency 409).

    A distinct-slug subclass of :class:`ConflictError` so it keeps the parent's
    ``409`` status and RFC 7807 handler while carrying its own discriminator
    ``type`` (``urn:netops:error:stale-precondition``). This is a conscious,
    documented deviation from RFC 7232's 412: the URN — not the status — is the
    load-bearing signal, letting a client tell a lost-update conflict apart from
    the sibling name-collision :class:`ConflictError` (slug ``conflict``).
    """

    slug = "stale-precondition"


class GraphTooLargeError(NetOpsError):
    """The requested topology subgraph exceeds the configured node cap.

    The G-SCA guard on ``GET /topology/graph`` (audit Wave 5, ARCH_DEBT #7):
    over the ``topology_max_nodes`` setting the API refuses outright rather
    than truncating, so a 200 is always the complete requested subgraph. The
    ``detail`` carries the count, the limit, and the scoped alternatives
    (``?site=`` / ``/graph/neighborhood``).
    """

    status_code = 413
    title = "Graph Too Large"
    slug = "graph-too-large"


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


class CredentialScopeError(ForbiddenError):
    """A device credential was used against a target outside its scope (ADR-0040 §2).

    Raised by the credentials service when, at session open, a scoped credential
    is asked to materialize for a device its scope does not cover — a structural
    least-privilege deny, not advisory. It is a 403 (authenticated, but the
    credential is not authorized for this target); the ``detail`` carries the
    credential/device IDS ONLY (never the scope values, the device attributes, or
    any secret material) so the deny is auditable without leaking the boundary.
    """

    title = "Credential Out Of Scope"
    slug = "credential-out-of-scope"


class RateLimitedError(NetOpsError):
    """Too many requests/attempts in a window (W6-T6; PRODUCTION.md §5).

    Surfaces as ``429`` with a coarse ``Retry-After`` (seconds). The ``detail``
    is deliberately generic: a throttled/locked response must not disclose
    whether the principal exists or how close it was to the limit (no oracle).
    """

    status_code = 429
    title = "Too Many Requests"
    slug = "rate-limited"

    def __init__(self, detail: str | None = None, *, retry_after: int = 0) -> None:
        super().__init__(detail)
        #: Coarse, window-bounded wait surfaced as the ``Retry-After`` header.
        self.retry_after = max(0, retry_after)


class PluginError(NetOpsError):
    """A vendor plugin operation failed (connection, command, or parse)."""

    status_code = 502
    title = "Vendor Plugin Failure"
    slug = "plugin-failure"


class LLMUpstreamError(NetOpsError):
    """An upstream LLM provider rejected the request or was unavailable.

    Raised when a model call fails at the provider/transport layer (e.g. an
    out-of-credits / rate-limit rejection, an authentication failure, a refused
    Ollama connection, or an unparseable structured response). It is a *gateway*
    failure, not a bug in our code, so it surfaces as a 502 with a generic,
    non-leaking detail rather than an opaque 500.
    """

    status_code = 502
    title = "AI Provider Failure"
    slug = "llm-upstream"


class SchemaNotReadyError(NetOpsError):
    """Postgres is reachable but required tables/migrations are missing.

    Typical first-run footgun: compose is up and ``/health/live`` is green, but
    ``alembic upgrade head`` was never run so ``users`` (and peers) do not exist.
    Surfaces as **503** with an operator-actionable detail — never a multi-second
    opaque 500 that burns CPU rendering a rich SQLAlchemy stack.
    """

    status_code = 503
    title = "Service Unavailable"
    slug = "schema-not-ready"


#: Top-level modules of the LLM provider/transport SDKs whose exceptions mean an
#: upstream failure (not a platform bug). Matched on the exception's root module
#: so the error layer never has to import the provider SDKs.
_LLM_PROVIDER_MODULES: frozenset[str] = frozenset(
    {
        "anthropic",
        "openai",
        "ollama",
        "httpx",
        "langchain_anthropic",
        "langchain_openai",
        "langchain_ollama",
        "langchain_google_genai",
    }
)


def translate_llm_error(exc: Exception) -> NetOpsError | None:
    """Map a provider/transport exception to :class:`LLMUpstreamError`, else ``None``.

    Returns ``None`` for exceptions that are already a :class:`NetOpsError`
    (they keep their own status — e.g. an RBAC :class:`ForbiddenError`) and for
    genuine code bugs (e.g. an ``AttributeError``), so real defects still surface
    as a 500 instead of being masked as a provider failure. The provider's own
    message is deliberately discarded — the detail is generic so nothing the
    provider echoes back can leak to clients.
    """
    if isinstance(exc, NetOpsError):
        return None
    root_module = type(exc).__module__.split(".", 1)[0]
    name = type(exc).__name__
    if root_module in _LLM_PROVIDER_MODULES or "OutputParser" in name:
        return LLMUpstreamError(
            "The AI model provider could not process the request; it may be "
            "unavailable, rate-limited, or misconfigured."
        )
    return None


def _is_missing_relation_error(exc: BaseException) -> bool:
    """True when *exc* (or its cause chain) is a missing-table / undefined relation.

    Matches asyncpg ``UndefinedTableError`` and SQLAlchemy ``ProgrammingError``
    wrappers without importing asyncpg/sqlalchemy at module load (keeps this
    module light and import-cycle free).
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        name = type(current).__name__
        msg = str(current).lower()
        if name == "UndefinedTableError" or "undefinedtable" in name.lower():
            return True
        # SQLAlchemy / asyncpg wrapper text: relation "users" does not exist
        if "does not exist" in msg and ("relation" in msg or "table" in msg):
            return True
        current = current.__cause__ or getattr(current, "orig", None) or current.__context__
    return False


def translate_db_schema_error(exc: Exception) -> SchemaNotReadyError | None:
    """Map a missing-schema DB exception to :class:`SchemaNotReadyError`, else ``None``.

    Already-typed :class:`NetOpsError` instances are left alone. Genuine code bugs
    (AttributeError, etc.) stay unmapped so they still surface as opaque 500s.
    The client detail is fixed and operator-facing — never the raw SQL / DSN.
    """
    if isinstance(exc, NetOpsError):
        return None
    if _is_missing_relation_error(exc):
        return SchemaNotReadyError(_SCHEMA_NOT_READY_DETAIL)
    return None


def _bounded_traceback(exc: BaseException) -> str:
    """Format a plain traceback string with frame + character caps (no locals).

    Deliberately avoids ``logger.exception`` / rich ConsoleRenderer local dumps,
    which on deep SQLAlchemy stacks burned ~100% CPU and stalled the event loop.
    """
    tb = "".join(
        traceback.format_exception(
            type(exc),
            exc,
            exc.__traceback__,
            limit=_TRACEBACK_FRAME_LIMIT,
        )
    )
    if len(tb) > _TRACEBACK_MAX_CHARS:
        return tb[:_TRACEBACK_MAX_CHARS] + "\n... (truncated)"
    return tb


def _problem_response(error: NetOpsError, request: Request) -> JSONResponse:
    headers: dict[str, str] | None = None
    if error.status_code == 401:
        headers = {"WWW-Authenticate": "Bearer"}
    elif isinstance(error, RateLimitedError):
        # RFC 7231 §7.1.3 Retry-After (delay-seconds form); coarse by design. A
        # 429 must ALWAYS carry Retry-After so a client knows to back off — a
        # boundary retry_after of 0 still emits a coarse minimum of 1 second
        # rather than a header-less 429 (CR4).
        retry_after = error.retry_after if error.retry_after > 0 else 1
        headers = {"Retry-After": str(retry_after)}
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

    Missing-schema DB errors are translated to a fast 503
    (:class:`SchemaNotReadyError`) with an operator-actionable detail. All other
    unhandled exceptions stay an opaque 500. Logging uses a **bounded plain
    traceback** (no ``logger.exception`` / rich local dumps) so a deep SQLAlchemy
    stack cannot pin the event loop at ~100% CPU.
    """
    mapped = translate_db_schema_error(exc)
    if mapped is not None:
        _logger.error(
            "schema_not_ready",
            path=request.url.path,
            error_type=type(exc).__name__,
        )
        return _problem_response(mapped, request)

    # Do NOT pass exc_info=True / use .exception(): structlog's ConsoleRenderer
    # in dev expands locals on every frame and can stall uvicorn for minutes on
    # SQLAlchemy ProgrammingError trees.
    _logger.error(
        "unhandled_exception",
        path=request.url.path,
        error_type=type(exc).__name__,
        error=str(exc)[:500],
        traceback=_bounded_traceback(exc),
    )
    return _problem_response(NetOpsError("An internal error occurred."), request)


def register_exception_handlers(app: FastAPI) -> None:
    """Install the global exception handlers on *app* (called by ``create_app``)."""
    app.add_exception_handler(NetOpsError, netops_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
