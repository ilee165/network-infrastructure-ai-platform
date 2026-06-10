"""structlog configuration and request-id correlation helpers (ADR-0015).

All backend logging flows through structlog: a JSON renderer in prod (one JSON
object per line, container-native) and a pretty console renderer in dev.
Stdlib logging (uvicorn, SQLAlchemy, Celery, netmiko) is routed through
structlog's ``ProcessorFormatter`` so the whole stream is uniform.

Correlation: an HTTP middleware (``app.main``) binds a per-request id into a
``contextvars.ContextVar``; every log line emitted while it is bound carries a
``request_id`` key. M1+: ``agent_session_id`` / ``reasoning_trace_id`` bindings
join via ``structlog.contextvars``.
"""

from __future__ import annotations

import logging
import sys
import uuid
from contextvars import ContextVar, Token
from typing import cast

import structlog

from app.core.config import Settings

_REQUEST_ID: ContextVar[str | None] = ContextVar("netops_request_id", default=None)


def new_request_id() -> str:
    """Generate a fresh opaque request id (hex UUID4)."""
    return uuid.uuid4().hex


def bind_request_id(request_id: str) -> Token[str | None]:
    """Bind *request_id* to the current context.

    Returns the token to pass to :func:`reset_request_id` when the request ends.
    """
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    """Restore the request-id context to its state before :func:`bind_request_id`."""
    _REQUEST_ID.reset(token)


def get_request_id() -> str | None:
    """Return the request id bound to the current context, if any."""
    return _REQUEST_ID.get()


def _add_request_id(
    logger: structlog.typing.WrappedLogger,
    method_name: str,
    event_dict: structlog.typing.EventDict,
) -> structlog.typing.EventDict:
    """structlog processor: inject the bound request id into every event."""
    request_id = _REQUEST_ID.get()
    if request_id is not None:
        event_dict["request_id"] = request_id
    return event_dict


def configure_logging(settings: Settings) -> None:
    """Configure structlog and route stdlib logging through it.

    Idempotent: safe to call from ``create_app()`` and from the Celery worker
    boot path; the root handler set is replaced, not appended to.
    """
    shared_processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        _add_request_id,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]
    renderer: structlog.typing.Processor
    if settings.env == "prod":
        # ConsoleRenderer formats exc_info itself; only the JSON path needs this.
        shared_processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[*shared_processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,  # allow reconfiguration (tests, env switch)
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
        foreign_pre_chain=shared_processors,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if settings.env == "dev" else logging.INFO)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named structlog logger (typed convenience wrapper)."""
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
