"""Deterministic compliance/audit report engine (P4 W3-T1; ADR-0053).

Assembles each report as a typed, secret-free payload (frozen Pydantic,
``extra="forbid"``), enforces the fail-closed redaction contract at ONE choke
point (:func:`app.engines.reports.redaction.enforce_redaction` inside the single
:func:`app.engines.reports.render.render_artifacts` path), and renders CSV
(stdlib, formula-injection neutralized) + PDF (WeasyPrint behind a deny-all URL
fetcher with bundled fonts — zero network egress at render time).

LLM output never enters an artifact; renders are deterministic (the generation
timestamp is payload data, never the render-time clock).
"""

from app.engines.reports.access import (
    ROLE_FLOORS,
    kinds_visible_to,
    required_role,
    role_meets_floor,
)
from app.engines.reports.builders import ENGINE_VERSION, build_payload
from app.engines.reports.idempotency import coerce_utc, deterministic_run_id, scheduled_period
from app.engines.reports.payloads import ReportPayload, ReportSection
from app.engines.reports.redaction import RedactionViolationError, enforce_redaction
from app.engines.reports.render import (
    RenderedArtifact,
    RenderEgressBlockedError,
    render_artifacts,
)

__all__ = [
    "ENGINE_VERSION",
    "ROLE_FLOORS",
    "RedactionViolationError",
    "RenderEgressBlockedError",
    "RenderedArtifact",
    "ReportPayload",
    "ReportSection",
    "build_payload",
    "coerce_utc",
    "deterministic_run_id",
    "enforce_redaction",
    "kinds_visible_to",
    "render_artifacts",
    "required_role",
    "role_meets_floor",
    "scheduled_period",
]
