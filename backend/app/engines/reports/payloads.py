"""Typed report payloads (ADR-0053 §1): frozen, ``extra="forbid"``, secret-free.

Every report is assembled as a :class:`ReportPayload` — a generic
sections-of-tables shape the four W3-T2..T5 report builders populate — and every
payload passes :func:`app.engines.reports.redaction.enforce_redaction` in the
single render path before any renderer sees it. ``extra="forbid"`` +
``frozen=True`` mean a builder cannot smuggle undeclared fields past the
redaction walk, and a payload cannot mutate between the redaction check and the
renderer.

Determinism (ADR-0053 §1): ``generated_at`` is INJECTED payload data — the
renderer never reads the clock, so the same payload + template + renderer
version reproduces the same artifact content (PDF metadata dates are pinned
from this same field).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class _FrozenModel(BaseModel):
    """Base config for every payload model: frozen + closed field set."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportSection(_FrozenModel):
    """One titled table of a report: column headers + string rows."""

    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...] = ()


class ReportPayload(_FrozenModel):
    """The complete, secret-free input of one report render (ADR-0053 §1)."""

    kind: str
    title: str
    period_start: datetime
    period_end: datetime
    #: Injected at generation time by the task — NEVER read from the clock at
    #: render time (deterministic, reproducible evidence; ADR-0053 §1).
    generated_at: datetime
    #: Regime control tags (metadata only; SOC 2 CC-series PROPOSED default,
    #: ADR-0053 §8).
    regime_tags: tuple[str, ...] = ()
    sections: tuple[ReportSection, ...] = ()
    notes: tuple[str, ...] = ()
