"""Configuration management engine (M4; ADR-0017).

Snapshot capture (content-addressed, verbatim, diff-friendly) lives here; drift
detection and the compliance engine join it in later M4 tasks. Pure logic over
the persistence layer and the D6 plugin contract — Celery wiring lives in
:mod:`app.workers.tasks.config`, never here (the engine never imports the
worker layer, and agents never import the engine: REPO-STRUCTURE §3.2).
"""

from app.engines.config_mgmt.capture import (
    CaptureResult,
    capture_snapshot,
    hash_config,
    normalize_config,
)

__all__ = [
    "CaptureResult",
    "capture_snapshot",
    "hash_config",
    "normalize_config",
]
