"""Configuration management engine (M4; ADR-0017).

Snapshot capture (content-addressed, verbatim, diff-friendly) and drift
detection (baseline vs current unified diff) live here; the compliance engine
joins them in a later M4 task. Pure logic over the persistence layer and the D6
plugin contract — Celery wiring lives in :mod:`app.workers.tasks.config`, never
here (the engine never imports the worker layer, and agents never import the
engine: REPO-STRUCTURE §3.2).
"""

from app.engines.config_mgmt.capture import (
    CaptureResult,
    capture_snapshot,
    hash_config,
    normalize_config,
)
from app.engines.config_mgmt.drift import (
    DriftResult,
    NoBaselineError,
    approve_baseline,
    detect_drift,
)

__all__ = [
    "CaptureResult",
    "DriftResult",
    "NoBaselineError",
    "approve_baseline",
    "capture_snapshot",
    "detect_drift",
    "hash_config",
    "normalize_config",
]
