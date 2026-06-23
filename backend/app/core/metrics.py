"""KEK-provider Prometheus gauges for the fail-closed readiness gate (P1 W6-T2).

ADR-0032 §2/§4 require the active KEK backend's *posture* and *liveness* to be
gate-checkable series on ``/metrics``, not just a log line — so a non-production
KEK or an unreachable KMS cannot hide behind a green deploy:

  * ``vault_key_provider_production_grade`` — Gauge ``1`` when the active provider
    self-reports :attr:`~app.core.crypto.KeyProvider.is_production_grade`, else
    ``0`` (a local Env/File fallback). Set once at startup (ADR-0032 §2/§5).
  * ``vault_key_provider_healthy`` — Gauge ``1`` when ``provider.health()`` last
    reported reachable, else ``0``. Refreshed by the readiness probe so an
    unreachable KMS pulls the replica from rotation while it stays *live*
    (ADR-0032 §4).

Registration is **graceful**, mirroring :mod:`app.engines.topology.metrics`:
``prometheus_client`` is an optional observability dependency (D15). When it is
importable the gauges register on the default ``REGISTRY`` (the api/worker
``/metrics`` endpoint exposes them); when it is not, the setters become safe
no-ops so importing this module — and the crypto/health paths that call it —
never hard-fails on a slim install.

Secure by default (ADR-0032 §6): these series carry only a 0/1 posture flag —
never a key handle, ARN, vault URI, ``credential_ref``, or any key material.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "PROVIDER_HEALTHY",
    "PROVIDER_PRODUCTION_GRADE",
    "set_provider_healthy",
    "set_provider_production_grade",
]

try:  # Optional observability dependency (D15) — degrade to no-ops if absent.
    from prometheus_client import Gauge

    PROVIDER_PRODUCTION_GRADE: Any = Gauge(
        "vault_key_provider_production_grade",
        "1 when the active credential-vault KEK provider self-reports "
        "production-grade (a real KMS backend), 0 for a local Env/File fallback "
        "(ADR-0032 §2).",
    )
    PROVIDER_HEALTHY: Any = Gauge(
        "vault_key_provider_healthy",
        "1 when the active KEK provider was last reachable, 0 when its health() "
        "reported unavailable (drives the fail-closed readiness gate, ADR-0032 §4).",
    )
    _PROM_ENABLED = True
except Exception:  # pragma: no cover - exercised only on a slim install
    # No prometheus_client: keep the symbols present (callers reference them) but
    # inert. The startup banner + readiness body remain the source of truth.
    PROVIDER_PRODUCTION_GRADE = None
    PROVIDER_HEALTHY = None
    _PROM_ENABLED = False


def set_provider_production_grade(*, production_grade: bool) -> None:
    """Record the active KEK provider's production-grade posture (0/1 gauge).

    No-op when ``prometheus_client`` is unavailable; the startup banner still
    carries the posture either way.
    """
    if not _PROM_ENABLED:
        return
    PROVIDER_PRODUCTION_GRADE.set(1 if production_grade else 0)


def set_provider_healthy(*, healthy: bool) -> None:
    """Record the active KEK provider's last-observed liveness (0/1 gauge).

    No-op when ``prometheus_client`` is unavailable; the readiness body still
    reports per-dependency up/down either way.
    """
    if not _PROM_ENABLED:
        return
    PROVIDER_HEALTHY.set(1 if healthy else 0)
