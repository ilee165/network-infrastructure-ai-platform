"""LLM provider readiness + connection probes (admin Settings surface).

Two layers (ADR-0009 local-first / secure-by-default):

1. **Configured** — credentials / deploy knobs present in env (no network).
2. **Probe** — bounded live check (Ollama ``/api/tags``; external models list
   endpoints) without accepting or returning secrets.

Responses never include API keys, endpoints, or raw exception text that might
embed a DSN. Field names avoid secret-hint tokens (``key``, ``token``,
``endpoint``, ``secret``, ``password``) so list/leak tests stay green.
"""

from __future__ import annotations

import os
import time
from typing import Any, Final, Literal

import httpx
from pydantic import BaseModel, Field

from app.core.config import Settings
from app.llm.providers import DEFAULT_MODELS, KNOWN_PROFILES

#: Hard budget for every outbound probe (matches health readiness spirit).
PROBE_TIMEOUT_SECONDS: Final = 3.0

ProfileStatus = Literal["ready", "not_configured", "unreachable", "error"]


class ProfileReadiness(BaseModel):
    """Non-secret readiness row for one known LLM profile."""

    profile: str
    #: True when deploy-time credentials (or local stack defaults) are present.
    configured: bool
    #: Live/config status after optional probe; static checks use not_configured/ready.
    status: ProfileStatus
    #: Default model / deployment name operators expect for this profile.
    model: str
    #: True when selecting this profile implies data may leave the deployment.
    egress: bool
    #: Pulled model tags from Ollama when a local probe succeeds; else empty.
    models: list[str] = Field(default_factory=list)
    #: Safe operator message (exception type / fixed phrase only — never secrets).
    detail: str | None = None
    latency_ms: float | None = None


class LlmReadinessReport(BaseModel):
    """Static configured-status report for every known profile (no network)."""

    active_profile: str
    local_model: str
    profiles: list[ProfileReadiness]


class LlmProbeRequest(BaseModel):
    """Body for ``POST …/llm-test`` — which profile to probe."""

    model_config = {"extra": "ignore"}

    profile: str = Field(min_length=1, max_length=64)


class LlmProbeResult(BaseModel):
    """Result of one live connection probe."""

    profile: str
    configured: bool
    status: ProfileStatus
    model: str
    egress: bool
    models: list[str] = Field(default_factory=list)
    detail: str | None = None
    latency_ms: float | None = None


def credentials_present(profile: str) -> bool:
    """Whether *profile* has the minimum deploy-time credentials in the environment."""
    if profile == "local":
        return True
    if profile == "anthropic":
        return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    if profile == "openai":
        return bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if profile == "azure":
        return bool(
            os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
            and os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
        )
    return False


def default_model_name(profile: str, settings: Settings) -> str:
    """Resolved default model/deployment for *profile* (no secrets)."""
    if profile == "local":
        return settings.llm_local_model
    return DEFAULT_MODELS.get(profile, profile)


def static_readiness(settings: Settings, *, active_profile: str) -> LlmReadinessReport:
    """Build a no-network readiness report for all :data:`KNOWN_PROFILES`."""
    rows: list[ProfileReadiness] = []
    for profile in KNOWN_PROFILES:
        configured = credentials_present(profile)
        egress = profile != "local"
        if configured:
            status: ProfileStatus = "ready"
            detail = None
        else:
            status = "not_configured"
            detail = "credentials not set in server environment"
        rows.append(
            ProfileReadiness(
                profile=profile,
                configured=configured,
                status=status,
                model=default_model_name(profile, settings),
                egress=egress,
                detail=detail,
            )
        )
    return LlmReadinessReport(
        active_profile=active_profile,
        local_model=settings.llm_local_model,
        profiles=rows,
    )


def _safe_detail(exc: BaseException) -> str:
    """Map exceptions to operator-safe fixed phrases (never ``str(exc)``)."""
    if isinstance(exc, httpx.TimeoutException):
        return "probe timed out"
    if isinstance(exc, httpx.ConnectError):
        return "connection refused or host unreachable"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"http {exc.response.status_code}"
    if isinstance(exc, httpx.HTTPError):
        return "http transport error"
    return type(exc).__name__


async def _http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> Any:
    """GET *url* and return parsed JSON; raises on non-2xx / transport failure."""
    async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as client:
        response = await client.get(url, headers=headers or {})
        response.raise_for_status()
        return response.json()


async def _probe_local(settings: Settings) -> LlmProbeResult:
    """Probe Ollama via ``GET {base}/api/tags``; list model names when up."""
    base = settings.ollama_base_url.rstrip("/")
    url = f"{base}/api/tags"
    model = default_model_name("local", settings)
    t0 = time.perf_counter()
    try:
        payload = await _http_get_json(url)
        latency = (time.perf_counter() - t0) * 1000.0
        models_raw = payload.get("models") if isinstance(payload, dict) else None
        names: list[str] = []
        if isinstance(models_raw, list):
            for entry in models_raw:
                if isinstance(entry, dict):
                    name = entry.get("name")
                    if isinstance(name, str) and name:
                        names.append(name)
        detail: str | None = None
        if model not in names and names:
            detail = f"configured model {model!r} not in pulled set"
        elif not names:
            detail = "ollama reachable but no models pulled"
        return LlmProbeResult(
            profile="local",
            configured=True,
            status="ready",
            model=model,
            egress=False,
            models=names,
            detail=detail,
            latency_ms=round(latency, 2),
        )
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000.0
        return LlmProbeResult(
            profile="local",
            configured=True,
            status="unreachable",
            model=model,
            egress=False,
            detail=_safe_detail(exc),
            latency_ms=round(latency, 2),
        )


async def _probe_external(profile: str, settings: Settings) -> LlmProbeResult:
    """Probe an external profile: credentials check + provider models HTTP GET."""
    model = default_model_name(profile, settings)
    if not credentials_present(profile):
        return LlmProbeResult(
            profile=profile,
            configured=False,
            status="not_configured",
            model=model,
            egress=True,
            detail="credentials not set in server environment",
        )

    headers: dict[str, str]
    url: str
    if profile == "anthropic":
        key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
        url = "https://api.anthropic.com/v1/models"
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }
    elif profile == "openai":
        key = (os.environ.get("OPENAI_API_KEY") or "").strip()
        url = "https://api.openai.com/v1/models"
        headers = {"Authorization": f"Bearer {key}"}
    elif profile == "azure":
        key = (os.environ.get("AZURE_OPENAI_API_KEY") or "").strip()
        endpoint = (os.environ.get("AZURE_OPENAI_ENDPOINT") or "").strip().rstrip("/")
        api_version = (os.environ.get("OPENAI_API_VERSION") or "2024-06-01").strip() or "2024-06-01"
        url = f"{endpoint}/openai/models?api-version={api_version}"
        headers = {"api-key": key}
    else:
        return LlmProbeResult(
            profile=profile,
            configured=False,
            status="error",
            model=model,
            egress=True,
            detail="unknown profile",
        )

    t0 = time.perf_counter()
    try:
        payload = await _http_get_json(url, headers=headers)
        latency = (time.perf_counter() - t0) * 1000.0
        # Never return provider model lists for external (can be large; not needed).
        _ = payload
        return LlmProbeResult(
            profile=profile,
            configured=True,
            status="ready",
            model=model,
            egress=True,
            detail=None,
            latency_ms=round(latency, 2),
        )
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000.0
        if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException)):
            status: ProfileStatus = "unreachable"
        else:
            status = "error"
        return LlmProbeResult(
            profile=profile,
            configured=True,
            status=status,
            model=model,
            egress=True,
            detail=_safe_detail(exc),
            latency_ms=round(latency, 2),
        )


async def probe_profile(profile: str, settings: Settings) -> LlmProbeResult:
    """Run a live connection probe for *profile*.

    Raises
    ------
    ValueError
        When *profile* is not in :data:`KNOWN_PROFILES`.
    """
    if profile not in KNOWN_PROFILES:
        raise ValueError(
            f"unknown LLM profile {profile!r}; known profiles: {', '.join(KNOWN_PROFILES)}"
        )
    if profile == "local":
        return await _probe_local(settings)
    return await _probe_external(profile, settings)
