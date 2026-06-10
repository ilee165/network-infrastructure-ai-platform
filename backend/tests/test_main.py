"""App-factory tests: routing prefix, request-id correlation, CORS wiring."""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


async def test_api_mounted_under_api_v1(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")
    assert response.status_code == 200
    # The unprefixed path must not exist.
    response = await client.get("/health/live")
    assert response.status_code == 404


async def test_response_carries_generated_request_id(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")
    assert response.headers.get("X-Request-ID")


async def test_inbound_request_id_is_preserved(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/api/v1/health/live", headers={"X-Request-ID": "trace-me-12345"}
    )
    assert response.headers["X-Request-ID"] == "trace-me-12345"


def test_cors_configured_from_settings(app: FastAPI) -> None:
    cors = next(
        (mw for mw in app.user_middleware if mw.cls is CORSMiddleware),
        None,
    )
    assert cors is not None
    assert cors.kwargs["allow_origins"] == ["http://testserver"]
