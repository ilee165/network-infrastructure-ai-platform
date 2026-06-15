"""Tests for document endpoints ``/api/v1/docs`` (M4; T14; ADR-0019).

Coverage:
- GET /docs               viewer+  list, filter by kind, paginate, 401 unauthenticated
- GET /docs/{id}          viewer+  detail, 404 on unknown
- GET /docs/{id}/download viewer+  download payload, 404 on unknown

Runs entirely over in-memory aiosqlite via ``tests/api/conftest.py`` fixtures.
No Postgres, Docker, or network.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Document, DocumentFormat, DocumentKind

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_document(
    session: AsyncSession,
    *,
    kind: DocumentKind = DocumentKind.INVENTORY,
    title: str = "Network Inventory",
    fmt: DocumentFormat = DocumentFormat.MD,
    content: str = "# Inventory\n\n| Device | IP |\n|--------|----|\n| sw-01 | 10.0.0.1 |\n",
    source_refs: dict[str, Any] | None = None,
) -> Document:
    doc = Document(
        kind=kind,
        title=title,
        format=fmt,
        content=content,
        source_refs=source_refs or {},
        generated_at=datetime.now(UTC),
    )
    session.add(doc)
    await session.flush()
    return doc


# ---------------------------------------------------------------------------
# List documents
# ---------------------------------------------------------------------------


class TestListDocuments:
    async def test_viewer_can_list(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        await _seed_document(session)
        await session.commit()

        resp = await client.get("/api/v1/docs", headers=auth_headers("viewer"))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1

    async def test_unauthenticated_is_401(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/docs")
        assert resp.status_code == 401

    async def test_empty_list(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        resp = await client.get("/api/v1/docs", headers=auth_headers("viewer"))
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    async def test_filter_by_kind(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        await _seed_document(session, kind=DocumentKind.INVENTORY, title="Inventory Doc")
        await _seed_document(session, kind=DocumentKind.DIAGRAM, title="Diagram Doc")
        await _seed_document(session, kind=DocumentKind.RUNBOOK, title="Runbook Doc")
        await session.commit()

        resp = await client.get(
            "/api/v1/docs",
            params={"kind": "inventory"},
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["kind"] == "inventory"

    async def test_pagination(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        for i in range(7):
            await _seed_document(session, title=f"Doc {i}")
        await session.commit()

        resp = await client.get(
            "/api/v1/docs",
            params={"limit": 3, "offset": 0},
            headers=auth_headers("viewer"),
        )
        data = resp.json()
        assert data["total"] == 7
        assert len(data["items"]) == 3

    @pytest.mark.parametrize("role", ["viewer", "operator", "engineer", "admin"])
    async def test_all_roles_can_list(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        role: str,
    ) -> None:
        resp = await client.get("/api/v1/docs", headers=auth_headers(role))
        assert resp.status_code == 200

    async def test_response_includes_content(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        await _seed_document(session, content="# Hello\n")
        await session.commit()

        resp = await client.get("/api/v1/docs", headers=auth_headers("viewer"))
        item = resp.json()["items"][0]
        # Unlike config snapshots, document content IS included (ADR-0019 — redacted at write)
        assert "content" in item
        assert item["content"] == "# Hello\n"


# ---------------------------------------------------------------------------
# Get one document
# ---------------------------------------------------------------------------


class TestGetDocument:
    async def test_viewer_gets_document(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        doc = await _seed_document(session, title="My Inventory")
        await session.commit()

        resp = await client.get(f"/api/v1/docs/{doc.id}", headers=auth_headers("viewer"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == str(doc.id)
        assert body["title"] == "My Inventory"
        assert "content" in body

    async def test_unknown_id_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(f"/api/v1/docs/{uuid.uuid4()}", headers=auth_headers("viewer"))
        assert resp.status_code == 404

    async def test_unauthenticated_is_401(
        self,
        client: httpx.AsyncClient,
        session: AsyncSession,
    ) -> None:
        doc = await _seed_document(session)
        await session.commit()

        resp = await client.get(f"/api/v1/docs/{doc.id}")
        assert resp.status_code == 401

    async def test_mermaid_diagram_document(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        content = "graph TD\n  A --> B\n"
        doc = await _seed_document(
            session,
            kind=DocumentKind.DIAGRAM,
            fmt=DocumentFormat.MERMAID,
            content=content,
            title="L2 Topology",
        )
        await session.commit()

        resp = await client.get(f"/api/v1/docs/{doc.id}", headers=auth_headers("viewer"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["format"] == "mermaid"
        assert body["content"] == content


# ---------------------------------------------------------------------------
# Download document
# ---------------------------------------------------------------------------


class TestDownloadDocument:
    async def test_viewer_downloads(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
    ) -> None:
        doc = await _seed_document(
            session, content="col1,col2\nval1,val2\n", fmt=DocumentFormat.CSV
        )
        await session.commit()

        resp = await client.get(f"/api/v1/docs/{doc.id}/download", headers=auth_headers("viewer"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["content"] == "col1,col2\nval1,val2\n"
        assert body["format"] == "csv"
        assert "title" in body
        assert "generated_at" in body

    async def test_unknown_id_is_404(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
    ) -> None:
        resp = await client.get(
            f"/api/v1/docs/{uuid.uuid4()}/download",
            headers=auth_headers("viewer"),
        )
        assert resp.status_code == 404

    async def test_unauthenticated_is_401(
        self,
        client: httpx.AsyncClient,
        session: AsyncSession,
    ) -> None:
        doc = await _seed_document(session)
        await session.commit()

        resp = await client.get(f"/api/v1/docs/{doc.id}/download")
        assert resp.status_code == 401

    @pytest.mark.parametrize("role", ["viewer", "operator", "engineer", "admin"])
    async def test_all_roles_can_download(
        self,
        client: httpx.AsyncClient,
        auth_headers: Callable[[str], dict[str, str]],
        session: AsyncSession,
        role: str,
    ) -> None:
        doc = await _seed_document(session, title=f"Doc for {role}")
        await session.commit()

        resp = await client.get(f"/api/v1/docs/{doc.id}/download", headers=auth_headers(role))
        assert resp.status_code == 200
