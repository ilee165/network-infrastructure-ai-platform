"""Document endpoints on ``/api/v1/docs`` (M4; T14; ADR-0019).

Routes (all read-only in M4):

    GET  /docs            viewer+  list generated documents (paginated, filterable)
    GET  /docs/{doc_id}   viewer+  detail (includes content)
    GET  /docs/{doc_id}/download  viewer+  raw content download payload

Documents are agent-generated artifacts (inventory / diagram / runbook).  The
A9 redaction layer is applied at the LLM boundary before a document is written
(ADR-0019), so the stored ``content`` is already redacted and safe to return to
any authenticated viewer.

The router tag is ``"documents"``; the prefix ``/docs`` is set here so that
``app.api.v1.__init__`` can include it without repeating the prefix.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, require_role
from app.core.errors import NotFoundError
from app.models import Document, DocumentKind, User
from app.schemas.config_mgmt import (
    DocumentDownload,
    DocumentListResponse,
    DocumentRead,
)

router = APIRouter(prefix="/docs", tags=["documents"])

DbSession = Annotated[AsyncSession, Depends(get_db)]
Viewer = Annotated[User, Depends(require_role("viewer"))]


@router.get("", response_model=DocumentListResponse)
async def list_documents(
    session: DbSession,
    _user: Viewer,
    kind: Annotated[DocumentKind | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> DocumentListResponse:
    """List generated documents, optionally filtered by kind (inventory/diagram/runbook).

    Viewer+ may access this endpoint.  Documents are agent-generated and the
    A9 redaction layer was applied at write time (ADR-0019), so content is safe
    for any authenticated user.
    """
    base = select(Document)
    if kind is not None:
        base = base.where(Document.kind == kind)

    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                base.order_by(Document.generated_at.desc(), Document.id).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return DocumentListResponse(
        items=[DocumentRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{doc_id}", response_model=DocumentRead)
async def get_document(
    doc_id: uuid.UUID,
    session: DbSession,
    _user: Viewer,
) -> DocumentRead:
    """Return one generated document by id (404 when unknown)."""
    doc = await session.get(Document, doc_id)
    if doc is None:
        raise NotFoundError(f"document {doc_id} does not exist")
    return DocumentRead.model_validate(doc)


@router.get("/{doc_id}/download", response_model=DocumentDownload)
async def download_document(
    doc_id: uuid.UUID,
    session: DbSession,
    _user: Viewer,
) -> DocumentDownload:
    """Return the download payload for a generated document (title + format + content).

    Viewer+ may access this endpoint.  This is the canonical download path for
    the frontend document library (M4 T16).
    """
    doc = await session.get(Document, doc_id)
    if doc is None:
        raise NotFoundError(f"document {doc_id} does not exist")
    return DocumentDownload.model_validate(doc)
