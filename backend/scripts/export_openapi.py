#!/usr/bin/env python3
"""Deterministic OpenAPI spec exporter (AR-W1-T2).

Closes the H14/M25-class seam: the frontend hand-rolls enum unions and
response interfaces for the ``devices``/``applications`` API modules with no
mechanical check against the backend's actual wire contract, so the two can
silently drift (see ``docs/roadmap/LESSONS.md`` and the ``agents.ts``
``AgentSessionStatus`` drift, repo-review M25 — left for a future expansion).

This module exports :func:`app.main.create_app`'s schema via ``FastAPI.openapi()``
— a pure schema-generation call. It does **not** trigger the app's ``lifespan``
(no DB/Redis/Neo4j/KMS connections are opened): ``lifespan`` only runs on actual
ASGI startup (``TestClient``/``uvicorn``), never on bare ``FastAPI()``
construction or a direct ``.openapi()`` call, so a default (env-var-free)
:class:`~app.core.config.Settings` is enough to build the app and export its
schema in CI with no live infra.

Output is a single JSON file with ``sort_keys=True`` and a trailing newline, so
re-running the export twice from the same code produces a byte-identical file —
that determinism is what makes the ``contract-drift`` CI diff meaningful rather
than noisy.

CLI::

    python scripts/export_openapi.py --write        # (re)write the committed spec
    python scripts/export_openapi.py --print         # emit generated spec to stdout
    python scripts/export_openapi.py --check         # diff vs committed → exit 1 on drift
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.main import create_app

_SCRIPTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = _SCRIPTS_DIR.parent
REPO_ROOT = BACKEND_DIR.parent

#: Committed location of the generated spec — a repo-root ``docs/api/`` home
#: (not ``backend/``) since the artifact is a shared backend/frontend contract,
#: not a backend-internal build output.
OPENAPI_SPEC_PATH = REPO_ROOT / "docs" / "api" / "openapi.json"


def export_schema() -> dict[str, Any]:
    """Build the app from a default ``Settings()`` and return its OpenAPI schema.

    A fresh :class:`~fastapi.FastAPI` instance is used (not the module-level
    ``app.main.app`` singleton) so the export never depends on process-local
    ``get_settings()`` caching or on any environment the CI runner happens to
    have set.
    """
    app = create_app(Settings())
    schema: dict[str, Any] = app.openapi()
    return schema


def render_spec() -> str:
    """Render the exported schema as stable, byte-identical JSON text.

    ``sort_keys=True`` normalizes dict key order (FastAPI does not guarantee it
    across Python versions/dict-construction order); a 2-space indent keeps the
    diff readable; the file ends with exactly one trailing newline.
    """
    schema = export_schema()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def _diff(committed: str, generated: str) -> str:
    return "".join(
        difflib.unified_diff(
            committed.splitlines(keepends=True),
            generated.splitlines(keepends=True),
            fromfile="docs/api/openapi.json (committed)",
            tofile="docs/api/openapi.json (generated)",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="(re)write the committed spec")
    group.add_argument("--print", action="store_true", help="emit generated spec to stdout")
    group.add_argument("--check", action="store_true", help="fail on spec drift")
    args = parser.parse_args(argv)

    if args.write:
        OPENAPI_SPEC_PATH.parent.mkdir(parents=True, exist_ok=True)
        OPENAPI_SPEC_PATH.write_text(render_spec(), encoding="utf-8")
        print(f"wrote {OPENAPI_SPEC_PATH}")
        return 0

    if args.print:
        sys.stdout.write(render_spec())
        return 0

    # --check
    generated = render_spec()
    committed = OPENAPI_SPEC_PATH.read_text(encoding="utf-8") if OPENAPI_SPEC_PATH.exists() else ""
    if generated != committed:
        sys.stderr.write(
            "ERROR: docs/api/openapi.json is out of sync with the FastAPI app. "
            "Re-generate:\n"
            "  cd backend && python scripts/export_openapi.py --write\n\n"
        )
        sys.stderr.write(_diff(committed, generated))
        return 1
    print("docs/api/openapi.json: in sync with the FastAPI app.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
