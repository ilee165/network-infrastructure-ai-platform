"""``python -m app.services.audit.export`` — run the audit→SIEM export worker."""

from __future__ import annotations

import asyncio
import sys

from app.services.audit.export.runner import _main

if __name__ == "__main__":  # pragma: no cover - thin module entrypoint
    sys.exit(asyncio.run(_main()))
