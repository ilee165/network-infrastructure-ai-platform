"""Regime-mapping version + drift guard (P4 W3-T6; ADR-0053 §8).

The authoritative report<->control mapping is a hand-authored doc
(``docs/compliance/soc2-cc-mapping.md``), not generated code — so unlike the
``.env.example`` config-drift gate (which regenerates and diffs), the guard
here pins the doc's content hash to the version it was written at.
:mod:`app.engines.reports.builders` appends :data:`MAPPING_VERSION_TAG` to
every kind's default ``regime_tags`` so a generated run snapshots *which*
revision of the doc was authoritative when it ran (ADR-0053 §8: tags are
metadata only; report content stays regime-neutral).

``backend/tests/engines/reports/test_regime_mapping.py`` is the drift guard:
it fails if the doc's content no longer hashes to :data:`MAPPING_DOC_SHA256`
for the current :data:`MAPPING_VERSION` — a substantive doc edit must bump
the version and update the hash in the SAME change, or the check goes red.
The doc's own "Rebasing to a different regime" section is the human-facing
mirror of this rule.

Hashing reads the doc in TEXT mode (universal-newline translation) before
encoding, so the pinned hash is stable across a CRLF checkout (Windows,
``core.autocrlf=true``) and an LF checkout (CI) alike — hashing raw bytes
would make the guard checkout-dependent and falsely trip.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

#: SOC 2 CC-series is the PROPOSED default regime (PRODUCTION.md §7/§12; ADR-0053
#: §8) until the Consultant's Q7 "compliance regimes" item is answered. Bumping
#: this integer is the ONLY sanctioned response to a substantive edit of the
#: mapping doc below — it must move in lockstep with MAPPING_DOC_SHA256.
MAPPING_VERSION: Final[int] = 1

#: Appended to every kind's SOC2 CC-series control tags in
#: ``app.engines.reports.builders.REGIME_TAG_DEFAULTS`` — metadata pointing at
#: which mapping-doc revision was in force at generation, never a control
#: identifier itself (ADR-0053 §8).
MAPPING_VERSION_TAG: Final[str] = f"mapping-version:{MAPPING_VERSION}"

#: Repo-relative path to the authoritative report<->control mapping doc
#: (P4 W3-T6). ``parents[4]`` from this file: reports/ -> engines/ -> app/ ->
#: backend/ -> repo root.
MAPPING_DOC_PATH: Final[Path] = (
    Path(__file__).resolve().parents[4] / "docs" / "compliance" / "soc2-cc-mapping.md"
)

#: sha256 of the doc's content (text-mode read, see module docstring) AT
#: MAPPING_VERSION. Recompute + update alongside any doc edit + version bump:
#: ``python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path(
#: 'docs/compliance/soc2-cc-mapping.md').read_text(encoding='utf-8').encode()
#: ).hexdigest())"`` (run from the repo root).
MAPPING_DOC_SHA256: Final[str] = "af9a86854b5c7c996317bed08cf50390ecba7f967262ee32b8ea7167714b33e8"


def mapping_doc_sha256() -> str:
    """Current sha256 of the mapping doc's content (text-mode, see docstring)."""
    return hashlib.sha256(MAPPING_DOC_PATH.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


__all__ = [
    "MAPPING_DOC_PATH",
    "MAPPING_DOC_SHA256",
    "MAPPING_VERSION",
    "MAPPING_VERSION_TAG",
    "mapping_doc_sha256",
]
