"""Contract tests for the OpenAPI spec exporter (AR-W1-T2).

Drives the SAME functions the ``contract-drift`` CI job runs, and proves the
export is process-stable (the property the CI diff depends on) and that the
gate bites on a real drift (not a false-green).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

# The exporter lives under backend/scripts/ (not an installed package); load it
# by path, matching the generate_env_example.py test's own pattern.
_EXPORT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "export_openapi.py"
_spec = importlib.util.spec_from_file_location("export_openapi", _EXPORT_PATH)
assert _spec and _spec.loader
export_openapi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_openapi)


def test_export_schema_is_a_valid_openapi_document() -> None:
    schema = export_openapi.export_schema()
    assert schema["openapi"].startswith("3.")
    assert "paths" in schema
    assert "components" in schema


def test_render_spec_is_deterministic_across_calls() -> None:
    """Re-running the export in the SAME process yields byte-identical output."""
    first = export_openapi.render_spec()
    second = export_openapi.render_spec()
    assert first == second


def test_render_spec_ends_with_exactly_one_trailing_newline() -> None:
    text = export_openapi.render_spec()
    assert text.endswith("\n")
    assert not text.endswith("\n\n")


def test_render_spec_is_sorted_json() -> None:
    """``json.dumps(..., sort_keys=True)`` — re-serializing must be a no-op."""
    text = export_openapi.render_spec()
    parsed = json.loads(text)
    reserialized = json.dumps(parsed, indent=2, sort_keys=True) + "\n"
    assert text == reserialized


def test_committed_spec_is_in_sync() -> None:
    """contract-drift gate — the committed file equals a fresh render."""
    generated = export_openapi.render_spec()
    committed = export_openapi.OPENAPI_SPEC_PATH.read_text(encoding="utf-8")
    assert committed == generated, (
        "committed docs/api/openapi.json is stale; regenerate with "
        "`cd backend && python scripts/export_openapi.py --write`"
    )


def test_devices_and_applications_schemas_present() -> None:
    """The two P4-Wave4 codegen-adopted modules must be exported."""
    schema = export_openapi.export_schema()
    names = set(schema["components"]["schemas"])
    for expected in (
        "DeviceRead",
        "DeviceListResponse",
        "DeviceInterfaceRead",
        "DeviceNeighborRead",
        "ApplicationRead",
        "ApplicationListResponse",
        "ApplicationDependencyRead",
    ):
        assert expected in names, f"{expected} missing from the exported OpenAPI schema"


def test_check_bites_on_planted_spec_drift(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Anti-false-green control: a stale committed spec must be detected as drift."""
    tampered = tmp_path / "openapi.json"
    tampered.write_text('{"tampered": true}\n', encoding="utf-8")
    monkeypatch.setattr(export_openapi, "OPENAPI_SPEC_PATH", tampered)
    assert export_openapi.main(["--check"]) == 1
