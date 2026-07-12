"""Contract tests for the config single-source generator (AR-W1-T1, H3, C5/C6).

These drive the SAME functions the ``config-drift`` CI job runs, and additionally
prove each check bites on a synthetic violation (the gate is not a false-green).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from app.core.config import Settings

# The generator lives under backend/scripts/ (not an installed package); load it
# by path so the test runs from the repo without a scripts/ package install.
_GEN_PATH = Path(__file__).resolve().parents[2] / "scripts" / "generate_env_example.py"
_spec = importlib.util.spec_from_file_location("generate_env_example", _GEN_PATH)
assert _spec and _spec.loader
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


# --------------------------------------------------------------------------- #
# Source-comment extraction.
# --------------------------------------------------------------------------- #
def test_extraction_recovers_real_descriptions() -> None:
    docs = gen.extract_field_docs(gen.CONFIG_SOURCE.read_text(encoding="utf-8"))
    # Sample fields with hand-written #: comments must round-trip meaningfully.
    assert docs["env"] is not None and "Deployment environment" in docs["env"]
    assert docs["secret_key"] is not None and "HS256 signing key" in docs["secret_key"]
    assert docs["ssh_strict"] is not None and "strict host-key checking" in docs["ssh_strict"]
    # Grouped comment-less fields map to None (rendered under their group head).
    assert docs["neo4j_user"] is None
    assert docs["neo4j_password"] is None


def test_every_field_is_extracted() -> None:
    docs = gen.extract_field_docs(gen.CONFIG_SOURCE.read_text(encoding="utf-8"))
    assert set(docs) == set(Settings.model_fields)


# --------------------------------------------------------------------------- #
# .env.example completeness + sync.
# --------------------------------------------------------------------------- #
def test_env_example_documents_every_settings_field() -> None:
    text = gen.render_env_example()
    for name in Settings.model_fields:
        assert f"\n{gen.env_key(name)}=" in text, f"{name} missing from .env.example"


def test_committed_env_example_is_in_sync() -> None:
    """H3 drift gate — the committed file equals a fresh render (byte-for-byte)."""
    generated = gen.render_env_example()
    committed = gen.ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
    assert committed == generated, (
        "committed .env.example is stale; regenerate with "
        "`python scripts/generate_env_example.py --write`"
    )


def test_hand_maintained_exception_blocks_preserved() -> None:
    text = gen.render_env_example()
    # Non-Settings exceptions kept verbatim and not managed as Settings fields.
    assert "NETOPS_ADMIN_PASSWORD=pwCHANGEME" in text
    assert "PGBACKREST_REPO1_CIPHER_PASS=pwCHANGEME" in text
    assert "MINIO_ROOT_USER=netops-backup" in text


def test_secret_material_never_emits_a_real_value() -> None:
    text = gen.render_env_example()
    # SecretStr / true-secret fields are empty or CHANGEME, never a live secret.
    assert "\nNETOPS_KEK=\n" in text
    assert "\nNETOPS_AUDIT_EXPORT_BEARER_TOKEN=\n" in text
    assert "\nNETOPS_NEO4J_PASSWORD=CHANGEME\n" in text
    # secret_key is the intentional dev tripwire (prod refuses it), emitted verbatim.
    assert "\nNETOPS_SECRET_KEY=dev-only-insecure-secret-key-change-me\n" in text


# --------------------------------------------------------------------------- #
# Secret classification.
# --------------------------------------------------------------------------- #
def test_configmap_heuristic_hit_list() -> None:
    secretstr = gen._secretstr_fields()
    caught = {
        n
        for n in Settings.model_fields
        if gen.is_configmap_excluded(n, is_secretstr=n in secretstr)
    }
    # Expected true secrets / secret-ish references caught by the conservative rule.
    for name in (
        "kek",
        "kek_file",
        "audit_export_bearer_token",
        "oidc_client_secret_ref",
        "vault_credential_ref",
        "vault_transit_key",
        "aws_kms_key_arn",
        "azure_key_name",
        "redis_password",
        "secret_key",
    ):
        assert name in caught, f"{name} should be configmap-excluded"


def test_secret_material_is_narrower_than_heuristic() -> None:
    secretstr = gen._secretstr_fields()
    # References are configmap-excluded but NOT secret material (safe in a ConfigMap).
    for ref in ("aws_kms_key_arn", "vault_transit_key", "azure_key_name", "vault_credential_ref"):
        assert gen.is_configmap_excluded(ref, is_secretstr=ref in secretstr)
        assert not gen.is_secret_material(ref, is_secretstr=ref in secretstr)
    # Live credentials are secret material.
    assert gen.is_secret_material("kek", is_secretstr=True)
    assert gen.is_secret_material("neo4j_password", is_secretstr=False)


def test_secretstr_fields_detected() -> None:
    assert gen._secretstr_fields() == frozenset({"kek", "audit_export_bearer_token"})


# --------------------------------------------------------------------------- #
# Helm chart key coverage / safety (C5/C6) — pass at HEAD.
# --------------------------------------------------------------------------- #
def test_chart_orphan_check_passes_at_head() -> None:
    assert gen.check_chart_orphans() == []


def test_chart_coverage_check_passes_at_head() -> None:
    assert gen.check_chart_coverage() == []


def test_configmap_secret_safety_passes_at_head() -> None:
    assert gen.check_configmap_secret_safety() == []


def test_chart_managed_baseline_matches_live_intersection() -> None:
    # The frozen baseline must equal what the chart actually renders today, so
    # coverage bites on a real drop rather than a stale constant.
    assert gen.chart_managed_fields() == gen._CHART_MANAGED_BASELINE


def test_chart_scan_reaches_subdirectory_templates() -> None:
    # Regression for a real gap: templates/ has admission/, backup/, policy/
    # subdirectories a non-recursive glob silently skips. NETOPS_KEK_REF is
    # rendered ONLY in deploy/kubernetes/netops/templates/backup/*.yaml, so
    # this only passes if the scan actually walks subdirectories.
    assert "NETOPS_KEK_REF" in gen.rendered_chart_keys()


def test_all_chart_exceptions_are_non_settings_keys() -> None:
    settings_keys = gen.settings_env_keys()
    for key in gen.CHART_KEY_EXCEPTIONS:
        assert key not in settings_keys, f"{key} is a Settings field; drop the exception"


def test_reference_safe_never_contains_secretstr() -> None:
    assert not (gen._secretstr_fields() & gen.CONFIGMAP_REFERENCE_SAFE)


# --------------------------------------------------------------------------- #
# The checks BITE on synthetic violations (anti-false-green controls).
# --------------------------------------------------------------------------- #
def test_orphan_check_bites_on_injected_key(monkeypatch: pytest.MonkeyPatch) -> None:
    real = gen.rendered_chart_keys()
    monkeypatch.setattr(gen, "rendered_chart_keys", lambda: real | {"NETOPS_TOTALLY_BOGUS_KEY"})
    problems = gen.check_chart_orphans()
    assert any("NETOPS_TOTALLY_BOGUS_KEY" in p for p in problems)


def test_coverage_check_bites_on_dropped_key(monkeypatch: pytest.MonkeyPatch) -> None:
    real = gen.rendered_chart_keys()
    dropped = next(iter(gen._CHART_MANAGED_BASELINE))
    monkeypatch.setattr(gen, "rendered_chart_keys", lambda: real - {dropped})
    problems = gen.check_chart_coverage()
    assert any(dropped in p for p in problems)


def test_configmap_safety_bites_on_secret_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    real = gen.configmap_data_keys()
    # Model a ConfigMap that renders the KEK as a plaintext literal value.
    monkeypatch.setattr(gen, "configmap_data_keys", lambda: real | {"NETOPS_KEK"})
    problems = gen.check_configmap_secret_safety()
    assert any("NETOPS_KEK" in p and "secret material" in p for p in problems)


def test_configmap_safety_bites_on_unlisted_secret_ish_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = gen.configmap_data_keys()
    # oidc_client_secret_ref is secret-ish and NOT reference-safe: a ConfigMap
    # literal for it must be flagged for review.
    monkeypatch.setattr(
        gen, "configmap_data_keys", lambda: real | {"NETOPS_OIDC_CLIENT_SECRET_REF"}
    )
    problems = gen.check_configmap_secret_safety()
    assert any("NETOPS_OIDC_CLIENT_SECRET_REF" in p for p in problems)
