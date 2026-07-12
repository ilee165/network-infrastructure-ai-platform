#!/usr/bin/env python3
"""Single-source generator for ``.env.example`` + Helm-chart config-key drift checks.

Closes H3 (``.env.example`` documents *every* :class:`~app.core.config.Settings`
field, 1:1) and the C5/C6-class seam (every ``NETOPS_*`` key the Helm chart
renders is a real ``Settings`` field or an explicitly documented exception —
never a typo silently swallowed by ``extra="ignore"``, never secret *material*
in a plaintext ConfigMap).

Two outputs, two different exclusion rules — do not conflate them:

1. ``.env.example`` documents **all** ``Settings`` fields (secret-typed ones
   included, with a fake placeholder — never a real secret). Field descriptions
   are lifted from the Sphinx-style ``#:`` attribute-doc comments in
   ``config.py`` via :func:`extract_field_docs` (there is no runtime
   field-description API here — the descriptions are source comments, not
   pydantic ``Field(description=...)`` metadata).
2. The Helm ConfigMap must **never** render secret material. A field is
   *configmap-excluded* (:func:`is_configmap_excluded`) when it is ``SecretStr``
   OR its name matches a secret-ish pattern. This is deliberately conservative
   (it also catches non-secret *references* like ``aws_kms_key_arn``); such
   references that are legitimately rendered into the ConfigMap today are listed
   in :data:`CONFIGMAP_REFERENCE_SAFE` with a rationale, and a ``SecretStr``
   field may never be declared reference-safe (fail-closed).

The module is import-safe (introspection only) and exposes the check functions so
the ``config-drift`` CI job and the unit suite drive the same code.

CLI::

    python scripts/generate_env_example.py --write        # (re)write .env.example
    python scripts/generate_env_example.py --print        # emit to stdout
    python scripts/generate_env_example.py --check         # diff vs committed → exit 1 on drift
    python scripts/generate_env_example.py --check-chart   # chart key-coverage/safety → exit 1
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

from app.core.config import Settings

# --------------------------------------------------------------------------- #
# Repo layout (this file lives at ``backend/scripts/``).
# --------------------------------------------------------------------------- #
_SCRIPTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = _SCRIPTS_DIR.parent
REPO_ROOT = BACKEND_DIR.parent
CONFIG_SOURCE = BACKEND_DIR / "app" / "core" / "config.py"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
CHART_TEMPLATES_DIR = REPO_ROOT / "deploy" / "kubernetes" / "netops" / "templates"
CONFIGMAP_TEMPLATE = CHART_TEMPLATES_DIR / "configmap.yaml"

ENV_PREFIX = "NETOPS_"


def env_key(field_name: str) -> str:
    """``kek_file`` -> ``NETOPS_KEK_FILE`` (the canonical env var name)."""
    return f"{ENV_PREFIX}{field_name.upper()}"


# --------------------------------------------------------------------------- #
# Secret classification.
# --------------------------------------------------------------------------- #
# Conservative configmap-exclusion heuristic (plan-review decision: type-based
# PLUS naming, the safer default). Any field whose name contains one of these is
# treated as configmap-excluded even when plainly typed ``str``.
_SECRET_NAME_RE = re.compile(r"(_secret|_ref|_key|kek|token|password)")

# Narrow "true secret material" set: fields whose *value* is a live credential
# (not a by-reference handle / ARN / key-NAME / path). These are masked in
# ``.env.example`` and may never appear as a ConfigMap literal value. SecretStr
# fields are added dynamically in :func:`is_secret_material`.
_SECRET_MATERIAL_NAMES = frozenset({"neo4j_password", "redis_password", "kek", "kek_file"})

# secret_key is str-typed with a deliberately insecure DEV default that the prod
# posture guard (``_forbid_default_secret_in_prod``) refuses to start on. Shipping
# that exact tripwire value in .env.example is SAFER than a generic placeholder
# (which would slip past the guard), so it is emitted verbatim, not masked.
_DEV_TRIPWIRE_FIELDS = frozenset({"secret_key"})


def _secretstr_fields() -> frozenset[str]:
    """Names of ``Settings`` fields whose annotation is (Optional) ``SecretStr``.

    Detected from the *source* annotation text — pydantic collapses
    ``SecretStr | None`` into a union whose ``str`` origin is awkward to sniff at
    runtime, and the source text is unambiguous.
    """
    names: set[str] = set()
    source = CONFIG_SOURCE.read_text(encoding="utf-8")
    cls = _settings_classdef(ast.parse(source))
    for node in cls.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            annotation = ast.get_source_segment(source, node.annotation)
            if annotation and "SecretStr" in annotation:
                names.add(node.target.id)
    return frozenset(names)


def is_configmap_excluded(field_name: str, *, is_secretstr: bool) -> bool:
    """Conservative rule for what a ConfigMap-facing render must omit.

    ``True`` when the field is ``SecretStr`` OR its name matches the secret-ish
    pattern. Over-catches non-secret references on purpose (safer default); the
    reference fields legitimately rendered today are pinned in
    :data:`CONFIGMAP_REFERENCE_SAFE`.
    """
    return is_secretstr or bool(_SECRET_NAME_RE.search(field_name))


def is_secret_material(field_name: str, *, is_secretstr: bool) -> bool:
    """Narrow rule: does this field's *value* carry live credential material?

    Used for the hard ConfigMap-literal safety gate and the ``.env.example`` mask.
    References/ARNs/key-names/paths are NOT secret material.
    """
    return is_secretstr or field_name in _SECRET_MATERIAL_NAMES


# --------------------------------------------------------------------------- #
# Source-comment (``#:``) extraction.
# --------------------------------------------------------------------------- #
def _settings_classdef(tree: ast.Module) -> ast.ClassDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            return node
    raise RuntimeError("Settings class not found in config.py")


def extract_field_docs(source: str) -> dict[str, str | None]:
    """Map each ``Settings`` field to the doc-comment immediately above it.

    Recovers the Sphinx ``#:`` attribute-docstrings (and plain ``#`` group-header
    blocks that directly abut a field) by walking the contiguous comment lines
    above each ``AnnAssign``. Fields with no own comment (grouped under a shared
    header, e.g. ``neo4j_user`` under ``neo4j_uri``) map to ``None`` — they are
    emitted under the group head, not re-commented.
    """
    tree = ast.parse(source)
    cls = _settings_classdef(tree)
    lines = source.splitlines()
    docs: dict[str, str | None] = {}
    for node in cls.body:
        if not (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)):
            continue
        name = node.target.id
        if name == "model_config":
            continue
        collected: list[str] = []
        i = node.lineno - 2  # 0-indexed line directly above the assignment
        while i >= 0:
            stripped = lines[i].strip()
            if stripped.startswith("#:"):
                collected.append(stripped[2:].strip())
            elif stripped.startswith("#"):
                body = stripped[1:].strip()
                # Drop decorative separators (``# ----`` / ``# ====``).
                if body and set(body) <= set("-="):
                    i -= 1
                    continue
                collected.append(body)
            else:
                break
            i -= 1
        collected.reverse()
        text = " ".join(part for part in collected if part).strip()
        docs[name] = text or None
    return docs


def _clean_rst(text: str) -> str:
    """Light RST→plain cleanup so .env comments read as prose (deterministic)."""
    text = re.sub(r":[a-z]+:`~?([^`]*)`", r"\1", text)  # :attr:`~x.y` -> x.y
    text = text.replace("``", "")
    return text


# --------------------------------------------------------------------------- #
# Field default rendering.
# --------------------------------------------------------------------------- #
_PYDANTIC_UNDEFINED = "PydanticUndefined"


def _field_default(field_name: str) -> Any:
    field = Settings.model_fields[field_name]
    if field.default_factory is not None:
        return field.default_factory()  # type: ignore[call-arg]
    default = field.default
    if type(default).__name__ == _PYDANTIC_UNDEFINED:
        return None
    return default


def _render_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)  # str / Path


def env_value(field_name: str, *, is_secretstr: bool) -> str:
    """The placeholder value written for a field in ``.env.example``.

    Non-secret fields show their honest default (None/"" → empty). True secret
    material with a non-empty insecure default is masked with ``CHANGEME`` (never
    a real or weak-default secret); ``secret_key`` is the dev tripwire, emitted
    verbatim.
    """
    default = _field_default(field_name)
    rendered = _render_scalar(default)
    if field_name in _DEV_TRIPWIRE_FIELDS:
        return rendered
    if is_secret_material(field_name, is_secretstr=is_secretstr):
        return "CHANGEME" if rendered else ""
    return rendered


# --------------------------------------------------------------------------- #
# ``.env.example`` rendering.
# --------------------------------------------------------------------------- #
_HEADER = """\
# AI Network Operations Platform — environment contract (M0).
#
# GENERATED FILE — do not hand-edit. Regenerate after any change to
# backend/app/core/config.py Settings:
#
#   cd backend && python scripts/generate_env_example.py --write
#
# The `config-drift` CI gate re-generates this file and fails on any diff, so
# every NETOPS_ variable here maps 1:1 to a Settings field (H3). Field docs are
# lifted from the `#:` comments in config.py. Two blocks below are the ONLY
# hand-maintained exceptions (not Settings fields): the bootstrap admin password
# (migration-read) and the pgBackRest backup-tier (compose --profile backup).
#
# Copy to .env and adjust. Hostnames default to docker compose service names
# (deploy/docker/docker-compose.yml). Secret-typed fields carry a fake
# placeholder (CHANGEME) or an empty value — never a real secret; set real
# values out-of-band. CORS/JSON-list values must keep their JSON quoting intact
# (compose/uvicorn read this file verbatim; do NOT `set -a; . .env`).\
"""

# Verbatim hand-maintained exception blocks (NOT Settings fields). Preserved
# character-for-character from the pre-generator .env.example.
_ADMIN_PASSWORD_BLOCK = """\
# Bootstrap 'admin' account password. EXCEPTION to the 1:1-with-config.py rule
# above: this is read directly from the environment by the M1 Alembic migration
# (backend/alembic/versions/0001_*) the first time `alembic upgrade head` seeds the admin
# user — it is NOT a config.py field. If unset, the migration seeds the insecure
# default "admin" and logs a loud warning. Set a strong value before the first
# migration and rotate after first login.
NETOPS_ADMIN_PASSWORD=pwCHANGEME\
"""

_PGBACKREST_BLOCK = """\
# ---------------------------------------------------------------------------
# pgBackRest backup tier — Compose host-cron parity ONLY (W5-T1, ADR-0030 §1/§4).
# These are NOT app config (no NETOPS_ prefix, not in config.py) — they are read
# by docker-compose.backup.yml (`--profile backup`). The chart sources the same
# values from the platform Secret / external-secrets, never from here.
# ---------------------------------------------------------------------------
# aes-256-cbc repo passphrase — REQUIRED when the backup profile is up; generate
# a strong value, e.g.:  python -c "import secrets; print(secrets.token_urlsafe(48))"
# This is the repo cipher pass — a DISTINCT secret from any KEK; never co-locate
# it with the repo (ADR-0011 §4).
PGBACKREST_REPO1_CIPHER_PASS=pwCHANGEME
# Dev MinIO root credential = the object-store key/secret the backup writes with.
MINIO_ROOT_USER=netops-backup
MINIO_ROOT_PASSWORD=pwCHANGEME\
"""

# Group heads (fields with their own `#:` comment) that belong in the Quickstart
# block. A field is Quickstart iff its group head is here, which keeps grouped
# comment-less fields (e.g. neo4j_user/password) with their head.
_QUICKSTART_HEADS = frozenset(
    {
        "env",
        "secret_key",
        "database_url",
        "redis_url",
        "redis_password",
        "neo4j_uri",
        "llm_profile",
        "ollama_base_url",
        "cors_origins",
        "access_token_expire_minutes",
    }
)


def _group_heads() -> dict[str, str]:
    """Map every field to its group head (nearest field at/above with own doc)."""
    docs = extract_field_docs(CONFIG_SOURCE.read_text(encoding="utf-8"))
    heads: dict[str, str] = {}
    current: str | None = None
    for name in Settings.model_fields:
        if docs.get(name) is not None or current is None:
            current = name
        heads[name] = current
    return heads


def _wrap_comment(text: str) -> list[str]:
    cleaned = _clean_rst(text)
    wrapped = textwrap.wrap(cleaned, width=78, break_long_words=False, break_on_hyphens=False)
    return [f"# {line}" for line in wrapped]


def _render_fields(field_names: list[str], docs: dict[str, str | None]) -> list[str]:
    secretstr = _secretstr_fields()
    out: list[str] = []
    for name in field_names:
        doc = docs.get(name)
        if doc is not None:
            if out:
                out.append("")
            out.extend(_wrap_comment(doc))
        out.append(f"{env_key(name)}={env_value(name, is_secretstr=name in secretstr)}")
    return out


def render_env_example() -> str:
    """Return the full deterministic ``.env.example`` text (trailing newline)."""
    docs = extract_field_docs(CONFIG_SOURCE.read_text(encoding="utf-8"))
    heads = _group_heads()
    quickstart = [n for n in Settings.model_fields if heads[n] in _QUICKSTART_HEADS]
    advanced = [n for n in Settings.model_fields if heads[n] not in _QUICKSTART_HEADS]

    parts: list[str] = [_HEADER, ""]
    parts += [
        "# =====================================================================",
        "# Non-Settings exception: bootstrap admin password (migration-read).",
        "# =====================================================================",
        _ADMIN_PASSWORD_BLOCK,
        "",
        "# =====================================================================",
        "# Quickstart — the settings most deployments set first.",
        "# =====================================================================",
    ]
    parts += _render_fields(quickstart, docs)
    parts += [
        "",
        "# =====================================================================",
        "# Advanced — the full Settings surface (generated 1:1 from config.py).",
        "# Every remaining NETOPS_ field with its config.py description; safe",
        "# defaults apply when unset, so tune only what a deployment needs.",
        "# =====================================================================",
    ]
    parts += _render_fields(advanced, docs)
    parts += [
        "",
        "# =====================================================================",
        "# Non-Settings exception: pgBackRest backup-tier (compose --profile backup).",
        "# =====================================================================",
        _PGBACKREST_BLOCK,
    ]
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# Helm-chart key-coverage / safety checks (C5/C6).
# --------------------------------------------------------------------------- #
# Declaration/reference sites for a NETOPS_* key in a k8s manifest or Job shell.
# Restricted to real sites so glob/comment fragments (``NETOPS_DB_SSL_*``) never
# register as keys.
_CHART_KEY_PATTERNS = (
    re.compile(r"\bname:\s*NETOPS_([A-Z0-9_]+)"),  # container env var name
    re.compile(r"\bkey:\s*NETOPS_([A-Z0-9_]+)"),  # secret/config keyRef key
    re.compile(r"(?m)^\s*NETOPS_([A-Z0-9_]+):\s"),  # ConfigMap data: mapping key
    re.compile(r"\bNETOPS_([A-Z0-9_]+)="),  # shell assignment
    re.compile(r"\$\{NETOPS_([A-Z0-9_]+)\}"),  # ${VAR}
    re.compile(r"\$\(NETOPS_([A-Z0-9_]+)\)"),  # $(VAR)
    re.compile(r"environ\[[\"']NETOPS_([A-Z0-9_]+)"),  # os.environ["VAR"]
)

# ``NETOPS_*`` keys the chart renders that are NOT Settings fields. Each entry is
# an explicitly documented exception with a rationale (mirrors the T1
# import-linter allowlist convention). A NEW undocumented chart key fails the
# gate — that is the point.
#
# Class A — DSN/composition helpers. The db-migrate / credential-rotation /
# neo4j-rebuild / audit-verify Jobs shell-assemble NETOPS_DATABASE_URL from these
# pieces before invoking Python; the *_PASSWORD / _AUTH pieces arrive via
# secretKeyRef from the platform Secret (never a ConfigMap), _*_ENC are locally
# url-encoded shell vars.
# Class B — intentional non-Settings coordinates documented inline in
# configmap.yaml (redis_url is the Settings source of truth; these are
# backward-compat / Sentinel-discovery coords).
# Class C — PRE-EXISTING key/field mismatches (the exact C5/C6 seam this gate
# exists to surface). Allowlisted so the gate is green at HEAD; each is flagged
# for burn-down (a follow-on wave), NOT fixed here (fixing = a chart/runtime
# behavior change, out of scope for this additive task). See the T4 report
# open-questions.
CHART_KEY_EXCEPTIONS: dict[str, str] = {
    # Class A
    "NETOPS_POSTGRES_HOST": "DSN composition helper (Job shell); not a Settings field",
    "NETOPS_POSTGRES_PORT": "DSN composition helper (Job shell); not a Settings field",
    "NETOPS_POSTGRES_DB": "DSN composition helper (Job shell); not a Settings field",
    "NETOPS_POSTGRES_USER": "DSN composition helper (Job shell); not a Settings field",
    "NETOPS_POSTGRES_PASSWORD": "DSN password via secretKeyRef (Secret, never ConfigMap)",
    "NETOPS_PG_USER_ENC": "locally url-encoded user for DSN assembly (Job shell var)",
    "NETOPS_PG_PASS_ENC": "locally url-encoded password for DSN assembly (Job shell var)",
    "NETOPS_NEO4J_AUTH": "neo4j user/pass via secretKeyRef (Secret); split to NEO4J_PASSWORD",
    "NETOPS_KEK_REF": "KEK reference via secretKeyRef (drill Jobs); not a ConfigMap literal",
    # Class B
    "NETOPS_REDIS_HOST": "backward-compat single-instance coordinate (redis_url is the field)",
    "NETOPS_REDIS_PORT": "backward-compat single-instance coordinate (redis_url is the field)",
    "NETOPS_REDIS_SENTINEL_HOSTS": "Sentinel-discovery coordinate (non-secret); not a field",
    # Class C — pre-existing mismatch, burn-down flagged (see open questions)
    "NETOPS_LOG_LEVEL": "PRE-EXISTING: no Settings field; log level derives from settings.env",
    "NETOPS_OIDC_ENABLED": "PRE-EXISTING: oidc_enabled is a computed @property, env ignored",
    "NETOPS_KMS_PROVIDER": "PRE-EXISTING: no field (superseded by NETOPS_VAULT_KEY_PROVIDER)",
    "NETOPS_KMS_MASTER_KEY_REF": "PRE-EXISTING: no field (superseded by the vault_* fields)",
    "NETOPS_OIDC_CLIENT_SECRET": (
        "PRE-EXISTING: app resolves the secret via oidc_client_secret_ref "
        "(vault); this value key is unconsumed"
    ),
}

# Configmap-excluded (secret-heuristic) fields that are nonetheless legitimate,
# NON-SECRET references safely rendered as ConfigMap literals today (ARN / vault
# URI / key-NAME / credential-ref handle / backend selector). A SecretStr field
# may NEVER be listed here (asserted in :func:`check_configmap_secret_safety`).
CONFIGMAP_REFERENCE_SAFE: frozenset[str] = frozenset(
    {
        "vault_key_provider",  # backend selector (env|file|aws|azure|vault)
        "aws_kms_key_arn",  # AWS KMS key ARN (a reference, not the key)
        "azure_key_vault_uri",  # Azure Key Vault URI
        "azure_key_name",  # Azure key NAME (a reference)
        "vault_transit_key",  # Vault transit key NAME (a reference)
        "vault_credential_ref",  # indirect login handle (role/AppRole id)
    }
)


def _read_templates() -> list[tuple[Path, str]]:
    """Read every chart template, recursively.

    ``templates/`` has subdirectories (``admission/``, ``backup/``, ``policy/``);
    a non-recursive glob silently skips them, which defeats the coverage/orphan
    checks below for exactly the files most likely to need a new
    :data:`CHART_KEY_EXCEPTIONS` entry (drill Jobs that shell-assemble DSNs).
    """
    files = sorted(CHART_TEMPLATES_DIR.rglob("*.yaml")) + sorted(CHART_TEMPLATES_DIR.rglob("*.tpl"))
    return [(f, f.read_text(encoding="utf-8")) for f in files]


def rendered_chart_keys() -> set[str]:
    """All ``NETOPS_*`` keys declared/referenced across the chart templates."""
    keys: set[str] = set()
    for _path, text in _read_templates():
        for pattern in _CHART_KEY_PATTERNS:
            for suffix in pattern.findall(text):
                keys.add(f"{ENV_PREFIX}{suffix}")
    return keys


def settings_env_keys() -> set[str]:
    return {env_key(name) for name in Settings.model_fields}


def configmap_data_keys() -> set[str]:
    """``NETOPS_*`` keys rendered as ConfigMap ``data:`` literals (configmap.yaml only)."""
    text = CONFIGMAP_TEMPLATE.read_text(encoding="utf-8")
    return {f"{ENV_PREFIX}{m}" for m in re.findall(r"(?m)^\s*NETOPS_([A-Z0-9_]+):\s", text)}


def check_chart_orphans() -> list[str]:
    """Direction B: every rendered ``NETOPS_*`` key is a field or a documented exception."""
    rendered = rendered_chart_keys()
    allowed = settings_env_keys() | set(CHART_KEY_EXCEPTIONS)
    orphans = sorted(rendered - allowed)
    return [
        f"chart renders undocumented key {k!r}: neither a Settings field nor a "
        f"CHART_KEY_EXCEPTIONS entry (a typo swallowed by extra='ignore', or a new "
        f"field that must be wired + documented)"
        for k in orphans
    ]


def chart_managed_fields() -> frozenset[str]:
    """The Settings-backed keys the chart renders today (frozen coverage baseline).

    Derived from the live intersection so it cannot drift out of sync with a
    rename; direction A asserts none of these silently *vanish* from the chart.
    """
    return frozenset(settings_env_keys() & rendered_chart_keys())


# Frozen baseline captured at authoring time (37 keys). A regression that drops
# one of these from the templates makes it disappear from the live intersection
# and trips :func:`check_chart_coverage`.
_CHART_MANAGED_BASELINE: frozenset[str] = frozenset(
    {
        "NETOPS_AUDIT_EXPORT_BATCH_SIZE",
        "NETOPS_AUDIT_EXPORT_BEARER_TOKEN",
        "NETOPS_AUDIT_EXPORT_ENDPOINT",
        "NETOPS_AUDIT_EXPORT_FORMAT",
        "NETOPS_AUDIT_EXPORT_HOST",
        "NETOPS_AUDIT_EXPORT_POLL_SECONDS",
        "NETOPS_AUDIT_EXPORT_PORT",
        "NETOPS_AUDIT_EXPORT_RETRY_BACKOFF_SECONDS",
        "NETOPS_AWS_KMS_KEY_ARN",
        "NETOPS_AWS_REGION",
        "NETOPS_AZURE_KEY_NAME",
        "NETOPS_AZURE_KEY_VAULT_URI",
        "NETOPS_DATABASE_URL",
        "NETOPS_DB_SSL_CERT",
        "NETOPS_DB_SSL_KEY",
        "NETOPS_DB_SSL_MODE",
        "NETOPS_DB_SSL_ROOT_CERT",
        "NETOPS_IS_PROD",
        "NETOPS_JUNOS_COMMIT_CONFIRMED_MINUTES",
        "NETOPS_LLM_LOCAL_MODEL",
        "NETOPS_LLM_PROFILE",
        "NETOPS_NEO4J_PASSWORD",
        "NETOPS_NEO4J_URI",
        "NETOPS_NEO4J_USER",
        "NETOPS_OIDC_CLIENT_ID",
        "NETOPS_OIDC_ISSUER",
        "NETOPS_OLLAMA_BASE_URL",
        "NETOPS_REDIS_PASSWORD",
        "NETOPS_REDIS_SENTINEL_MASTER",
        "NETOPS_REDIS_URL",
        "NETOPS_SSH_STRICT",
        "NETOPS_VAULT_ADDR",
        "NETOPS_VAULT_CREDENTIAL_REF",
        "NETOPS_VAULT_KEY_PROVIDER",
        "NETOPS_VAULT_TRANSIT_KEY",
        "NETOPS_VAULT_TRANSIT_MOUNT",
        "NETOPS_WORKER_METRICS_PORT",
    }
)


def check_chart_coverage() -> list[str]:
    """Direction A: no key in the frozen chart-managed baseline vanished."""
    rendered = rendered_chart_keys()
    missing = sorted(_CHART_MANAGED_BASELINE - rendered)
    return [
        f"chart-managed key {k!r} is no longer rendered in any template (a "
        f"regression dropped it, or the baseline needs updating for an intentional removal)"
        for k in missing
    ]


def check_configmap_secret_safety() -> list[str]:
    """Hard gate: no secret *material* rendered as a ConfigMap literal.

    Every configmap.yaml ``data:`` key that maps to a configmap-excluded field
    must be an explicitly reference-safe field; and no ``SecretStr`` field may be
    declared reference-safe (fail-closed against a future SecretStr leaking in).
    """
    problems: list[str] = []
    secretstr = _secretstr_fields()

    leaked_secretstr = sorted(secretstr & CONFIGMAP_REFERENCE_SAFE)
    for name in leaked_secretstr:
        problems.append(
            f"SecretStr field {name!r} is in CONFIGMAP_REFERENCE_SAFE — secret "
            f"material can never be reference-safe; remove it"
        )

    key_to_field = {env_key(name): name for name in Settings.model_fields}
    for data_key in sorted(configmap_data_keys()):
        field = key_to_field.get(data_key)
        if field is None:
            continue  # non-Settings keys handled by the orphan gate
        if is_secret_material(field, is_secretstr=field in secretstr):
            problems.append(
                f"ConfigMap data literal {data_key!r} renders secret material "
                f"({field!r}) — deliver it via secretKeyRef from a Secret instead"
            )
        elif (
            is_configmap_excluded(field, is_secretstr=field in secretstr)
            and field not in CONFIGMAP_REFERENCE_SAFE
        ):
            problems.append(
                f"ConfigMap data literal {data_key!r} maps to secret-ish field "
                f"({field!r}) not in CONFIGMAP_REFERENCE_SAFE — confirm it is a "
                f"non-secret reference and allowlist it, or move it to a Secret"
            )
    return problems


def run_chart_checks() -> list[str]:
    return check_chart_orphans() + check_chart_coverage() + check_configmap_secret_safety()


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #
def _diff(committed: str, generated: str) -> str:
    return "".join(
        difflib.unified_diff(
            committed.splitlines(keepends=True),
            generated.splitlines(keepends=True),
            fromfile=".env.example (committed)",
            tofile=".env.example (generated)",
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true", help="(re)write .env.example")
    group.add_argument("--print", action="store_true", help="emit generated .env.example to stdout")
    group.add_argument("--check", action="store_true", help="fail on .env.example drift")
    group.add_argument("--check-chart", action="store_true", help="fail on chart key drift/leak")
    args = parser.parse_args(argv)

    if args.write:
        ENV_EXAMPLE_PATH.write_text(render_env_example(), encoding="utf-8")
        print(f"wrote {ENV_EXAMPLE_PATH}")
        return 0

    if args.print:
        sys.stdout.write(render_env_example())
        return 0

    if args.check:
        generated = render_env_example()
        committed = (
            ENV_EXAMPLE_PATH.read_text(encoding="utf-8") if ENV_EXAMPLE_PATH.exists() else ""
        )
        if generated != committed:
            sys.stderr.write(
                "ERROR: .env.example is out of sync with Settings. Re-generate:\n"
                "  cd backend && python scripts/generate_env_example.py --write\n\n"
            )
            sys.stderr.write(_diff(committed, generated))
            return 1
        print(".env.example: in sync with Settings.")
        return 0

    # --check-chart
    problems = run_chart_checks()
    if problems:
        sys.stderr.write("ERROR: Helm chart config-key drift:\n")
        for p in problems:
            sys.stderr.write(f"  - {p}\n")
        return 1
    print(
        "chart config keys: every rendered NETOPS_* key is a Settings field or a "
        "documented exception; no secret material in ConfigMap literals."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
