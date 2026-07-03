#!/usr/bin/env python3
"""Strict CRD field-validation for the CNPG/KEDA custom resources in a rendered
chart (P3 W4-T2 / audit-W2 T7 — closes systemic gap S1).

WHY THIS EXISTS. `kubeconform` -skips the CNPG `Cluster`/`Pooler` and KEDA
`ScaledObject`/`TriggerAuthentication` kinds ("no built-in schema"), and `conftest`
only evaluates hand-written rules. So an invented/misplaced field on one of those
custom resources passes EVERY static gate and only bites on live `kubectl apply`
(which is `continue-on-error` in the kind jobs). That is exactly how
`spec.postgresql.runAsNonRoot` — an unknown field the CNPG CRD REJECTS — reached a
live RED undetected (docs/production-audit-2026-07-01/T7-HARNESS-RECOVERY.md).

WHAT IT DOES. Replicates the apiserver's structural-schema STRICT field validation
(what `kubectl apply` >=1.25 sends as fieldValidation=Strict) against the VENDORED,
pinned CRDs in ci/kind/crd-schemas/. It walks each rendered CR and reports any field
NOT permitted by the CRD's openAPIV3Schema (honouring additionalProperties and
x-kubernetes-preserve-unknown-fields). A CNPG/KEDA CR with NO matching vendored
schema is a HARD FAIL (never a silent skip — a version drift must bite, not pass).

It does NOT evaluate CEL (x-kubernetes-validations) or the operator admission
webhook — those are separate/live-only classes. This closes the UNKNOWN-FIELD class,
the one that bit.

Usage:  validate-cr-schemas.py <rendered-manifests.yaml>
Exit:   0 = every CNPG/KEDA CR is structurally valid; non-zero = at least one
        unknown field OR an unmatched CR schema (count printed).
"""
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(
        "ERROR: PyYAML required (pip install pyyaml). "
        "The CI step installs it; locally `pip install pyyaml`.\n"
    )
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
CRD_DIR = os.path.normpath(os.path.join(HERE, "..", "crd-schemas"))

# The groups this guard is responsible for. A CR in one of these groups with no
# matching vendored schema is a HARD FAIL (drift), not a skip.
GUARDED_GROUPS = ("postgresql.cnpg.io", "keda.sh")


def load_crds(crd_dir):
    """(group, kind, version) -> openAPIV3Schema, from every *.yaml CRD in dir."""
    reg = {}
    if not os.path.isdir(crd_dir):
        sys.stderr.write(f"ERROR: vendored CRD dir missing: {crd_dir}\n")
        sys.exit(2)
    for fn in sorted(os.listdir(crd_dir)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        doc = yaml.safe_load(open(os.path.join(crd_dir, fn)))
        if not isinstance(doc, dict) or doc.get("kind") != "CustomResourceDefinition":
            continue
        group = doc["spec"]["group"]
        kind = doc["spec"]["names"]["kind"]
        for ver in doc["spec"]["versions"]:
            reg[(group, kind, ver["name"])] = ver["schema"]["openAPIV3Schema"]
    return reg


def unknown_fields(obj, schema, path=""):
    """Yield dotted paths of fields not permitted by the structural schema."""
    if not isinstance(obj, dict):
        return
    preserve = schema.get("x-kubernetes-preserve-unknown-fields", False)
    addl = schema.get("additionalProperties", None)
    props = schema.get("properties", {})
    for key, val in obj.items():
        child = f"{path}.{key}" if path else key
        # metadata is standard ObjectMeta — validated by the apiserver separately,
        # NOT against the CRD structural schema. Skip at the top level.
        if path == "" and key == "metadata":
            continue
        if key in props:
            child_schema = props[key]
            if isinstance(val, dict):
                yield from unknown_fields(val, child_schema, child)
            elif isinstance(val, list):
                items = child_schema.get("items", {})
                for i, el in enumerate(val):
                    if isinstance(el, dict):
                        yield from unknown_fields(el, items, f"{child}[{i}]")
        else:
            if preserve is True:
                continue
            if isinstance(addl, dict) or addl is True:
                continue
            yield child


def main(render_path):
    reg = load_crds(CRD_DIR)
    if not reg:
        sys.stderr.write(f"ERROR: no CRD schemas loaded from {CRD_DIR}\n")
        return 2
    docs = [d for d in yaml.safe_load_all(open(render_path)) if isinstance(d, dict)]

    checked = 0
    unknown = 0
    unmatched = 0
    for d in docs:
        api_version = str(d.get("apiVersion", ""))
        group, _, version = api_version.partition("/")
        if group not in GUARDED_GROUPS:
            continue
        kind = d.get("kind")
        name = d.get("metadata", {}).get("name", "<no-name>")
        schema = reg.get((group, kind, version))
        if schema is None:
            unmatched += 1
            print(
                f"[NO-SCHEMA] {api_version} {kind}/{name} — no vendored CRD schema "
                f"(version drift? refresh ci/kind/crd-schemas/ — see its README)"
            )
            continue
        checked += 1
        bad = list(unknown_fields(d, schema))
        if bad:
            unknown += len(bad)
            print(f"[UNKNOWN-FIELD] {kind}/{name} ({api_version}) — the live apply would REJECT:")
            for b in bad:
                print(f"       {b}")

    print(
        f"\n=== CR schema validation: {checked} CR(s) checked | "
        f"{unknown} unknown-field(s) | {unmatched} unmatched schema(s) ==="
    )
    if unknown or unmatched:
        print("::error::CNPG/KEDA custom resource(s) carry field(s) the live apply "
              "would REJECT (or a CR has no vendored schema). This is the S1 class "
              "the runAsNonRoot rot belonged to — fix before a live run.")
        return 1
    print("all CNPG/KEDA custom resources are structurally valid against the pinned CRDs.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: validate-cr-schemas.py <rendered-manifests.yaml>\n")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
