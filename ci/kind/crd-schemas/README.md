# Vendored CRD schemas — CNPG + KEDA (pinned)

These are the **upstream CustomResourceDefinitions**, pinned to the exact versions
`ci/kind/ha/install-operators.sh` installs. They exist so the static layer can do what
`kubeconform` cannot: **strict field-validate the CNPG/KEDA custom resources**
(`Cluster`, `Pooler`, `ScaledObject`, `TriggerAuthentication`) against the real
structural schema, catching an invented/misplaced field BEFORE it reaches a live
`kubectl apply`.

They close **systemic gap S1** (see
`docs/production-audit-2026-07-01/T7-HARNESS-RECOVERY.md`): `kubeconform` `-skip`s these
kinds ("no built-in schema") and `conftest` only checks hand-written rules, so an
unknown CR field (e.g. the `spec.postgresql.runAsNonRoot` rot) passed every static gate
and only bit on live apply.

## Files & sources

| File | Kind | Source (pinned) |
|---|---|---|
| `postgresql.cnpg.io_clusters.yaml` | CNPG `Cluster` | `cloudnative-pg/cloudnative-pg` `release-1.29`, `config/crd/bases/` |
| `postgresql.cnpg.io_poolers.yaml` | CNPG `Pooler` | `cloudnative-pg/cloudnative-pg` `release-1.29`, `config/crd/bases/` |
| `keda.sh_scaledobjects.yaml` | KEDA `ScaledObject` | `kedacore/keda` `v2.16.1`, `config/crd/bases/` |
| `keda.sh_triggerauthentications.yaml` | KEDA `TriggerAuthentication` | `kedacore/keda` `v2.16.1`, `config/crd/bases/` |

`VERSIONS` records the pinned lines (`CNPG_RELEASE=1.29`, `KEDA=2.16.1`).

## Drift rule (enforced)

`ci/kind/selftest/validate-cr-schemas-bite.sh` **hard-fails** if `VERSIONS` does not
match the `CNPG_VERSION` / `KEDA_VERSION` pins in `ci/kind/ha/install-operators.sh`. So
bumping an operator pin **without refreshing these schemas** bites in CI — the schemas
can never silently go stale against the operator the cluster actually runs.

## Refresh (when an operator pin changes)

```bash
# CNPG (match install-operators.sh CNPG_VERSION major.minor -> release-<x.y> branch)
curl -fsSL https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/config/crd/bases/postgresql.cnpg.io_clusters.yaml -o ci/kind/crd-schemas/postgresql.cnpg.io_clusters.yaml
curl -fsSL https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/config/crd/bases/postgresql.cnpg.io_poolers.yaml  -o ci/kind/crd-schemas/postgresql.cnpg.io_poolers.yaml
# KEDA (match install-operators.sh KEDA_VERSION tag)
curl -fsSL https://raw.githubusercontent.com/kedacore/keda/v2.16.1/config/crd/bases/keda.sh_scaledobjects.yaml         -o ci/kind/crd-schemas/keda.sh_scaledobjects.yaml
curl -fsSL https://raw.githubusercontent.com/kedacore/keda/v2.16.1/config/crd/bases/keda.sh_triggerauthentications.yaml -o ci/kind/crd-schemas/keda.sh_triggerauthentications.yaml
# then update VERSIONS to match, and re-run:
bash ci/kind/selftest/validate-cr-schemas-bite.sh
```
