{{/*
netops chart helpers (P1 W3 scaffold).

The hardened securityContext helper here is the reusable ADR-0029 §3 control
that W4 services (api/worker/frontend) consume — author once, apply everywhere,
so a hardened default cannot drift per-service.
*/}}

{{- define "netops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "netops.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "netops.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every object. */}}
{{- define "netops.labels" -}}
helm.sh/chart: {{ include "netops.chart" . }}
app.kubernetes.io/name: {{ include "netops.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: netops
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/*
Reusable hardened container securityContext (ADR-0029 §3 table).
Usage: {{- include "netops.hardenedSecurityContext" . | nindent 12 }}
Optional override map under .securityContextOverride is merged shallowly so a
caller can, for example, raise runAsUser without re-stating the whole block.
Every control is ON; weakening one is a warned values override (see _warnings).
*/}}
{{- define "netops.hardenedSecurityContext" -}}
{{- $h := .Values.hardening.securityContext -}}
runAsNonRoot: {{ $h.runAsNonRoot }}
runAsUser: {{ $h.runAsUser }}
runAsGroup: {{ $h.runAsGroup }}
allowPrivilegeEscalation: {{ $h.allowPrivilegeEscalation }}
readOnlyRootFilesystem: {{ $h.readOnlyRootFilesystem }}
privileged: false
capabilities:
  drop:
{{- range $h.capabilitiesDrop }}
    - {{ . }}
{{- end }}
seccompProfile:
  type: {{ $h.seccompProfile.type }}
{{- end -}}

{{/* Pod-level securityContext shared by hardened workloads. */}}
{{- define "netops.podSecurityContext" -}}
runAsNonRoot: {{ .Values.hardening.securityContext.runAsNonRoot }}
runAsUser: {{ .Values.hardening.securityContext.runAsUser }}
runAsGroup: {{ .Values.hardening.securityContext.runAsGroup }}
fsGroup: {{ .Values.hardening.securityContext.runAsGroup }}
seccompProfile:
  type: {{ .Values.hardening.podSeccompProfile.type }}
{{- end -}}

{{/* Fully-qualified backend image reference (no `latest` — admission rejects it). */}}
{{- define "netops.backendImage" -}}
{{- $img := .Values.images.backend -}}
{{- printf "%s:%s" $img.repository $img.tag -}}
{{- end -}}

{{/*
Fully-qualified image reference for an arbitrary entry under `.Values.images`.
Usage: {{ include "netops.image" (dict "img" .Values.images.frontend) }}
Always renders repo:tag (explicit tag, never `latest` — admission rejects it).
*/}}
{{- define "netops.image" -}}
{{- $img := .img -}}
{{- printf "%s:%s" $img.repository $img.tag -}}
{{- end -}}

{{/*
Per-component metadata labels (common labels + the component identifier).
Usage: {{- include "netops.componentLabels" (dict "ctx" . "component" "api") | nindent 4 }}
The `ctx` key carries the root context so the shared `netops.labels` resolves;
`component` is the workload identity used by Services/NetworkPolicies to select.
*/}}
{{- define "netops.componentLabels" -}}
{{ include "netops.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Stable pod/Service selector for a component (the immutable subset of labels a
Service `selector` and NetworkPolicy `podSelector` match on). Kept minimal and
version-independent so a chart upgrade does not orphan running pods.
Usage: {{- include "netops.serviceSelector" (dict "ctx" . "component" "api") | nindent 4 }}
*/}}
{{- define "netops.serviceSelector" -}}
app.kubernetes.io/name: {{ include "netops.name" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Namespace the packet-CAPTURE workload (Deployment/SA/NetworkPolicy) is installed
into (ADR-0031 §5). Capture adds NET_RAW, which built-in Pod Security Admission
rejects under `restricted` and a pod label cannot exempt — so capture lives in
its own namespace at a relaxed PSA level. Falls back to the release namespace if
unset so the chart still renders.
*/}}
{{- define "netops.captureNamespace" -}}
{{- default .Release.Namespace .Values.captureNamespace.name -}}
{{- end -}}

{{/*
netops.seccompInstallerNamespace — the namespace the seccomp-installer
DaemonSet/ConfigMap/SA render into. It runs root + DAC_OVERRIDE + a hostPath
mount to seed the kubelet seccomp profile, which built-in PSA `restricted` HARD-
REJECTS — pod annotations cannot exempt PSA (exemptions are API-server config).
So it MUST live in a relaxed-PSA namespace. Defaults to the capture namespace
(enforce=privileged), the already-gated home for the seccomp/NET_RAW deviation
(ADR-0029 §3 / ADR-0031 §5); override seccompInstaller.namespace to relocate.
Falls back to the release namespace if both are unset.
*/}}
{{- define "netops.seccompInstallerNamespace" -}}
{{- default (include "netops.captureNamespace" .) .Values.seccompInstaller.namespace -}}
{{- end -}}

{{/* Packet node-pool toleration matching the taint (ADR-0031 §5). */}}
{{- define "netops.packetToleration" -}}
- key: {{ .Values.packetNodePool.taint.key | quote }}
  operator: Equal
  value: {{ .Values.packetNodePool.taint.value | quote }}
  effect: {{ .Values.packetNodePool.taint.effect }}
{{- end -}}

{{/*
netops.platformSecretName — the Secret the chart references for platform
credentials (postgres password, OIDC, KMS ref, and the W5-T1 pgBackRest repo
keys). In production this is `secrets.existingSecret` (populated out-of-band by
external-secrets / CSI); in dev it is the chart-generated `<fullname>-dev-secrets`
(secret.yaml). Authored once so every consumer resolves the SAME name.
*/}}
{{- define "netops.platformSecretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{ .Values.secrets.existingSecret }}
{{- else -}}
{{ include "netops.fullname" . }}-dev-secrets
{{- end -}}
{{- end -}}

{{/*
netops.pgbackrestJobPod — the reusable backup Job-pod spec for a pgBackRest
backup of a given `--type` (W5-T1, ADR-0030 §1/§4). Authored ONCE so the weekly-
full and daily-incr CronJobs cannot drift. Args:
  ctx   = root context (.)
  type  = "full" | "incr"
The container runs ONE `sh -c` script: stanza-create (idempotent) → backup →
`pgbackrest verify` (GATES the job) → a non-empty `info` assertion (L5). All
credentials are PGBACKREST_* / PG* env from the platform Secret (secretKeyRef),
never inlined. Hardened via the shared securityContext helpers.
*/}}
{{- define "netops.pgbackrestJobPod" -}}
{{- $ctx := .ctx -}}
{{- $type := .type -}}
{{- $b := $ctx.Values.backup.postgres -}}
{{- $fullname := include "netops.fullname" $ctx -}}
{{- $secretName := include "netops.platformSecretName" $ctx -}}
spec:
  # The backup must not overlap the next tick (a second pgbackrest against the
  # same stanza races the repo); a missed window is rescheduled within the deadline.
  backoffLimit: {{ $b.backoffLimit }}
  template:
    metadata:
      labels:
        {{- include "netops.componentLabels" (dict "ctx" $ctx "component" "backup") | nindent 8 }}
    spec:
      serviceAccountName: backup-sa
      automountServiceAccountToken: {{ $ctx.Values.serviceAccounts.automountServiceAccountToken }}
      restartPolicy: Never
      securityContext:
        {{- include "netops.podSecurityContext" $ctx | nindent 8 }}
      containers:
        - name: pgbackrest
          image: {{ include "netops.image" (dict "img" $b.image) }}
          imagePullPolicy: {{ $b.image.pullPolicy }}
          securityContext:
            {{- include "netops.hardenedSecurityContext" $ctx | nindent 12 }}
          command:
            - sh
            - -c
            # ONE sh -c script (L3: env expands here; exec argv would NOT do
            # $(VAR)). pipefail + a `test -s` non-empty guard on the info pipe
            # (L5). `verify` GATES the job — `set -e` makes any non-zero (backup
            # OR verify) fail the pod. Credentials are PGBACKREST_* env, never argv.
            - |
              set -euo pipefail
              echo "[pgbackrest] stanza-create (idempotent) for stanza ${PGBACKREST_STANZA}"
              pgbackrest --stanza="${PGBACKREST_STANZA}" --log-level-console=info stanza-create || true
              echo "[pgbackrest] {{ $type }} backup -> object-store repo"
              pgbackrest --stanza="${PGBACKREST_STANZA}" --type={{ $type }} --log-level-console=info backup
              echo "[pgbackrest] verify (GATES this job — a non-clean verify fails it)"
              pgbackrest --stanza="${PGBACKREST_STANZA}" --log-level-console=detail verify
              echo "[pgbackrest] assert the backup set is non-empty"
              # L5: pipe through tee with pipefail; `test -s` guards an empty info
              # stream so a silently-empty repo fails the job instead of passing.
              pgbackrest --stanza="${PGBACKREST_STANZA}" info --output=text | tee /tmp/pgbackrest/info.txt
              test -s /tmp/pgbackrest/info.txt
              grep -q "status: ok" /tmp/pgbackrest/info.txt
              echo "[pgbackrest] {{ $type }} backup + verify complete"
          env:
            # Stanza + type as env (used by the sh -c script, not interpolated argv).
            - name: PGBACKREST_STANZA
              value: {{ $b.stanza | quote }}
            # pgBackRest reads its config from this path (the mounted ConfigMap).
            # The CronJob has NO PGDATA volume, so it uses the REMOTE view
            # (pg1-host=tls → the in-postgres `pgbackrest server` sidecar) when the
            # TLS server is enabled; the LOCAL view only applies in-pod (ADR-0030 §4).
            - name: PGBACKREST_CONFIG
              {{- if and $b.tls.enabled $ctx.Values.services.postgres.enabled }}
              value: /etc/pgbackrest/pgbackrest-remote.conf
              {{- else }}
              value: /etc/pgbackrest/pgbackrest.conf
              {{- end }}
            # Postgres auth — the backup connects as the platform DB user; the
            # password is by-reference (secrets.keys.postgresPassword).
            - name: PGUSER
              valueFrom:
                configMapKeyRef:
                  name: {{ $fullname }}-config
                  key: NETOPS_POSTGRES_USER
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ $secretName }}
                  key: {{ $ctx.Values.secrets.keys.postgresPassword }}
            {{- if $b.encryption.enabled }}
            # Repo cipher PASSPHRASE — aes-256-cbc (ADR-0030 §1). External-secret
            # REF only; NEVER inlined. pgBackRest reads PGBACKREST_REPO1_CIPHER_PASS.
            - name: PGBACKREST_REPO1_CIPHER_PASS
              valueFrom:
                secretKeyRef:
                  name: {{ $secretName }}
                  key: {{ $ctx.Values.secrets.keys.backupRepoCipherPass }}
            {{- end }}
            # Object-store credential (least-privilege, write-to-prefix only).
            # External-secret REFs only; NEVER inlined (ADR-0030 §1 / ADR-0011 §4).
            - name: PGBACKREST_REPO1_S3_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ $secretName }}
                  key: {{ $ctx.Values.secrets.keys.backupRepoS3Key }}
            - name: PGBACKREST_REPO1_S3_KEY_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ $secretName }}
                  key: {{ $ctx.Values.secrets.keys.backupRepoS3KeySecret }}
          resources:
            {{- toYaml $b.resources | nindent 12 }}
          volumeMounts:
            - name: pgbackrest-config
              mountPath: /etc/pgbackrest
              readOnly: true
            {{- if and $b.tls.enabled $ctx.Values.services.postgres.enabled }}
            # mTLS client material (CA + client cert/key) to reach the in-postgres
            # `pgbackrest server` over TLS (ADR-0030 §4). By-reference from the
            # Secret; the CronJob presents client.crt (CN = tls.clientCommonName).
            - name: pgbackrest-tls
              mountPath: /etc/pgbackrest-tls
              readOnly: true
            {{- end }}
            # readOnlyRootFilesystem:true — pgBackRest needs writable scratch for
            # its lock/spool/log + the info assertion file (the ONLY writable mounts).
            - name: pgbackrest-runtime
              mountPath: /var/lib/pgbackrest
            - name: pgbackrest-tmp
              mountPath: /tmp/pgbackrest
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: pgbackrest-config
          configMap:
            name: {{ $fullname }}-pgbackrest-config
        {{- if and $b.tls.enabled $ctx.Values.services.postgres.enabled }}
        # mTLS client material for the remote (TLS) backup path (ADR-0030 §4),
        # by-reference from the platform Secret (NEVER inlined).
        - name: pgbackrest-tls
          secret:
            secretName: {{ $secretName }}
            items:
              - key: {{ $ctx.Values.secrets.keys.backupTlsCa }}
                path: ca.crt
              - key: {{ $ctx.Values.secrets.keys.backupTlsClientCert }}
                path: client.crt
              - key: {{ $ctx.Values.secrets.keys.backupTlsClientKey }}
                path: client.key
        {{- end }}
        - name: pgbackrest-runtime
          emptyDir:
            sizeLimit: 1Gi
        - name: pgbackrest-tmp
          emptyDir:
            sizeLimit: 256Mi
        - name: tmp
          emptyDir:
            sizeLimit: 128Mi
{{- end -}}

{{/*
netops.dbClientTlsEnv — the api/worker -> Postgres mTLS CLIENT env (W4-T4,
ADR-0039 §4). Authored ONCE so the api + worker cannot drift. Renders the
NETOPS_DB_SSL_* settings (sslmode + the mounted cert/key/CA FILE paths) the
backend reads in app.db.build_ssl_connect_args. NO key material — only file
paths into the read-only Secret mount (ADR-0039 §5). Also sets NETOPS_DATABASE_URL
to the in-cluster DSN so the client dials the postgres Service over the verified
link (the app default DSN points at the compose host, not the chart Service).
Usage: {{- include "netops.dbClientTlsEnv" . | nindent 12 }}
Renders nothing when mtls.postgres.enabled is false.
*/}}
{{- define "netops.dbClientTlsEnv" -}}
{{- $m := .Values.mtls.postgres -}}
{{- if $m.enabled }}
# api/worker -> Postgres mTLS (ADR-0039 §4). The DSN targets the in-cluster
# postgres Service; the SSL mode + mounted client cert/key/CA drive the asyncpg
# verify-full SSLContext (app.db). The password stays a separate secretKeyRef env.
- name: NETOPS_DATABASE_URL
  value: postgresql+asyncpg://{{ .Values.config.postgres.user }}:$(NETOPS_POSTGRES_PASSWORD)@{{ .Values.config.postgres.host }}:{{ .Values.config.postgres.port }}/{{ .Values.config.postgres.database }}
- name: NETOPS_DB_SSL_MODE
  value: {{ $m.sslMode | quote }}
- name: NETOPS_DB_SSL_ROOT_CERT
  value: {{ printf "%s/%s" $m.mountPath ($m.caFile | default "ca.crt") | quote }}
- name: NETOPS_DB_SSL_CERT
  value: {{ printf "%s/%s" $m.mountPath ($m.serverCertFile | default "tls.crt") | quote }}
- name: NETOPS_DB_SSL_KEY
  value: {{ printf "%s/%s" $m.mountPath ($m.serverKeyFile | default "tls.key") | quote }}
{{- end -}}
{{- end -}}

{{/*
netops.dbClientTlsVolumeMount — the read-only CLIENT cert mount for api/worker
(W4-T4, ADR-0039 §5). The client Secret (cert-manager-issued or dev-fallback)
mounted at mtls.postgres.mountPath. Usage:
  {{- include "netops.dbClientTlsVolumeMount" . | nindent 12 }}
*/}}
{{- define "netops.dbClientTlsVolumeMount" -}}
{{- if .Values.mtls.postgres.enabled }}
# api/worker -> Postgres mTLS client cert/key + CA, mounted read-only from the
# Secret (cert-manager-issued or dev-fallback). Never image-baked (ADR-0039 §5).
- name: db-tls-client
  mountPath: {{ .Values.mtls.postgres.mountPath }}
  readOnly: true
{{- end -}}
{{- end -}}

{{/*
netops.dbClientTlsVolume — the CLIENT cert Secret volume for api/worker
(W4-T4, ADR-0039 §5). defaultMode 0400: the client KEY is readable ONLY by the
pod's runAsUser, never group/world (the pods run as a single non-root uid; no
fsGroup-shared reader needs it). Usage:
  {{- include "netops.dbClientTlsVolume" . | nindent 8 }}
*/}}
{{- define "netops.dbClientTlsVolume" -}}
{{- if .Values.mtls.postgres.enabled }}
- name: db-tls-client
  secret:
    secretName: {{ .Values.mtls.postgres.clientSecretName }}
    defaultMode: 0400
{{- end -}}
{{- end -}}
