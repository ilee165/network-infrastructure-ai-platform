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

{{/*
The effective in-cluster Postgres HOST the api/worker/cronjobs dial (W1-T2,
ADR-0042 §3/§4). When the CloudNativePG HA tier is enabled the single-instance
`config.postgres.host` Service (`netops-postgres`) is NOT rendered; every
connection MUST go through the PgBouncer Pooler read-write Service
(`<fullname>-pg-pooler-rw`) so the connection budget holds and PgBouncer re-points
to the new primary on failover. When CNPG is OFF this is just
`config.postgres.host` — the GA single-instance render is byte-for-byte unchanged.
Usage: {{ include "netops.postgresHost" . }}
*/}}
{{- define "netops.postgresHost" -}}
{{- if .Values.cloudNativePg.enabled -}}
{{- printf "%s-pg-pooler-rw" (include "netops.fullname" .) -}}
{{- else -}}
{{- .Values.config.postgres.host -}}
{{- end -}}
{{- end -}}

{{/*
netops.redisSentinelHosts — the `;`-joined Sentinel host:port list the
failover-aware client uses for primary discovery (W1-T4, ADR-0044 §1). Each
Sentinel StatefulSet pod has a stable headless-Service DNS name
(<fullname>-redis-sentinel-<ordinal>.<fullname>-redis-sentinel-headless), so the
client can reach EVERY Sentinel even while one is down — there is NO single
Sentinel host pin. Usage: {{ include "netops.redisSentinelHosts" . }}
*/}}
{{- define "netops.redisSentinelHosts" -}}
{{- $fullname := include "netops.fullname" . -}}
{{- $svc := printf "%s-redis-sentinel-headless" $fullname -}}
{{- $port := .Values.redisSentinel.sentinel.port -}}
{{- $hosts := list -}}
{{- range $i := until (int .Values.redisSentinel.sentinel.replicas) -}}
{{- $hosts = append $hosts (printf "%s-redis-sentinel-%d.%s:%v" $fullname $i $svc $port) -}}
{{- end -}}
{{- $hosts | join ";" -}}
{{- end -}}

{{/*
netops.redisUrl — the failover-aware Redis URL the api/worker/KEDA dial as
NETOPS_REDIS_URL (W1-T4, ADR-0044 §1). When the redisSentinel HA tier is enabled
this is a `sentinel://h0:26379;h1:26379;h2:26379/<db>` URL pointing at the 3
Sentinels — so the client (kombu/redis-py Sentinel transport) resolves the
CURRENT primary at connect time and re-points on failover with NO config change
(the load-bearing no-static-host-pin decision). When the tier is OFF this is the
plain single-instance `redis://<host>:<port>/<db>` URL — the GA default render is
byte-for-byte unchanged. The password is NEVER in this URL (it is a separate
NETOPS_REDIS_PASSWORD secretKeyRef env); the URL carries only non-secret
coordinates. Usage: {{ include "netops.redisUrl" . }}
*/}}
{{- define "netops.redisUrl" -}}
{{- $db := .Values.config.redis.db | default 0 -}}
{{- if .Values.redisSentinel.enabled -}}
{{- printf "sentinel://%s/%v" (include "netops.redisSentinelHosts" .) $db -}}
{{- else -}}
{{- printf "redis://%s:%v/%v" .Values.config.redis.host .Values.config.redis.port $db -}}
{{- end -}}
{{- end -}}

{{/*
netops.redisSentinelMaster — the Sentinel master_name the failover-aware client
passes in its transport options (W1-T4, ADR-0044 §1). Reads the live
redisSentinel value when the HA tier is on (the source of truth), else the
config coordinate. Usage: {{ include "netops.redisSentinelMaster" . }}
*/}}
{{- define "netops.redisSentinelMaster" -}}
{{- if .Values.redisSentinel.enabled -}}
{{- .Values.redisSentinel.sentinel.masterName -}}
{{- else -}}
{{- .Values.config.redis.sentinel.masterName -}}
{{- end -}}
{{- end -}}

{{/*
Whether THIS CHART renders the in-chart api/worker↔Postgres mTLS (W1-T2 / ADR-0039).
True ("true") only when mtls.postgres.enabled AND the CNPG HA tier is OFF: the
chart's mtls.postgres machinery (server cert + pg_hba + verify-full client config)
targets the in-chart `netops-postgres` StatefulSet. Under cloudNativePg.enabled
that StatefulSet is not rendered and the CloudNativePG OPERATOR owns the cluster's
TLS, so the in-chart mTLS is N/A and rendering it would (a) fail (external-PG
guard) or (b) point clients at a server this chart never wired. Empty string =
false. Usage: {{- if include "netops.pgMtlsEnabled" . }} ... {{- end }}
*/}}
{{- define "netops.pgMtlsEnabled" -}}
{{- if and .Values.mtls.postgres.enabled (not .Values.cloudNativePg.enabled) -}}
true
{{- end -}}
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
netops.dbClientTlsEnv — the api/worker in-cluster DB env (W4-T4 ADR-0039 §4 /
W1-T2 ADR-0042 §4). Authored ONCE so the api + worker cannot drift. Sets
NETOPS_DATABASE_URL to the in-cluster DSN (the app default DSN points at the
compose host, not the chart Service) and — when in-chart mTLS applies — the
NETOPS_DB_SSL_* settings (sslmode + the mounted cert/key/CA FILE paths) the
backend reads in app.db.build_ssl_connect_args. NO key material — only file paths
into the read-only Secret mount (ADR-0039 §5).

The DSN host is netops.postgresHost (the PgBouncer Pooler rw Service under the
CNPG HA tier, else the single-instance Service). The DSN is emitted whenever the
in-cluster DSN must override the compose default — i.e. when in-chart mTLS is on
OR when the CNPG tier is enabled (its Service name differs from the app default).
The SSL env is emitted ONLY when in-chart mTLS applies (netops.pgMtlsEnabled =
mtls on AND CNPG off): under CNPG the operator owns the cluster TLS and the app
reaches it through the Pooler, so no in-chart verify-full client config is wired
here (live CNPG↔app mTLS is W4-T1).
Usage: {{- include "netops.dbClientTlsEnv" . | nindent 12 }}
Renders nothing when mtls is off AND CNPG is off (the unchanged GA default).
*/}}
{{- define "netops.dbClientTlsEnv" -}}
{{- if or (include "netops.pgMtlsEnabled" .) .Values.cloudNativePg.enabled }}
# api/worker -> Postgres (ADR-0039 §4 / ADR-0042 §4). The DSN targets the
# in-cluster postgres host (the PgBouncer Pooler rw Service when the CNPG HA tier
# is enabled, else the single-instance Service). The password stays a separate
# secretKeyRef env.
- name: NETOPS_DATABASE_URL
  value: postgresql+asyncpg://{{ .Values.config.postgres.user }}:$(NETOPS_POSTGRES_PASSWORD)@{{ include "netops.postgresHost" . }}:{{ .Values.config.postgres.port }}/{{ .Values.config.postgres.database }}
{{- include "netops.dbClientTlsSslEnv" . }}
{{- end -}}
{{- end -}}

{{/*
netops.dbClientTlsSslEnv — JUST the NETOPS_DB_SSL_* client env (mode + mounted
cert/key/CA FILE paths), WITHOUT NETOPS_DATABASE_URL. The api/worker deployments
get the URL from netops.dbClientTlsEnv (K8s $(VAR) expansion); the audit /
credential CronJobs assemble their own DSN inside a `sh -c` script (L3) and only
need the SSL settings here so app.db.build_ssl_connect_args mounts the verify-full
SSLContext. Renders nothing when in-chart mTLS does not apply (mtls off, OR the
CNPG HA tier is enabled — the operator owns the cluster TLS then; ADR-0042 §4).
Usage: {{- include "netops.dbClientTlsSslEnv" . | nindent 16 }}
*/}}
{{- define "netops.dbClientTlsSslEnv" -}}
{{- $m := .Values.mtls.postgres -}}
{{- if include "netops.pgMtlsEnabled" . }}
- name: NETOPS_DB_SSL_MODE
  value: {{ $m.sslMode | quote }}
- name: NETOPS_DB_SSL_ROOT_CERT
  value: {{ printf "%s/%s" $m.mountPath ($m.caFile | default "ca.crt") | quote }}
# M1 (PR#76): the CLIENT cert/key paths derive from the CLIENT file-name settings
# (clientCertFile/clientKeyFile), NOT the server ones — the client mounts its own
# Secret, so customizing the server Secret key names must not break the client paths.
- name: NETOPS_DB_SSL_CERT
  value: {{ printf "%s/%s" $m.mountPath ($m.clientCertFile | default "tls.crt") | quote }}
- name: NETOPS_DB_SSL_KEY
  value: {{ printf "%s/%s" $m.mountPath ($m.clientKeyFile | default "tls.key") | quote }}
{{- end -}}
{{- end -}}

{{/*
netops.dbClientTlsVolumeMount — the read-only CLIENT cert mount for api/worker
(W4-T4, ADR-0039 §5). The client Secret (cert-manager-issued or dev-fallback)
mounted at mtls.postgres.mountPath. Usage:
  {{- include "netops.dbClientTlsVolumeMount" . | nindent 12 }}
*/}}
{{- define "netops.dbClientTlsVolumeMount" -}}
{{- if include "netops.pgMtlsEnabled" . }}
# api/worker -> Postgres mTLS client cert/key + CA, mounted read-only from the
# Secret (cert-manager-issued or dev-fallback). Never image-baked (ADR-0039 §5).
# Gated on netops.pgMtlsEnabled: under the CNPG HA tier the operator owns the
# cluster TLS and this in-chart client Secret is not rendered, so no dangling mount.
- name: db-tls-client
  mountPath: {{ .Values.mtls.postgres.mountPath }}
  readOnly: true
{{- end -}}
{{- end -}}

{{/*
netops.dbClientTlsVolume — the CLIENT cert Secret volume for api/worker
(W4-T4, ADR-0039 §5). defaultMode 0440: with fsGroup set (podSecurityContext
fsGroup == runAsGroup == 10001) K8s writes the Secret files owned root:10001, so
the key is OWNED BY ROOT and GROUP-READABLE by the pod's fsGroup — the non-root
app uid 10001 reads it via its gid, never world. 0400 (owner-only) would deny the
app group read and break the asyncpg verify-full client-chain load; this mirrors
the postgres server mount's 0640 group-read pattern (key non-world-readable).
Usage:
  {{- include "netops.dbClientTlsVolume" . | nindent 8 }}
*/}}
{{- define "netops.dbClientTlsVolume" -}}
{{- if include "netops.pgMtlsEnabled" . }}
- name: db-tls-client
  secret:
    secretName: {{ .Values.mtls.postgres.clientSecretName }}
    defaultMode: 0440
{{- end -}}
{{- end -}}
