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
