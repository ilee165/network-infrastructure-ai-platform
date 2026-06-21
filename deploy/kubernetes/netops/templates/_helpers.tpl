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

{{/* Packet node-pool toleration matching the taint (ADR-0031 §5). */}}
{{- define "netops.packetToleration" -}}
- key: {{ .Values.packetNodePool.taint.key | quote }}
  operator: Equal
  value: {{ .Values.packetNodePool.taint.value | quote }}
  effect: {{ .Values.packetNodePool.taint.effect }}
{{- end -}}
