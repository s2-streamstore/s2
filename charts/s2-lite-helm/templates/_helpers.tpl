{{/*
Expand the name of the chart.
*/}}
{{- define "s2-lite.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "s2-lite.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "s2-lite.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "s2-lite.labels" -}}
helm.sh/chart: {{ include "s2-lite.chart" . }}
{{ include "s2-lite.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "s2-lite.selectorLabels" -}}
app.kubernetes.io/name: {{ include "s2-lite.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "s2-lite.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "s2-lite.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "s2-lite.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
WAL storage mode: "bucket", "volume", or "" when the WAL shares the main bucket.
Validates the walStorage values.
*/}}
{{- define "s2-lite.walStorage.mode" -}}
{{- $bucket := .Values.walStorage.bucket }}
{{- $volume := .Values.walStorage.persistentVolume.enabled }}
{{- if and $bucket $volume }}
{{- fail "walStorage.bucket and walStorage.persistentVolume.enabled are mutually exclusive" }}
{{- end }}
{{- if and (or $bucket $volume) (not .Values.objectStorage.enabled) }}
{{- fail "walStorage requires objectStorage.enabled" }}
{{- end }}
{{- if $bucket }}bucket{{- else if $volume }}volume{{- end }}
{{- end }}

{{/*
Name of the WAL PersistentVolumeClaim
*/}}
{{- define "s2-lite.walStorage.claimName" -}}
{{- default (printf "%s-wal" (include "s2-lite.fullname" .)) .Values.walStorage.persistentVolume.existingClaim }}
{{- end }}
