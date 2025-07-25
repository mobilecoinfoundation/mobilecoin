{{/*
Expand the name of the chart.
*/}}
{{- define "fog-ledger-fsg.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fog-ledger-fsg.fullname" -}}
{{- if .Values.fullnameOverride }}
  {{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
  {{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "fog-ledger-fsg.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | trimSuffix "." }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "fog-ledger-fsg.labels" -}}
helm.sh/chart: {{ include "fog-ledger-fsg.chart" . }}
{{ include "fog-ledger-fsg.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "fog-ledger-fsg.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fog-ledger-fsg.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{/* stackConfig - get "network" name of fall back to default */}}
{{- define "fog-ledger-fsg.stackConfig" }}
{{- $networkName := .Values.mobilecoin.network }}
{{- get .Values.fogLedger.stackConfig.network $networkName | default (get .Values.fogLedger.stackConfig.network "default") | toYaml }}
{{- end }}
