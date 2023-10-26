{{/*
Expand the name of the chart.
*/}}
{{- define "fog-view.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fog-view.fullname" -}}
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
{{- define "fog-view.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | trimSuffix "." }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "fog-view.labels" -}}
helm.sh/chart: {{ include "fog-view.chart" . }}
{{ include "fog-view.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "fog-view.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fog-view.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* grpcCookieSalt */}}
{{- define "fog-view.grpcCookieSalt" -}}
{{- randAlphaNum 8 }}
{{- end }}

{{/* shardRangeGenerator - get "network" name of fall back to default */}}
{{- define "fog-view.stackConfig" }}
{{- $networkName := .Values.mobilecoin.network }}
{{- get .Values.fogView.stackConfig.network $networkName | default (get .Values.fogView.stackConfig.network "default") | toYaml }}
{{- end }}
