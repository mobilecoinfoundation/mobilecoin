{{/* Copyright (c) 2018-2023 The MobileCoin Foundation */}}

{{/* Expand the name of the Chart. */}}
{{- define "mobilecoind.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mobilecoind.fullname" -}}
{{- if .Values.fullnameOverride }}
  {{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
  {{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "mobilecoind.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | trimSuffix "." }}
{{- end }}

{{/* Common labels */}}
{{- define "mobilecoind.labels" -}}
helm.sh/chart: {{ include "mobilecoind.chart" . }}
{{ include "mobilecoind.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "mobilecoind.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mobilecoind.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
