{{/* Copyright (c) 2018-2024 The MobileCoin Foundation */}}

{{/* Expand the name of the consensusNode. */}}
{{- define "consensusNode.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "consensusNode.fullname" -}}
{{- if .Values.fullnameOverride }}
  {{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
  {{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "consensusNode.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | trimSuffix "." }}
{{- end }}

{{/* Common labels */}}
{{- define "consensusNode.labels" -}}
helm.sh/chart: {{ include "consensusNode.chart" . }}
{{ include "consensusNode.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "consensusNode.selectorLabels" -}}
app.kubernetes.io/name: {{ include "consensusNode.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Find the instance number of the consensus deploy (1, 2, 3...) */}}
{{- define "consensusNode.instanceNumber" -}}
  {{- if (regexMatch ".*-[0-9]+$" (include "consensusNode.fullname" .)) }}
{{- regexFind "[0-9]+" (include "consensusNode.fullname" .) }}
  {{- else }}
0
  {{- end }}
{{- end }}

{{- define "consensusNode.rateLimitPeriod" -}}
{{ add 60000 (include "consensusNode.instanceNumber" .) }}
{{- end }}
