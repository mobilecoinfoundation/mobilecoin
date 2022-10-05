{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

{{/*
Expand the name of the chart.
*/}}
{{- define "chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "chart.fullname" -}}
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
{{- define "chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "chart.labels" -}}
helm.sh/chart: {{ include "chart.chart" . }}
{{ include "chart.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
IAS Secret Name
*/}}
{{- define "chart.iasSecretName" -}}
  {{- if .Values.ias.secret.external }}
    {{- .Values.ias.secret.name }}
  {{- else }}
    {{- include "chart.fullname" . }}-{{ .Values.ias.secret.name }}
  {{- end }}
{{- end }}

{{/*
Sentry ConfigMap Name
*/}}
{{- define "chart.sentryConfigMapName" -}}
  {{- if .Values.sentry.configMap.external }}
    {{- .Values.sentry.configMap.name }}
  {{- else }}
    {{- include "chart.fullname" . }}-{{ .Values.sentry.configMap.name }}
  {{- end }}
{{- end }}

{{/*
supervisord-mobilecoind ConfigMap Name
*/}}
{{- define "chart.mobilecoindConfigMapName" -}}
  {{- if .Values.mobilecoind.configMap.external }}
    {{- .Values.mobilecoind.configMap.name }}
  {{- else }}
    {{- include "chart.fullname" . }}-{{ .Values.mobilecoind.configMap.name }}
  {{- end }}
{{- end }}
