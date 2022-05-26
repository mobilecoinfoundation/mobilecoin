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
Mobilecoin Network (monitoring label)
*/}}
{{- define "chart.mobileCoinNetwork.network" -}}
  {{- if .Values.mobileCoinNetwork.configMap.external }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace .Values.mobileCoinNetwork.configMap.name).data.network | default "" }}
  {{- else }}
    {{- .Values.mobileCoinNetwork.network }}
  {{- end }}
{{- end }}

{{/*
Mobilecoin Network Partner (monitoring label)
*/}}
{{- define "chart.mobileCoinNetwork.partner" -}}
  {{- if .Values.mobileCoinNetwork.configMap.external }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace .Values.mobileCoinNetwork.configMap.name).data.partner | default "" }}
  {{- else }}
    {{- .Values.mobileCoinNetwork.partner }}
  {{- end }}
{{- end }}
