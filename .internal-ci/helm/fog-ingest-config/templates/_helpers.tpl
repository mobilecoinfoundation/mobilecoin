{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

{{/* Expand the name of the fogIngestConfig. */}}
{{- define "fogIngestConfig.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fogIngestConfig.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- tpl .Values.fullnameOverride . | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "fogIngestConfig.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | trimSuffix "." }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "fogIngestConfig.labels" -}}
helm.sh/chart: {{ include "fogIngestConfig.chart" . }}
{{ include "fogIngestConfig.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "fogIngestConfig.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fogIngestConfig.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* pgPassword - reuse existing password */}}
{{- define "fogIngestConfig.pgPassword" -}}
{{- $pgPassword := randAlphaNum 48 }}
{{- if .Values.fogRecoveryDatabase.password }}
{{- $pgPassword = .Values.fogRecoveryDatabase.password }}
{{- end }}
{{- $pgSecret := (lookup "v1" "Secret" .Release.Namespace "fog-recovery-postgresql") }}
{{- if $pgSecret }}
{{- $pgPassword = index $pgSecret.data "postgres-password" | b64dec }}
{{- end }}
{{- $pgPassword }}
{{- end }}

{{/* pgPassword - reuse existing password */}}
{{- define "fogIngestConfig.pgReplicationPassword" -}}
{{- $pgReplicationPassword := randAlphaNum 48 }}
{{- $pgSecret := (lookup "v1" "Secret" .Release.Namespace "fog-recovery-postgresql") }}
{{- if $pgSecret }}
{{- $pgReplicationPassword = index $pgSecret.data "replication-password" | b64dec }}
{{- end }}
{{- $pgReplicationPassword }}
{{- end }}
