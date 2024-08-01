{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

{{/* Expand the name of the fogIngest. */}}
{{- define "fog-ingest.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fog-ingest.fullname" -}}
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

{{/* Create chart name and version as used by the chart label. */}}
{{- define "fog-ingest.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | trimSuffix "." }}
{{- end }}

{{/* Common labels */}}
{{- define "fog-ingest.labels" -}}
helm.sh/chart: {{ include "fog-ingest.chart" . }}
{{ include "fog-ingest.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "fog-ingest.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fog-ingest.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Generate fog-ingest Peers List */}}
{{- define "fog-ingest.peerURLs" }}
  {{- $peerURLs := list }}
  {{- $name := include "fog-ingest.fullname" . }}
  {{- $namespace := .Release.Namespace }}
  {{- range $i, $e := until (int .Values.fogIngest.replicaCount ) }}
    {{- $peerURLs = append $peerURLs (printf "insecure-igp://%s-%d.%s.%s.svc.cluster.local:8090" $name $i $name $namespace) }}
  {{- end }}
  {{- join "," $peerURLs }}
{{- end }}
