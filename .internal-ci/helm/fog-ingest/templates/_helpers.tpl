{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

{{/* Expand the name of the fogIngest. */}}
{{- define "fogIngest.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fogIngest.fullname" -}}
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
{{- define "fogIngest.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "fogIngest.labels" -}}
helm.sh/chart: {{ include "fogIngest.chart" . }}
{{ include "fogIngest.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "fogIngest.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fogIngest.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Generate fog-ingest Peers List */}}
{{- define "fogIngest.peerURLs" }}
  {{- $peerURLs := list }}
  {{- $name := include "fogIngest.fullname" . }}
  {{- $namespace := .Release.Namespace }}
  {{- range $i, $e := until (int .Values.fogIngest.replicaCount ) }}
    {{- $peerURLs = append $peerURLs (printf "insecure-igp://%s-%d.%s.%s.svc.cluster.local:8090" $name $i $name $namespace) }}
  {{- end }}
  {{- join "," $peerURLs }}
{{- end }}

{{/* Mobilecoin Network monitoring labels */}}
{{- define "fogIngest.mobileCoinNetwork.network" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace "mobilecoin-network").data.network | default "" }}
  {{- else }}
    {{- tpl .Values.mcCoreCommonConfig.mobileCoinNetwork.network . }}
  {{- end }}
{{- end }}

{{- define "fogIngest.mobileCoinNetwork.partner" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace "mobilecoin-network").data.partner | default "" }}
  {{- else }}
    {{- tpl .Values.mcCoreCommonConfig.mobileCoinNetwork.partner . }}
  {{- end }}
{{- end }}
