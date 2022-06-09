{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

{{/*
Expand the name of the consensusNodeConfig.
*/}}
{{- define "consensusNodeConfig.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "consensusNodeConfig.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "consensusNodeConfig.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "consensusNodeConfig.labels" -}}
helm.sh/chart: {{ include "consensusNodeConfig.chart" . }}
{{ include "consensusNodeConfig.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "consensusNodeConfig.selectorLabels" -}}
app.kubernetes.io/name: {{ include "consensusNodeConfig.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Figure out our node id from the name or use values clientHostname/peerHostname */}}

{{/* clientHostname */}}
{{- define "consensusNodeConfig.clientHostname" -}}
{{- tpl .Values.node.client.hostname . }}
{{- end }}

{{/* peerHostname */}}
{{- define "consensusNodeConfig.peerHostname" -}}
{{- tpl .Values.node.peer.hostname . }}
{{- end }}

{{/* TX_SOURCE_URL */}}
{{- define "consensusNodeConfig.txSourceUrl" -}}
{{- tpl .Values.node.txSourceUrl . }}
{{- end }}

{{/* ledgerDistributionAWSPath */}}
{{- define "consensusNodeConfig.ledgerDistributionAWSPath" -}}
{{ printf "s3://%s/%s?region=%s" .Values.global.node.ledgerDistribution.s3Bucket (include "consensusNodeConfig.clientHostname" .) .Values.global.node.ledgerDistribution.awsRegion }}
{{- end }}
