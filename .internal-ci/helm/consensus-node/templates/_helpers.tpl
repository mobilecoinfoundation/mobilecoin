{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

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
  {{- $name := default .Chart.Name .Values.nameOverride }}
  {{- if contains $name .Release.Name }}
    {{- .Release.Name | trunc 63 | trimSuffix "-" }}
  {{- else }}
    {{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
  {{- end }}
{{- end }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "consensusNode.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
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

{{/* Define Secret and ConfigMap object names */}}
{{- define "consensusNode.nodeConfig.configMap.name" -}}
{{ include "consensusNode.fullname" . }}-consensus-node
{{- end }}

{{- define "consensusNode.ledgerDistribution.secret.name" -}}
{{ include "consensusNode.fullname" . }}-ledger-distribution
{{- end }}

{{- define "consensusNode.msgSignerKey.secret.name" -}}
{{ include "consensusNode.fullname" . }}-msg-signer-key
{{- end }}

{{- define "consensusNode.networkConfig.configMap.name" -}}
{{ include "consensusNode.fullname" . }}-network-config
{{- end }}

{{- define "consensusNode.tokensConfig.configMap.name" -}}
{{ include "consensusNode.fullname" . }}-tokens-config
{{- end }}

{{/*
peer and client hostnames - we need this for ingress.
lookup name from configmap if we have created the objects in consensus-node-config separately.
*/}}
{{- define "consensusNode.peerHostname" -}}
  {{- if eq .Values.consensusNodeConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace (include "consensusNode.nodeConfig.configMap.name" .)).data.PEER_HOSTNAME | default "" }}
  {{- else }}
    {{- tpl .Values.consensusNodeConfig.node.peer.hostname . }}
  {{- end }}
{{- end }}

{{- define "consensusNode.clientHostname" -}}
  {{- if eq .Values.consensusNodeConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace (include "consensusNode.nodeConfig.configMap.name" .)).data.CLIENT_HOSTNAME | default "" }}
  {{- else }}
    {{- tpl .Values.consensusNodeConfig.node.client.hostname . }}
  {{- end }}
{{- end }}

{{- define "consensusNode.blockVersion" -}}
  {{- if eq .Values.consensusNodeConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace (include "consensusNode.nodeConfig.configMap.name" .)).data.BLOCK_VERSION | default "false" }}
  {{- else }}
    {{- tpl .Values.global.node.nodeConfig.blockVersion . }}
  {{- end }}
{{- end }}

{{- define "consensusNode.txSourceUrl" -}}
  {{- if eq .Values.consensusNodeConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace (include "consensusNode.nodeConfig.configMap.name" .)).data.TX_SOURCE_URL | default "false" }}
  {{- else }}
    {{- tpl .Values.global.node.nodeConfig.txSourceUrl . }}
  {{- end }}
{{- end }}

{{/* Mobilecoin Network monitoring labels */}}
{{- define "consensusNode.mobileCoinNetwork.network" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace "mobilecoin-network").data.network | default "" }}
  {{- else }}
    {{- tpl .Values.mcCoreCommonConfig.mobileCoinNetwork.network . }}
  {{- end }}
{{- end }}

{{- define "consensusNode.mobileCoinNetwork.partner" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace "mobilecoin-network").data.partner | default "" }}
  {{- else }}
    {{- tpl .Values.mcCoreCommonConfig.mobileCoinNetwork.partner . }}
  {{- end }}
{{- end }}
