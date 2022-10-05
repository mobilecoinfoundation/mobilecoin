{{/* Copyright (c) 2018-2022 The MobileCoin Foundation */}}

{{/* Expand the name of the fogServices. */}}
{{- define "fogServices.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "fogServices.fullname" -}}
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
{{- define "fogServices.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "fogServices.labels" -}}
helm.sh/chart: {{ include "fogServices.chart" . }}
{{ include "fogServices.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "fogServices.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fogServices.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Fog Public FQDN */}}
{{- define "fogServices.fogPublicFQDN" -}}
{{- $domainname := "" }}
{{- if .Values.fogServicesConfig.fogPublicFQDN.domainname }}
{{- $domainname = .Values.fogServicesConfig.fogPublicFQDN.domainname }}
{{- end }}
{{- $publicFQDNConfig := lookup "v1" "ConfigMap" .Release.Namespace "fog-public-fqdn" }}
{{- if $publicFQDNConfig }}
{{- $domainname = index $publicFQDNConfig.data "domainname" }}
{{- end }}
{{- $domainname }}
{{- end }}

{{/* FogReport Hosts (fogPublicFQDN + fogReportSANs) */}}
{{- define "fogServices.fogReportHosts" -}}
{{- $reportHosts := list }}
{{- if .Values.fogServicesConfig.fogPublicFQDN.fogReportSANs }}
{{- $reportHosts = split "\n" (.Values.fogServicesConfig.fogPublicFQDN.fogReportSANs) }}
{{- end }}
{{- $fogReportSansConfig := lookup "v1" "ConfigMap" .Release.Namespace "fog-public-fqdn" }}
{{- if $fogReportSansConfig }}
{{- $reportHosts = split "\n" (index $fogReportSansConfig.data "fogReportSANs") }}
{{- end }}
{{ include "fogServices.fogPublicFQDN" . }}
{{- range $reportHosts }}
{{ . }}
{{- end }}
{{- end }}

{{- define "fogServices.clientAuth" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "Secret" .Release.Namespace "client-auth-token").data.token | default "" | b64dec }}
  {{- else }}
    {{- .Values.mcCoreCommonConfig.clientAuth.token | default ""}}
  {{- end }}
{{- end }}

{{/* Mobilecoin Network monitoring labels */}}
{{- define "fogServices.mobileCoinNetwork.network" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace "mobilecoin-network").data.network | default "" }}
  {{- else }}
    {{- tpl .Values.mcCoreCommonConfig.mobileCoinNetwork.network . }}
  {{- end }}
{{- end }}

{{- define "fogServices.mobileCoinNetwork.partner" -}}
  {{- if eq .Values.mcCoreCommonConfig.enabled false }}
    {{- (lookup "v1" "ConfigMap" .Release.Namespace "mobilecoin-network").data.partner | default "" }}
  {{- else }}
    {{- tpl .Values.mcCoreCommonConfig.mobileCoinNetwork.partner . }}
  {{- end }}
{{- end }}

{{/* fogViewGRPCCookieSalt - reuse existing password */}}
{{- define "fogServices.fogViewGRPCCookieSalt" -}}
{{- $salt := randAlphaNum 8 }}
{{- if .Values.fogServicesConfig.fogView.grpc.cookie.salt }}
{{- $salt = .Values.fogServicesConfig.fogView.grpc.cookie.salt }}
{{- end }}
{{- $saltSecret := (lookup "v1" "Secret" .Release.Namespace "fog-view-grpc-cookie") }}
{{- if $saltSecret }}
{{- $salt = index $saltSecret.data "salt" | b64dec }}
{{- end }}
{{- $salt }}
{{- end }}

{{/* fogViewHTTPCookieSalt - reuse existing password */}}
{{- define "fogServices.fogViewHTTPCookieSalt" -}}
{{- $salt := randAlphaNum 8 }}
{{- if .Values.fogServicesConfig.fogView.http.cookie.salt }}
{{- $salt = .Values.fogServicesConfig.fogView.http.cookie.salt }}
{{- end }}
{{- $saltSecret := (lookup "v1" "Secret" .Release.Namespace "fog-view-http-cookie") }}
{{- if $saltSecret }}
{{- $salt = index $saltSecret.data "salt" | b64dec }}
{{- end }}
{{- $salt }}
{{- end }}


{{/* fogLedgerGRPCCookieSalt - reuse existing password */}}
{{- define "fogServices.fogLedgerGRPCCookieSalt" -}}
{{- $salt := randAlphaNum 8 }}
{{- if .Values.fogServicesConfig.fogLedger.grpc.cookie.salt }}
{{- $salt = .Values.fogServicesConfig.fogLedger.grpc.cookie.salt }}
{{- end }}
{{- $saltSecret := (lookup "v1" "Secret" .Release.Namespace "fog-ledger-grpc-cookie") }}
{{- if $saltSecret }}
{{- $salt = index $saltSecret.data "salt" | b64dec }}
{{- end }}
{{- $salt }}
{{- end }}

{{/* fogLedgerHTTPCookieSalt - reuse existing password */}}
{{- define "fogServices.fogLedgerHTTPCookieSalt" -}}
{{- $salt := randAlphaNum 8 }}
{{- if .Values.fogServicesConfig.fogLedger.http.cookie.salt }}
{{- $salt = .Values.fogServicesConfig.fogLedger.http.cookie.salt }}
{{- end }}
{{- $saltSecret := (lookup "v1" "Secret" .Release.Namespace "fog-ledger-http-cookie") }}
{{- if $saltSecret }}
{{- $salt = index $saltSecret.data "salt" | b64dec }}
{{- end }}
{{- $salt }}
{{- end }}
