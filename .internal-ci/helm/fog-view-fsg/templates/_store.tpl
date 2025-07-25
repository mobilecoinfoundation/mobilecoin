{{- define "fog-view-fsg.store" -}}
{{- $view := .Values.fogView }}
{{- $store := $view.store }}
- name: fog-view-store
  image: "{{ .Values.image.org }}/{{ .Values.image.name }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: Always
  args: [ "/usr/bin/fog_view_server" ]
  ports:
  - name: grpc
    containerPort: {{ $view.ports.grpc }}
  livenessProbe:
    {{- $store.livenessProbe | toYaml | nindent 4 }}
  startupProbe:
    {{- $store.startupProbe | toYaml | nindent 4 }}
  readinessProbe:
    {{- $store.readinessProbe | toYaml | nindent 4 }}
  envFrom:
  - configMapRef:
      name: {{ include "fog-view-fsg.fullname" . }}-store
  env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
  - name: RUST_BACKTRACE
    value: {{ $store.rust.backtrace | quote }}
  - name: RUST_LOG
    value: {{ $store.rust.log | quote }}
  - name: MC_CHAIN_ID
    value: {{ .Values.mobilecoin.network }}
  - name: MC_ADMIN_LISTEN_URI
    value: insecure-mca://127.0.0.1:8001/
  # This is looking for the fqdn of the svc that is in front of the store.
  - name: MC_CLIENT_LISTEN_URI
    value: "insecure-fog-view-store://0.0.0.0:{{ $view.ports.grpc }}/?responder-id=$(POD_NAME).{{ include "fog-view-fsg.fullname" . }}-store-headless.$(POD_NAMESPACE):{{ $view.ports.grpc }}/"
  - name: MC_CLIENT_RESPONDER_ID
    value: "$(POD_NAME).{{ include "fog-view-fsg.fullname" . }}-store-headless.$(POD_NAMESPACE):{{ $view.ports.grpc }}"
  - name: FOGDB_HOST
    valueFrom:
      configMapKeyRef:
        name: {{ $view.externalConfigMaps.postgresReader.name }}
        key: postgres-hostname
  - name: FOGDB_USER
    valueFrom:
      configMapKeyRef:
        name: {{ $view.externalConfigMaps.postgresReader.name }}
        key: postgres-username
  - name: FOGDB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: {{ $view.externalSecrets.postgresReader.name }}
        key: postgres-password
  - name: FOGDB_DATABASE
    valueFrom:
      configMapKeyRef:
        name: {{ $view.externalConfigMaps.postgresReader.name }}
        key: postgres-database
  - name: FOGDB_SSL_OPTIONS
    valueFrom:
      configMapKeyRef:
        name: {{ $view.externalConfigMaps.postgresReader.name }}
        key: postgres-ssl-options
  - name: DATABASE_URL
    value: "postgres://$(FOGDB_USER):$(FOGDB_PASSWORD)@$(FOGDB_HOST)/$(FOGDB_DATABASE)$(FOGDB_SSL_OPTIONS)"
  {{- if .Values.jaegerTracing.enabled }}
  - name: MC_TELEMETRY
    value: "true"
  - name: OTEL_SERVICE_NAME
    value: fog-view-store
  - name: OTEL_RESOURCE_ATTRIBUTES
    value: "deployment.environment={{ .Values.mobilecoin.partner }},deployment.chain_id={{ .Values.mobilecoin.network }}"
  - name: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    value: http://otel-collector.otel:4317
  {{- end }}
  - name: MC_SENTRY_DSN
    valueFrom:
      configMapKeyRef:
        name: sentry
        key: fog-view-sentry-dsn
        optional: true
  # Maps to Sentry Environment
  - name: MC_BRANCH
    value: {{ .Values.mobilecoin.network }}
  resources:
    {{- toYaml $store.resources | nindent 4 }}
{{- end -}}
