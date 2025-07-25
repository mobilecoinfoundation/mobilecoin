{{- define "fog-view-fsg.router" -}}
{{- $view := .Values.fogView }}
{{- $router := $view.router }}
- name: fog-view-router
  image: "{{ .Values.image.org }}/{{ .Values.image.name }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: Always
  args: [ "/usr/bin/fog_view_router" ]
  ports:
  - name: grpc
    containerPort: {{ $view.ports.grpc }}
  startupProbe:
    {{- $router.startupProbe | toYaml | nindent 4 }}
  livenessProbe:
    {{- $router.livenessProbe | toYaml | nindent 4 }}
  readinessProbe:
    {{- $router.readinessProbe | toYaml | nindent 4 }}
  envFrom:
  - configMapRef:
      name: {{ include "fog-view-fsg.fullname" . }}-router
  env:
  - name: RUST_BACKTRACE
    value: {{ $router.rust.backtrace | quote }}
  - name: RUST_LOG
    value: {{ $router.rust.log | quote }}
  - name: MC_CLIENT_RESPONDER_ID
    value: {{ $view.responderID }}:443
  - name: MC_CHAIN_ID
    value: {{ .Values.mobilecoin.network }}
  - name: MC_CLIENT_LISTEN_URI
    value: insecure-fog-view://0.0.0.0:{{ $view.ports.grpc }}/
  - name: MC_ADMIN_LISTEN_URI
    value: insecure-mca://127.0.0.1:8001/
  {{- if eq .Values.jaegerTracing.enabled true }}
  - name: MC_TELEMETRY
    value: "true"
  - name: OTEL_SERVICE_NAME
    value: fog-view-router
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
    {{- toYaml $router.resources | nindent 4 }}
{{- end -}}
