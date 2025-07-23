{{- define "fog-ledger-fsg.router" -}}
{{- $ledger := .Values.fogLedger }}
{{- $router := $ledger.router }}
- name: fog-ledger-router
  image: "{{ .Values.image.org }}/{{ .Values.image.name }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: Always
  args: [ "/usr/bin/ledger_router" ]
  ports:
  - name: grpc
    containerPort: {{ $ledger.ports.grpc }}
  startupProbe:
    {{- $router.startupProbe | toYaml | nindent 4 }}
  livenessProbe:
    {{- $router.livenessProbe | toYaml | nindent 4 }}
  readinessProbe:
    {{- $router.readinessProbe | toYaml | nindent 4 }}
  envFrom:
  - configMapRef:
      name: {{ include "fog-ledger-fsg.fullname" . }}-router
  env:
  - name: RUST_BACKTRACE
    value: {{ $router.rust.backtrace | quote }}
  - name: RUST_LOG
    value: {{ $router.rust.log | quote }}
  - name: MC_CLIENT_RESPONDER_ID
    value: {{ $ledger.responderID }}:443
  - name: MC_CHAIN_ID
    value: {{ .Values.mobilecoin.network }}
  - name: MC_CLIENT_LISTEN_URI
    value: insecure-fog-ledger://0.0.0.0:{{ $ledger.ports.grpc }}/
  - name: MC_ADMIN_LISTEN_URI
    value: insecure-mca://127.0.0.1:8001/
  - name: MC_MOBILECOIND_URI
    value: insecure-mobilecoind://mobilecoind:3229
  {{- if eq .Values.jaegerTracing.enabled true }}
  - name: MC_TELEMETRY
    value: "true"
  - name: OTEL_SERVICE_NAME
    value: fog-ledger-router
  - name: OTEL_RESOURCE_ATTRIBUTES
    value: "deployment.environment={{ .Values.mobilecoin.partner }},deployment.chain_id={{ .Values.mobilecoin.network }}"
  - name: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    value: http://otel-collector.otel:4317
  {{- end }}
  - name: MC_SENTRY_DSN
    valueFrom:
      configMapKeyRef:
        name: sentry
        key: fog-ledger-sentry-dsn
        optional: true
  # Maps to Sentry Environment
  - name: MC_BRANCH
    value: {{ .Values.mobilecoin.network }}
  resources:
    {{- toYaml $router.resources | nindent 4 }}
{{- end -}}
