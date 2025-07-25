{{- define "fog-ledger-fsg.store" -}}
{{- $ledger := .Values.fogLedger }}
{{- $store := $ledger.store }}
- name: fog-ledger-store
  image: "{{ .Values.image.org }}/{{ .Values.image.name }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: Always
  args: [ "/usr/bin/key_image_store" ]
  ports:
  - name: grpc
    containerPort: {{ $ledger.ports.grpc }}
  livenessProbe:
    {{- $store.livenessProbe | toYaml | nindent 4 }}
  startupProbe:
    {{- $store.startupProbe | toYaml | nindent 4 }}
  readinessProbe:
    {{- $store.readinessProbe | toYaml | nindent 4 }}
  envFrom:
  - configMapRef:
      name: {{ include "fog-ledger-fsg.fullname" . }}-store
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
  # This is looking for the fqdn of the svc that is in front of the store.
  - name: MC_CLIENT_LISTEN_URI
    value: "insecure-key-image-store://0.0.0.0:{{ $ledger.ports.grpc }}/?responder-id=$(POD_NAME).{{ include "fog-ledger-fsg.fullname" . }}-store-headless.$(POD_NAMESPACE):{{ $ledger.ports.grpc }}/"
  - name: MC_CLIENT_RESPONDER_ID
    value: "$(POD_NAME).{{ include "fog-ledger-fsg.fullname" . }}-store-headless.$(POD_NAMESPACE):{{ $ledger.ports.grpc }}"
  - name: MC_ADMIN_LISTEN_URI
    value: insecure-mca://127.0.0.1:8001/
  - name: MC_MOBILECOIND_URI
    value: insecure-mobilecoind://mobilecoind:3229
  {{- if .Values.jaegerTracing.enabled }}
  - name: MC_TELEMETRY
    value: "true"
  - name: OTEL_SERVICE_NAME
    value: fog-ledger-store
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
    {{- toYaml $store.resources | nindent 4 }}
{{- end -}}
