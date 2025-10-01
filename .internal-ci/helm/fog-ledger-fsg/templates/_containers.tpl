{{- define "containers.sysctl" -}}
- name: sysctl
  image: ubuntu:20.04
  command:
  - sysctl
  - -w
  - net.ipv4.tcp_retries2=5
  - net.core.somaxconn=65535
  securityContext:
    privileged: true
    runAsUser: 0
    runAsNonRoot: False
    readOnlyRootFilesystem: true
{{- end -}}

{{- define "containers.admin-http-gateway" -}}
- name: admin-http-gateway
  image: "{{ .Values.image.org }}/{{ .Values.image.name }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: Always
  args:
  - /usr/bin/mc-admin-http-gateway
  - --listen-host=0.0.0.0
  - --listen-port={{ .Values.fogLedger.ports.mgmt }}
  - --admin-uri=insecure-mca://127.0.0.1:8001/
  ports:
  - name: mgmt
    containerPort: {{ .Values.fogLedger.ports.mgmt }}
  resources:
    requests:
      cpu: 256m
      memory: 256Mi
  # securityContext:
  #   runAsUser: 1000
  #   runAsGroup: 1000
  #   runAsNonRoot: true
  #   capabilities:
  #     drop:
  #     - ALL
  #   readOnlyRootFilesystem: true
{{- end -}}

{{- define "containers.go-grpc-gateway" -}}
- name: grpc-gateway
  image: "{{ .Values.image.org }}/go-grpc-gateway:{{ .Values.image.tag | default .Chart.AppVersion }}"
  imagePullPolicy: Always
  command:
  - /usr/bin/go-grpc-gateway
  - -grpc-server-endpoint=127.0.0.1:{{ .Values.fogLedger.ports.grpc }}
  - -grpc-insecure
  - -http-server-listen=:{{ .Values.fogLedger.ports.http }}
  - -logtostderr
  ports:
  - name: http
    containerPort: {{ .Values.fogLedger.ports.http }}
  resources:
    requests:
      cpu: 256m
      memory: 256Mi
{{- end -}}
