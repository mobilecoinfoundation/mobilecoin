# Fog-Report

Run a MobileCoin fog-report instance.

### Required Values

You must set the fog report service hostnames and mobilecoin network and partner ids.

```yaml
mobilecoin:
  network: main
  partner: mc

fogReport:
  hosts:
  - fog.prod.mobilecoinww.com
```

### Launching multiple fog-report instances

Create 2 fog-report-signing-cert secrets Use the `fogReport.externalSecrets.signingCert.name` value to override the name for each instance that you launch.

**Instance A**

Create `fog-report-signing-cert-a` secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fog-report-signing-cert-a
type: kubernetes.io/tls
stringData:
  tls.crt: |-
    <certificate pem>
  tls.key: |-
    <key pem>
```

`fog-report-signing-cert-a` values.yaml

```yaml
mobilecoin:
  network: main
  partner: mc

fogReport:
  hosts:
  - fog.prod.example-a.com
  externalSecrets:
    signingCert:
      name: fog-report-signing-cert-a
```

Install chart with name override:

```bash
helm upgrade fog-report-a mco-public/fog-report -i -f values.yaml
```

**Instance B**

Create `fog-report-signing-cert-b` secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fog-report-signing-cert-b
type: kubernetes.io/tls
stringData:
  tls.crt: |-
    <certificate pem>
  tls.key: |-
    <key pem>
```

`fog-report-signing-cert-b` values.yaml

```yaml
mobilecoin:
  network: main
  partner: mc

fogReport:
  hosts:
  - fog.prod.example-b.com
  externalSecrets:
    signingCert:
      name: fog-report-signing-cert-b
```

Install chart with name override:

```bash
helm upgrade fog-report-b mco-public/fog-report -i -f values.yaml
```

### Required ConfigMaps

postgresReader example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fog-recovery-reader-0-postgresql
data:
  postgresql-database: recovery
  postgresql-hostname: <hostname>
  postgresql-port: "5432"
  postgresql-ssl-options: "?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt"
  postgresql-username: <user>
```

### Required Secrets

postgresReader example:

```yaml
apiVersion: v1
metadata:
  name: fog-recovery-reader-0-postgresql
kind: Secret
type: Opaque
stringData:
  postgresql-password: <password>
```

signingCert example:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fog-report-signing-cert
type: kubernetes.io/tls
stringData:
  tls.crt: |-
    <certificate pem>
  tls.key: |-
    <key pem>
```

### Optional ConfigMaps

sentry:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sentry
data:
  fog-report-sentry-dsn: <sentry dsn>
```
