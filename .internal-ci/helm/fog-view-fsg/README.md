# Fog-View-FSG

Run a MobileCoin fog-view fogShardGenerator chart

### Required Values

You must set the fog view service hostnames and mobilecoin network and partner ids.

```yaml
mobilecoin:
  network: main
  partner: mc

fogView:
  color: (blue|green)
  zone: <azure region + AZ number>
  responderID: fog.prod.mobilecoinww.com
```

Install chart:

```bash
helm upgrade fog-view-fsg-blue-z1 mcf-public/fog-view-fsg -i -f values.yaml
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
