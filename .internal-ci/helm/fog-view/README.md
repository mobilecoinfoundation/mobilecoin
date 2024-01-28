# Fog-View

Run a MobileCoin fog-view instance.

### Required Values

You must set the fog view service hostnames and mobilecoin network and partner ids.

```yaml
mobilecoin:
  network: main
  partner: mc

fogView:
  router:
    hosts:
    # add more instances here to generate additional routers
    - partner: mc
      responderID: fog.prod.mobilecoinww.com
```

Install chart:

```bash
helm upgrade fog-view mcf-public/fog-view -i -f values.yaml
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

IAS example

```yaml
apiVersion: v1
metadata:
  name: ias
kind: Secret
type: Opaque
stringData:
  MC_IAS_API_KEY
  MC_IAS_SPID
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
