# fog-ingest Helm Chart

Use in a blue/green type of deployment

```sh
helm upgrade fog-ingest-blue ./ -i -n <namespace> \
  --set image.tag=prod-1.0.1-pre2
```

```sh
helm upgrade fog-ingest-green ./ -i -n <namespace> \
  --set image.tag=prod-1.0.1-pre2
```

Note: generated PersistentVolumeClaims will stick around if the Helm Chart is removed or the pods are deleted and allowed to regenerate.

## Scaling

`fog-ingest` is only designed to have one active instance. We should run at-least 2 in order to have a hot standby incase the active instance fails. Scaling the replicas doesn't improve performance.

The peer list generation happens when the chart is generated.  In order to scale the fog-ingest service you should adjust the `fogIngest.replicaCount` value and upgrade the fogIngest.  The peer list is added to the ConfigMap additional pods will be added, but existing pods will not automatically update.  Either destroy and re-create the pods or execute a restart of the fog services with supervisord.

## Setup

Configure a `values.yaml` file or pre-populate your namespace with the following ConfigMaps and Secrets.

- `ias`

    Intel spid and primary or secondary key.
    
    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: ias
    type: Opaque
    stringData:
      key: <primary or secondary key>
      spid: <spid>
    ```

- `sentry`

    Sentry service alert and error monitoring

    ```yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: sentry
    data:
      fog-ingest-sentry-dsn: <dsn-url>
      fog-view-sentry-dsn: <dsn-url>
      fog-ledger-sentry-dsn: <dsn-url>
      fog-report-sentry-dsn: <dsn-url>
      ledger-distribution-sentry-dsn: <dsn-url>
    ```

- `fog-recovery-postgresql` ConfigMap

    If you're using an cluster external database, populate the ConfigMap and Secret with the connection values.

    These example setting work with the helm postgresql chart when launched in the local namespace.

    ```sh
    helm install fog-recovery bitnami/postgresql -n <namespace> \
      --set postgresqlDatabase=recovery
    ```

    ```yaml
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: fog-recovery-postgresql
    data:
      postgresql-database: recovery
      postgresql-hostname: fog-recovery-postgresql
      postgresql-port: "5432"
      postgresql-ssl-options: "?sslmode=disable" # Set as appropriate
      postgresql-username: postgres
    ```


- `fog-recovery-postgresql` Secret

    If you're using an cluster external database, populate the ConfigMap and Secret with the connection values.

    If you're using the postgresql helm chart launched as follows, this secret will be populated for you.

    ```sh
    helm install fog-recovery bitnami/postgresql -n <namespace> \
      --set postgresqlDatabase=recovery
    ```

    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: fog-recovery-postgresql
    type: Opaque
    stringData:
      postgresql-password: really-good-password
    ```

- `fog-ingest` ConfigMap

    Database connection configuration for fog-ingest

    ```yaml
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: fog-ingest
    data:
      POSTGRES_IDLE_TIMEOUT: "60"
      POSTGRES_MAX_LIFETIME: "120"
      POSTGRES_CONNECTION_TIMEOUT: "5"
      POSTGRES_MAX_CONNECTIONS: "3"
    ```
