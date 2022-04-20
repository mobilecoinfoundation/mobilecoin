# fog-services Helm Chart

Rolling upgrades for view, report and ledger fog services.

```sh
helm upgrade fog-services ./ -i -n <namespace> \
  --set image.tag=prod-1.0.1-pre2
```
Note: generated PersistentVolumeClaims will stick around if the Helm Chart is removed or the pods are deleted and allowed to regenerate.

## Setup

Configure a `values.yaml` file or pre-populate your namespace with the following ConfigMaps and Secrets.


- `mobilecoin-network`

    Mobilecoin network value for monitoring: mainnet, testnet, alpha...

    ```yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: mobilecoin-network
    data:
      network: testnet
    ```

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

- `supervisord-mobilecoind`

    `mobilecoind` configuration for in container supervisord.  Example values are for MobileCoin MainNet.

    `mobilecoind` needs direct connections to each node. The `--peer` url must have `?responder-id=<loadbalancer-url>` query string if the peer is part of a load balanced set.

    Set `--peer` and `--tx-source-url` (associated public s3 bucket https:// url) per node that you want to watch.

    ```yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: supervisord-mobilecoind
    data:
      mobilecoind.conf: |
        [program:mobilecoind-sync]
        command=/usr/bin/mobilecoind
          --peer mc://node1.prod.mobilecoinww.com:443/
          --tx-source-url https://ledger.mobilecoinww.com/node1.prod.mobilecoinww.com
          --peer mc://node2.prod.mobilecoinww.com:443/
          --tx-source-url https://ledger.mobilecoinww.com/node2.prod.mobilecoinww.com
          --peer mc://node3.prod.mobilecoinww.com:443/
          --tx-source-url https://ledger.mobilecoinww.com/node3.prod.mobilecoinww.com
          --quorum-set '{ "threshold": 3, "members": [{"args":"node1.prod.mobilecoinww.com:443","type":"Node"},{"args":"node2.prod.mobilecoinww.com:443","type":"Node"},{"args":"node3.prod.mobilecoinww.com:443","type":"Node"}] }'
          --ledger-db /fog-data/ledger
          --watcher-db /fog-data/watcher
          --poll-interval 1

        stdout_logfile=/dev/fd/1
        stdout_logfile_maxbytes=0
        stderr_logfile=/dev/fd/2
        stderr_logfile_maxbytes=0
        autorestart=true
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

- `fog-client-auth-token` Secret
    
    Client auth token for Signal auth.

    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
    name: fog-client-auth-token
    type: Opaque
    stringData:
      token: long-token-value
    ```

- `fog-report-signing-cert` Secret

    Certificate chain and key for Fog reports

    ```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: fog-report-signing-cert
    type: kubernetes.io/tls
    stringData:
      tls.crt: |-
        <cert chain>
      tls.key: |-
        <cert key>
    ```

- `fog-public-fqdn` ConfigMap

    FQDN for the fog ingress

    ```yaml
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: fog-public-fqdn
    data:
      value: <fog.prod.mobilecoinww.com or something>
      # Since you can't put structured data in a config-map entry
      # String value, list of SANs one per line
      fogReportSANs: |-
        some.name.com
        some.other.com
    ```

- `fog-report` ConfigMap

    Database connection configuration for fog-report

    ```yaml
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: fog-report
    data:
      POSTGRES_IDLE_TIMEOUT: "60"
      POSTGRES_MAX_LIFETIME: "120"
      POSTGRES_CONNECTION_TIMEOUT: "5"
      POSTGRES_MAX_CONNECTIONS: "3"
    ```

- `fog-view` ConfigMap

    Database connection configuration for fog-view

    ```yaml
    kind: ConfigMap
    apiVersion: v1
    metadata:
      name: fog-view
    data:
      POSTGRES_IDLE_TIMEOUT: "60"
      POSTGRES_MAX_LIFETIME: "120"
      POSTGRES_CONNECTION_TIMEOUT: "5"
      POSTGRES_MAX_CONNECTIONS: "3"
    ```
