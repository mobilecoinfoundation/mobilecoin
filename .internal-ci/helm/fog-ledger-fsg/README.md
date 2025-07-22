# Fog-Ledger-FSG

Run a MobileCoin fog-ledger fogShardGenerator chart

### Required Values

You must set the fog view service hostnames and mobilecoin network and partner ids.

```yaml
mobilecoin:
  network: main
  partner: mc

fogLedger:
  color: (blue|green)
  zone: <azure region + AZ number>
  responderID: fog.prod.mobilecoinww.com
```

Install chart:

```bash
helm upgrade fog-ledger-fsg-blue-z1 oci://ghcr.io/mobilecoinfoundation/charts/fog-ledger-fsg -i -f values.yaml
```

### Optional ConfigMaps

sentry:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sentry
data:
  fog-ledger-sentry-dsn: <sentry dsn>
```
