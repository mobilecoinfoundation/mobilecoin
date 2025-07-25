# Fog-Ledger-Service

Run a MobileCoin fog-view instance.

### Required Values

You must set the fog view service hostnames and mobilecoin network and partner ids.

```yaml
mobilecoin:
  network: main
  partner: mc

fogLedger:
  responderID: fog.<namespace>.development.mobilecoin.com
  color: blue
```

Install chart:

```bash
helm upgrade fog-ledger-service oci://ghcr.io/mobilecoinfoundation/charts/fog-view-service -i -f values.yaml
```
