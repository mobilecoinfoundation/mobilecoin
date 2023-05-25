# fog-test-client

## Requirements

- op (1Password cli)
- jq
- kubectl
- helm

## Setup

This assumes that all the fog-test-client instances will be installed on the same cluster in different namespaces.

1. Run `scripts/setup.sh`

    This will pull down the account keys and secrets from 1password and generate the kubernetes objects needed for the deployment. The files will be in `/tmp/nets`

1. Run `scripts/apply-k8s.sh`

    This will apply the generated kubernetes objects in `/tmp/nets` for their networks into an isolated namespace.

## Deployment

### For MC networks

```bash
helm -n ${namespace} upgrade fog-test-client mcf-public/fog-test-client -i --version v3.0.0
```

### For Signal networks

```bash
helm -n ${namespace} upgrade fog-test-client mcf-public/fog-test-client -i --version v3.0.0 --set fogTestClientConfig.fogClientAuthTokenSecret.enabled=true
```
