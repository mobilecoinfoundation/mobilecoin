# consensus-node Helm Chart

Deploy a single node of the consensus service

```sh
helm upgrade node1 ./ -i -n <namespace> \
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