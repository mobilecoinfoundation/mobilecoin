# consensus-node Helm Chart

## Launch a node.

The example node will be `consensus-node-1`

### Required Secrets

__Ledger Distribution__

Configuration for AWS S3 bucket used to store the ledger.

The name should be prefixed with the name of the helm release (`consensus-node-1`).

```yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: consensus-node-1-ledger-distribution
stringData:
  AWS_ACCESS_KEY_ID: <key id>
  AWS_SECRET_ACCESS_KEY: <access key>
  AWS_REGION: eu-west-2
  # bucket name
  LEDGER_DISTRIBUTION_S3_BUCKET: ledger.mainnet.mobilecoinww.com
  # s3 url to bucket
  MC_DEST: s3://ledger.mainnet.mobilecoinww.com/node1.prod.mobilecoinww.com?region=eu-west-2
  # HTTP path to s3 bucket - may be behind a CDN
  MC_TX_SOURCE_URL: https://ledger.mobilecoinww.com/node1.prod.mobilecoinww.com/
```

__Message Signer Private Key__

The private key for peer communication.

The name should be prefixed with the name of the helm release (`consensus-node-1`).

```yaml
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: consensus-node-1-msg-signer-key
stringData:
  MC_MSG_SIGNER_KEY: <private key>
```

### Required ConfigMaps

__Tokens Config__

The tokens config is shared by all consensus nodes on the network. It only needs to be installed once and should be named `tokens-config`

```yaml
apiVersion: v1
 kind: ConfigMap
metadata:
  name: tokens-config
data:
  tokens.signed.json: |
    {
      <tokens config>
    }
```
__Network Config__

Network Config is unique for each node and contains the list of all _other_ peers and their message public keys.

The name should be prefixed with the name of the helm release (`consensus-node-1`).

```yaml
apiVersion: v1
 kind: ConfigMap
metadata:
  name: consensus-node-1-network-config
data:
  network.json: |-
    {
      "broadcast_peers": [
      ],
      "quorum_set": {
        "members": [
          {
            "args": "",
            "type": "Node"
          },
        ],
        "threshold": 7
      },
      "tx_source_urls": [
      ]
    }
```

### Helm chart

Set up values yaml:
```yaml
mobilecoin:
  network: main
  partner: mc

node:
  config:
    clientHostname: node1.prod.mobilecoinww.com
    peerHostname: peer1.prod.mobilecoinww.com
```

Launch Helm chart

```sh
helm upgrade consensus-node-1 oci://ghcr.io/mobilecoin/charts/consensus-node \
  -i -n <namespace> --version <semver> -f values.yaml
```
