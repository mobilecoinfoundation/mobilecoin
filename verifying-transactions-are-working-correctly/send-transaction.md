# Send Transaction

**Step 1: **Start mobilecoind to sync the ledger and connect to Consensus Validators

{% hint style="info" %}
Check out the [latest release](https://github.com/mobilecoinofficial/mobilecoin/releases/latest) of the mobilecoin repo
{% endhint %}

**Step 2:** Open up `./start-tesnet-client.sh` to see how to build and run mobilecoind with the latest commands and CSS file from S3

| Parameter         | Description                                                                                                                                                                                                                                                                                |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--ledger-db`     | Path to sync ledger to; will build ledger locally.                                                                                                                                                                                                                                         |
| `--poll-interval` | Frequency of polling nodes for block height to trigger sync.                                                                                                                                                                                                                               |
| `--peer`          | <p>Consensus Validator to check block height and to submit transactions. When multiple peers are provided, transactions are submitted in a round-robin fashion.</p><p><strong></strong></p><p><strong>Note: </strong>We use a URI scheme with mc:// preceding the address of the node.</p> |
| --tx-source-url   | Location in S3 from which to pull blocks for syncing the ledger locally.                                                                                                                                                                                                                   |
| --mobilecoind-db  | Local wallet DB holds keys and transactions.                                                                                                                                                                                                                                               |
| --service-port    | API port for grpc commands. The python wallet will use this port.                                                                                                                                                                                                                          |

```
${TARGETDIR}/mobilecoind \
        --ledger-db /tmp/ledger-db \
        --poll-interval 10 \
        --peer mc://node1.test.mobilecoin.com/ \
        --peer mc://node2.test.mobilecoin.com/ \
        --tx-source-url 
https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
        --tx-source-url
https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
        --mobilecoind-db /tmp/transaction-db \
        --service-port 4444 &> $(pwd)/mobilecoind.log &
```

The log will show messages related to syncing the ledger. When it has finished syncing, you will see messages such as:

```
2020-07-24 22:34:20.092996 UTC DEBG Polling finished, current results:
{ResponderId("node2.test.mobilecoin.com:443"): Some(43694), 
ResponderId("node1.test.mobilecoin.com:443"): Some(43694)}, mc.app: 
mobilecoind, mc.module: mc_ledger_sync::polling_network_state, mc.src:
ledger/sync/src/polling_network_state.rs:118
2020-07-24 22:34:20.093014 UTC TRCE Sleeping, num_blocks = 43695...,
mc.app: mobilecoind, mc.module: mc_ledger_sync::ledger_sync_service_thread,
mc.src: ledger/sync/src/ledger_sync_service_thread.rs:138
```

\
