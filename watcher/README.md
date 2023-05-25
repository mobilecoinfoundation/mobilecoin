mc-watcher
=========

Watcher nodes perform an essential role in the MobileCoin network by verifying the signatures that the full validator nodes attach to each block. In this way the watcher nodes continuously monitor the integrity of the decentralized MobileCoin network.

Basic run command to sync block signatures from two nodes on the test network:

Create a `sources.toml` file, for example:
```toml
[[sources]]
tx_source_url = "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/"
consensus_client_url = "mc://node1.test.mobilecoin.com/"

[[sources]]
tx_source_url = "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/"
consensus_client_url = "mc://node2.test.mobilecoin.com/"
```

```sh
SGX_MODE=HW IAS_MODE=PROD MC_LOG=debug,hyper=error,want=error,reqwest=error,mio=error,rustls=error \
    cargo run -p mc-watcher --bin mc-watcher -- \
    --sources-path sources.toml \
    --watcher-db /tmp/watcher-db
```

The watcher can also be incorporated into other programs, as in [`mobilecoind`](../mobilecoind/README.md), where the watcher continuously syncs block signatures, and `mobilecoind` offers an interface to query block signatures for watched nodes through the mobilecoind API.

In order to check that the watcher is running, you can send a gRPC request to the health check endpoint:
```sh
grpcurl -proto ./util/grpc/proto/health_api.proto -plaintext localhost:3226 grpc.health.v1.Health/Check
```
