mc-watcher
=========

Watcher nodes perform an essential role in the MobileCoin network by verifying the signatures that the full validator nodes attach to each block. In this way the watcher nodes continuously monitor the integrity of the decentralized MobileCoin network.

Basic run command to sync block signatures from two nodes on the test network:

```sh
RUST_LOG=trace,hyper=error,want=error,reqwest=error,mio=error,rustls=error \
    cargo run -p mc-watcher --bin watcher -- \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
    --watcher-db /tmp/watcher-db
```

The watcher can also be incorporated into other programs, as in [`mobilecoind`](../mobilecoind/README.md), where the watcher continuously syncs block signatures, and `mobilecoind` offers an interface to query block signatures for watched nodes through the mobilecoind API.
