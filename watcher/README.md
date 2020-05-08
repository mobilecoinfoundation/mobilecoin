mc-watcher
=========

Watcher nodes perform an essential role in the MobileCoin network by verifying the signatures that the full validator nodes attach to each block. In this way the watcher nodes continuously monitor the integrity of the decentralized MobileCoin network. A watcher node also maintains a complete local copy of the blockchain and provide an API for wallet or exchange clients.

Basic run command:

```
RUST_LOG=trace,hyper=error,want=error,reqwest=error,mio=error,rustls=error \
    cargo run -p mc-watcher --bin watcher -- \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
    --watcher-db /tmp/watcher-db \
```
