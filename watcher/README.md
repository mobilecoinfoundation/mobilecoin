mc-watcher
=========

Basic run command:

```
RUST_LOG=trace,hyper=error,want=error,reqwest=error cargo run -p mc-watcher --bin watcher -- \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
    --watcher-db /tmp/watcher-db \
    --ledger-db /tmp/ledger-db
```
