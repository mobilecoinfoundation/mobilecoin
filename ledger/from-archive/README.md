mc-ledger-from-archive
======

Sync the ledger from archive.

Basic run command:

```sh
mkdir /tmp/ledger-db
RUST_LOG=trace,mc_ledger_sync=error,mc_connection=error \
    cargo run -p mc-ledger-from-archive -- \
    --ledger-db /tmp/ledger-db \
    --tx-source-url https://d22gcbaenl3cwd.cloudfront.net/node2.test.mobilecoin.com/
```
