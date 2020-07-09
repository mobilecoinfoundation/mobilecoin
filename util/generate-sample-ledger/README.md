## Generate Sample Ledger

The MobileCoin network requires an intitial block of transactions, dubbed the "Origin Block," for all the nodes to start with the same contents in the ledger. This crate provides a tool for bootstrapping transactions in order to run consensus and local testing with an Origin Block.

Many MobileCoin services require passing the `--ledger-db` parameter, specifying the path to the directory containing the ledger database.

### Setup

First, generate the sample keys for accounts, with `--num` specifying the number of accounts to create.

```
mkdir keys
cargo run --release -p mc-util-keyfile --bin sample-keys -- --num 10
```

### Usage

Next, generate the ledger.

```
cargo run --release -p mc-util-generate-sample-ledger --bin generate-sample-ledger
```

This will generate 100 transactions for each account, placing the database in the `ledger` directory.
