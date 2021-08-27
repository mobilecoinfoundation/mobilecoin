# fog-test-client

The `fog-test-client` can be used to validate that a fog-enabled test network
is working. It instantiates the `fog-sample-paykit` for several account keys
used in tests, and attempts to transact between them, waiting for payments to
appear and balances to change as expected.

The private keys to the accounts which should be used in the test must be provided,
by passing the path to a directory of keyfiles as a command-line argument.

Before the test can proceed, the account keys have to have a balance of mobilecoins.
The `fog-distribution` tool moves money from the genesis block to the test accounts.

This test can be run against nodes running entirely locally, or against a deployed
network in the cloud.

Example usage

``` bash
    SGX_MODE=HW IAS_MODE=DEV cargo build -p fog-test-client
    RUST_LOG=debug ./test_client -- --key-dir ../ops/sample_data/keys --consensus mc://node1.alpha.mobilecoin.com/ --num-clients 2 --num-transactions 1 --consensus-wait 300 --transfer-amount 20 --fog-view-override fog-view.alpha.mobilecoin.com --fog-ledger fog-ledger.alpha.mobilecoin.com
```
