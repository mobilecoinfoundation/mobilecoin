## MainNet User Guide

The [Terms of Use for MobileCoins and MobileCoin Wallets](./TERMS-OF-USE.md) (also available at www.buymobilecoin.com) applies to all MobileCoins and MobileCoin Wallets.

You must read and accept these terms to use MobileCoin Software.

### MobileCoin Wallets

To send and receive MobileCoin, you can use any of our open source wallet solutions.

Please note that currently, the MobileCoin Wallet is not available for download or use by U.S. persons or entities, persons or entities located in the U.S., or persons or entities in other prohibited jurisdictions.

#### MobileCoin Wallet CLI

* Run [`mobilecoind`](./mobilecoind/README.md) for the wallet backend. Note that the mobilecoind-db is considered sensitive; you should follow best practices for isolation and security.
* Run [`mobilecoind-json`](./mobilecoind-json/README.md) to issue HTTP requests through a proxy to the `mobilecoind` backend.

An example MainNet build and launch command for mobilecoind is:

1. Get the enclave sigstruct:

    ```
    SIGSTRUCT_URI=$(curl -s https://enclave-distribution.prod.mobilecoin.com/production.json | jq -r '.consensus.sigstruct')
    curl -O https://enclave-distribution.prod.mobilecoin.com/${SIGSTRUCT_URI}
    ```

1. Build mobilecoind and mobilecoind-json

    ```
    SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css cargo build --release -p mc-mobilecoind -p mc-mobilecoind-json
    ```

1. Run mobilecoind, connecting to one or multiple Consensus Validator Nodes:

    ```
    ./target/release/mobilecoind \
        --ledger-db /path/to/ledger-db \
        --mobilecoind-db /path/to/mobilecoind-db \
        --poll-interval 10 \
        --peer mc://node1.prod.mobilecoinww.com/ \
        --peer mc://node2.prod.mobilecoinww.com/ \
        --tx-source-url https://ledger.mobilecoinww.com/node1.prod.mobilecoinww.com/ \
        --tx-source-url https://ledger.mobilecoinww.com/node2.prod.mobilecoinww.com/ \
        --listen-uri insecure-mobilecoind://127.0.0.1:4444/
    ```

1. Run mobilecoind-json

    ```
    ./target/release/mobilecoind-json
    ```

1. Issue curl commands to mobilecoind-json, listening on 9090, or send protobuf requests to mobilecoind, listening on localhost:4444.

    ```
    curl localhost:9090/ledger/local
    ```

    See the [mobilecoind protobuf API](./mobilecoind/api/proto/mobilecoind_api.proto) and the [mobilecoind-json README](./mobilecoind-json/README.md) for the full API descriptions.

### Run a MainNet *Watcher Node*

If you have a Linux-compatible home computer, or choose to operate a Linux-compatible server in the cloud, you can run a *watcher node* in the MobileCoin MainNet. This involves running [`mobilecoind`](./mobilecoind/README.md) in watcher mode.

### Join the Community

1. Exchange payment request information with other community members at the [MobileCoin Community Forum](https://community.mobilecoin.foundation).

1. Collaborate to help stress test the *validator nodes* to discover potential problems.

### Run a MainNet *Validator Node*

If you have an SGX-capable machine, or choose to operate an SGX-capable server in the cloud, you can run a *validator node* in the MobileCoin MainNet.

1. Send an email to [support@mobilecoin.foundation](mailto://support@mobilecoin.foundation) and let the MobileCoin Foundation know how you'd like to get involved!

## Getting Help

For troubleshooting and questions, please visit the community forum at https://community.mobilecoin.foundation. You can also open a technical support ticket via email to <support@mobilecoin.foundation>.
