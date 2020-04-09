## The MobileCoin Daemon

`mobilecoind` is a standalone executable, which provides blockchain synchronization and wallet services.

It creates encrypted, attested connections to consensus validators who are participating in federated voting in order to get the current block height, block headers, and to submit transactions. These consensus validators are considered highly trusted due to their use of SGX, and they are used as a reliable source for block information as well as to validate and process the proposed transactions from `mobilecoind`.

To keep the blockchain in sync, the MobileCoin Daemon downloads new blocks from cloud storage and checks with the consensus validators that the block headers are correct. If this succeeds, they are added to a local copy of the blockchain called the Ledger DB. This is done periodically and ensures the local copy of the blockchain is fresh enough to calculate balances and generate transactions.

Wallet Clients, such as a CLI, wanting to use wallet services can register their keys through the [API](./api/proto/mobilecoind_api.proto). In addition to keeping the blockchain in sync, the MobileCoin Daemon maintains a list of unspent transactions owned by any registered keys for fast lookup and spending, in a database called the MobileCoin Daemon DB.

## Table of Contents

  - [Getting Started](#getting-started)
    - [Setup](#setup)
    - [Example Invocation](#example-invocation)

### Getting Started

#### Setup

In order to sync the ledger from multiple sources, you will need to specify the consensus validators that you trust, as well as the location where they publish their externalized blocks (this is typically an S3 bucket).

We use URIs to specify peers, such as:

```
mc://node1.test.mobilecoin.com/
```

You will need to specify a ledger location to which to sync the ledger. This directory can be empty (or non-existent), or can contain the origin block, created from [generate_sample_ledger](../generate_sample_ledger/README.md).
You will also need to specify a directory for the MobileCoin Daemon database, where keys and transaction data would be stored.

#### Example Invocation

This invocation connects to two consensus validators in the MobileCoin demo network, uses their respective S3 buckets to download new blocks, polls every second for updates and provides a MobileCoinD API on port 4444.

>Note: The MobileCoin Daemon validates attestation evidence from the Consensus Validators, and so needs to know whether those validators are running with hardware SGX or in simulation mode, via the SGX_MODE variable.

```
SGX_MODE=HW MC_LOG=debug,rustls=warn,hyper=warn,tokio_reactor=warn,mio=warn,want=warn,rusoto_core=error,h2=error,reqwest=error cargo run --release -p mobilecoind -- \
    --ledger-db /path/to/ledger \
    --poll-interval 1 \
    --peer mc://node1.test.mobilecoin.com/ \
    --peer mc://node2.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
    --mobilecoind-db /path/to/mobilecoind-db \
    --service-port 4444
```

For more details about the various command line arguments supported by the MobileCoin Daemon, use the `--help` argument:
```cargo run --release -p mobilecoind -- --help```
