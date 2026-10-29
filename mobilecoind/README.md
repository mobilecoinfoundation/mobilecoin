## mobilecoind

The MobileCoin Daemon, or `mobilecoind`, is a standalone executable which provides blockchain synchronization and wallet services.

It creates encrypted, attested connections to validator nodes who are participating in federated voting in order to get the current block height, block headers, and to submit transactions. These validator nodes are considered highly trusted due to their use of SGX, and they are used as a reliable source for block information as well as to validate and process the proposed transactions from `mobilecoind`.

To keep the blockchain in sync, `mobilecoind` downloads new blocks from cloud storage and checks with the validator nodes that the block headers are correct. If this succeeds, they are added to a local copy of the blockchain called the Ledger DB. This is done periodically and ensures the local copy of the blockchain is fresh enough to calculate balances and generate transactions.

Wallet Clients, such as a CLI, wanting to use wallet services can register their keys through the [API](./api/proto/mobilecoind_api.proto). In addition to keeping the blockchain in sync, the MobileCoin Daemon maintains a list of unspent transactions owned by any registered keys for fast lookup and spending, in a database called the MobileCoin Daemon DB.

## Table of Contents

  - [Getting Started](#getting-started)
    - [Setup](#setup)
    - [Verifying Signed Enclaves](#verifying-signed-enclaves)
    - [Example Invocation](#example-invocation)
    - [Offline Transactions](#offline-transactions)

### Getting Started

#### Setup

In order to sync the ledger from multiple sources, you will need to specify the validator nodes that you trust, as well as the location where they publish their externalized blocks (this is typically an S3 bucket).

We use URIs to specify peers, such as:

```
mc://node1.test.mobilecoin.com/
```

You will need to specify a ledger location to which to sync the ledger. This directory can be empty (or non-existent), or can contain the origin block, created from [generate-sample-ledger](../util/generate-sample-ledger/README.md).
You will also need to specify a directory for the MobileCoin Daemon database, where keys and transaction data would be stored.

#### Verifying Block Signatures

When started with `--watcher-db`, mobilecoind syncs all block signatures from the consensus validator archives listed in the tx-source-urls. On sync, each block signature is verified. See the [watcher](../watcher/README.md) crate for more information.

#### Verifying Signed Enclaves

When mobilecoind connects to validator nodes, it verifies the integrity of their software using Intel's Secure Guard eXtensions (SGX) via attestation evidence.

The validator node provides a signed measurement of its internal state to assure that it is running exactly the software you expect. You must provide a specific file to mobilecoind on startup so that it has the materials it needs to validate the enclave's evidence.

The TestNet signature artifacts are available via

```
curl -O https://enclave-distribution.test.mobilecoin.com/production.json
```

This retrieves a json record of:

```json
{
    "consensus": {
        "enclave": "pool/<git revision>/<signing hash>/<filename>",
        "sigstruct": "pool/<git revision>/<signing hash>/<filename>"
    }
}
```

The git revision refers to the TestNet release version, and provides the full path to the production version of the artifact.

For example, MobileCoin's TestNet enclave signature materials are available via:

```
curl -O https://enclave-distribution.test.mobilecoin.com/pool/bceca6256b2ad9a6ccc1b88c109687365677f0c9/bf7fa957a6a94acb588851bc8767eca5776c79f4fc2aa6bcb99312c3c386c/consensus-enclave.css
```

Once you fetch the sigstruct artifact, you must provide the sigstruct to mobilecoind via the environment variable `CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css`.

#### Example Invocation

This invocation connects to two validator nodes in the MobileCoin demo network, uses their respective S3 buckets to download new blocks, polls every second for updates and provides a MobileCoinD API on port 4444.

>Note: The MobileCoin Daemon validates attestation evidence from the validator nodes, and so needs to know whether those validators are running with hardware SGX or in simulation mode, via the `SGX_MODE` variable.

```
SGX_MODE=HW CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
    MC_LOG=debug,rustls=warn,hyper=warn,tokio_reactor=warn,mio=warn,want=warn,rusoto_core=error,h2=error,reqwest=error \
    cargo run --release -p mc-mobilecoind -- \
    --ledger-db /path/to/ledger \
    --watcher-db /path/to/watcher-db \
    --poll-interval 1 \
    --peer mc://node1.test.mobilecoin.com/ \
    --peer mc://node2.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
    --mobilecoind-db /path/to/mobilecoind-db \
    --listen-uri insecure-mobilecoind://127.0.0.1:4444/
```

For more details about the various command line arguments supported by the MobileCoin Daemon, use the `--help` argument:
```cargo run --release -p mc-mobilecoind -- --help```

#### Offline Transactions

Offline transactions are a way of constructing a transaction on a machine that is not connected to the Internet, allowing for increased safety around the storage of sensitive key material. The requirements for doing that are:
1. A machine that is connected to the internet, running `mobilecoind` as usual.
1. A second machine, not connected to the internet, that has a recent copy of ledger. The ledger must contain some spendable TxOuts by the key that will be used.

The steps for constructing and submitting an offline transaction are:

1. Copy a recent copy of the ledger database into the airgapped machine. The copied ledger should include TxOuts that are spendable by the user.
1. Copy the pre-built mobilecoind binary to the airgapped machine.
1. Run `mobilecoind` on the airgapped machine: `MC_LOG=trace ./mobilecoind --release -- --offline --listen-uri insecure-mobilecoind://127.0.0.1:4444/ --mobilecoind-db /tmp/wallet-db`.
1. Connect to this `mobilecoind`, add a monitor with your keys, let it scan the ledger, and construct a transaction using the `GenerateTx` API call, using one of the clients such as `mobilecoind-json`.
1. `GenerateTx` will return a `TxProposal`, which you can then copy back to the internet-connected machine.
1. Copy this `TxProposal` into a machine that has internet access and `mobilecoind` running.
1. Decode the `TxProposal` and submit it using the `SubmitTx` API call. Even if the `mobilecoind` instance you are submitting to has no monitors defined at all, this would still work.

## Encrypted database upgrades

Database format `20261016` uses a fresh random 96-bit AES-GCM nonce for every
monitor write, including sync updates. Each encryption generation has a random
32-byte salt and its own Argon2id-derived key (64 MiB, 3 passes, 4 lanes).
Password changes, including setting the same password again, create a new
generation and re-encrypt every monitor. The password API still accepts a
caller-derived 32-byte value; an empty password still disables encryption.

An older encrypted database opens locked. The first successful `UnlockDb` (or
mobilecoind-json `/unlock-db`) authenticates the password and migrates all monitor
records, the password marker, salt, and format version in one LMDB transaction.
Sync starts only after this succeeds. Allow enough storage for LMDB's temporary
copy-on-write pages. Wrong passwords or migration failures leave the database
locked and its committed data unchanged; investigate the error and retry unlock.
Unencrypted databases upgrade their version on opening.

Upgraded databases cannot be opened by older binaries, even after encryption is
removed. Rollback requires a protected pre-upgrade backup and an older binary;
that backup still uses the vulnerable encryption format. Run only one mobilecoind
process per database directory.

### Remove unused pages after migration

In-place migration changes active records but does not erase old ciphertext from
unused LMDB pages. Finish the rollout with an offline compact copy. LMDB's
`mdb_copy -c` copies only current pages, omitting unused pages. Install the LMDB
`mdb_copy` utility appropriate for the deployment before starting this procedure.

1. Upgrade mobilecoind, unlock the database, and wait for successful migration.
   Verify that the expected monitors and sync positions are accessible.
2. Stop mobilecoind and every other process accessing that database directory.
   Keep them stopped until the replacement is complete.
3. Create a compact copy on the same filesystem, with restricted permissions:

   ```sh
   db_dir=/path/to/mobilecoind-db
   compact_dir="${db_dir}.compact"
   old_dir="${db_dir}.pre-compact"
   umask 077
   test ! -e "$compact_dir" && test ! -e "$old_dir" || exit 1
   mkdir -m 700 "$compact_dir"
   mdb_copy -c "$db_dir" "$compact_dir" || exit 1
   ```

4. Start the upgraded binary with the usual deployment configuration but point
   `--mobilecoind-db` at the compact directory. Unlock it and verify every expected
   monitor and sync position. Stop that validation process before replacing files.
   If validation fails, retain the source directory and investigate.
5. With all database processes stopped, replace the directory:

   ```sh
   mv -- "$db_dir" "$old_dir" || exit 1
   if ! mv -- "$compact_dir" "$db_dir"; then
       mv -- "$old_dir" "$db_dir"
       exit 1
   fi
   ```

6. Restore the deployment's required ownership and permissions, then restart with
   the original database path and unlock. Retire the old directory and any
   pre-migration snapshots/backups according to the storage system's secure data
   retirement procedure. Ordinary file deletion does not guarantee erasure from
   SSDs, filesystem snapshots, or backups.
