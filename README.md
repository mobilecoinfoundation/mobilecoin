![](./img/mobilecoin_logo.png)

## Note to Developers

* MobileCoin is a prototype.
* The APIs are constantly evolving and designed to demonstrate types of functionality. Expect substantial changes before the release.

## MobileCoin

MobileCoin is a privacy-preserving payments network designed for use on mobile devices.

### Table of Contents

  - [Getting Started](#getting-started)
    - [Build Instructions](#build-instructions)
    - [License](#license)
    - [Overview](#overview)
      - [Blockchain](#blockchain)
      - [Consensus](#consensus)
        - [Ledger Distribution](#ledger-distribution)
      - [Wallet](#wallet)
        - [The MobileCoin Daemon](#the-mobilecoin-daemon)
  - [FAQ](#faq)
  - [Crates Overview](#crates-overview)

### Getting Started

To contributors: see [CONTRIBUTING.md](./CONTRIBUTING.md).

To participate in federated voting on MobileCoin transactions, see [Consensus](#consensus).

To privately send and receive mobilecoin, see [Wallet](#wallet).

To validate the blockchain, see [The MobileCoin Daemon](#the-mobilecoin-daemon).

#### Build Instructions

This workspace is built with `cargo build`, and tested with `cargo test`.

Some crates, such as consensus-service, build binaries that have special runtime requirements, such as Intel's Software Guard eXtensions (SGX). You will need to provide an environment variable to indicate whether to build for hardware mode (`HW`) or simulation mode (`SW`) mode, as well as which attestation service to use, e.g. `SGX_MODE=HW IAS_MODE=DEV cargo build`. You will find more information in the BUILD.md in these crates, for example, [consensus/service/BUILD.md](consensus/service/BUILD.md).

To ease the process of building, we provide a tool which starts a docker container with all the correct dependencies, including the necessary versions of SGX and proto libraries.

You can use it with the following:

```
# From the root of the repo
./mob prompt

# At the container prompt
cargo build
```

The consensus_enclave is a nested workspace, which is built with `cargo build.`

#### License

The components of MobileCoin require different licenses. Look for the LICENSE file in each crate for more information.

#### Overview

The MobileCoin ecosystem consists of three main components, which enable users to send each other MobileCoin securely and privately:

* The blockchain - completely private ledger of transactions.
* The consensus network - fast, decentralized confirmation of transactions.
* The wallet - secure access to send and receive mobilecoin.

##### Blockchain

The blockchain is the source of truth for all transactions. It consists of blocks of transactions. Each transaction produces new outputs, which can be consumed in a later transaction.

For more information on how transactions work, and how they use CrytpoNote-style transactions to preserve privacy of both the sender and receiver, see the [transaction](./transaction/README.md) crate.

To understand the blockchain format and storage, see the [ledger_db](./ledger/db/README.md) crate.

##### Consensus

Every transaction is validated in a trusted enclave, and members of consensus vote on whether to include the transaction in the blockchain in a process called consensus.

The MobileCoin Consensus Protocol is a high-performance solution to the Byzantine Agreement Problem that allows new payments to be rapidly confirmed. The Consensus service uses Intel’s Software Guard eXtensions (SGX) to provide defense-in-depth improvements to privacy and trust via secure enclaves.

To learn how MobileCoin uses SGX to provide integrity in Byzantine Fault Tolerant (BFT) consensus as well as forward secrecy to secure your privacy, see the [consensus/enclave](./consensus/enclave/README.md) crate.

To build and run consensus, see the [consensus/service](./consensus/service/README.md) crate.

###### Ledger Distribution

Consensus nodes can publish their blocks to a long-term storage mechanism, such as Simple Storage Service (S3). Best practices recommend publishing the ledger when running consensus for the MobileCoin community.

To build and run ledger distribution, see the [ledger/distribution](./ledger/distribution/README.md) crate.

##### Wallet

To send and receive transactions, run a [wallet client](./mobilecoind/clients) alongside [`mobilecoind`](./mobilecoind/README.md).

>Note: `mobilecoind` provides the wallet bindings in gRPC, so that you can write a wallet client in any language. We provide a [python example](./mobilecoind/clients/python).

##### The MobileCoin Daemon

`mobilecoind` syncs transactions from the ledger to your local machine.

>Note: This is necessary in order to run a wallet.

To build and run the MobileCoin Daemon, see the [mobilecoind](./mobilecoind/README.md) crate.

### FAQ

1. Are my transactions still private in the event of an SGX compromise?

    SGX provides integrity and confidentiality while it is sound, but several side channel exploits against SGX in recent months indicate that it is unwise to leave transactions in the clear while in the black box of the enclave. For that reason, MobileCoin transactions use CryptoNote technology to ensure that, even in the clear, the recipient is concealed with a one-time address, the sender is concealed in a ring signature, and the amounts are concealed with Ring Confidential Transactions (RingCT).

    In the event of an SGX compromise, someone's view of the ledger inside the enclave would still be protected by both ring signatures and one-time addresses, and amounts concealed with RingCT. These are the primary mechanisms in other privacy coins, which do not have SGX. Without SGX, this leaves open the possibility of a statistical attack, tracing the inputs in the ring signature to determine probabilistic relationships between transactions. This attack is only applicable to new transactions made during the time that the exploit is known, but not patched. Once the SGX vulnerability is addressed, those statistical attacks are no longer possible, because MobileCoin discards the inputs to transactions inside the enclave, and therefore forward secrecy is preserved.

1. Can I run a Consensus Validator without SGX?

    You can run a Consensus Validator using SGX in simulation-mode, however you will not be able to participate in consensus with other validators who are running consensus, because your software measurement will be different, and you will not be able to attest with hardware-enabled SGX peers.

1. If I don't have SGX, can I participate at all?

   You can run the MobileCoin daemon, which does not require SGX, and validate block signatures.

1. Does the wallet require SGX?

   The wallet does not require SGX.

1. I thought you were called "Mobile" Coin. Where is all the mobile code?

   We are hard at work building the mobile SDKs for iOS and Android, as well as additional privacy-preserving infrastructure to support blockchain transactions from mobile devices. We will be releasing these soon.

1. Do my keys ever leave my device? I thought the only way to get and send blockchain transactions on my phone was to hand over my keys to a third-party service who can scan for transactions on my behalf?

   The keys never leave your device. This is a challenging problem that private blockchains face, and we are excited to present our solution to this problem in the coming weeks.

### Crates Overview

#### Runnable MobileCoin Components

| Name    | Description |
| ------- | ----------- |
| [`consensus`](./consensus/service/README.md) | Byzantine Fault Tolerant Consensus. |
| [`ledger/distribution`](./ledger/distribution/README.md) | Publishing the ledger to long-term storage. |
| [`mobilecoind`](./mobilecoind/README.md) | Sending and receiving MobileCoin, syncing ledger, and validating blocks. |

#### Additional MobileCoin Components

| Name    | Description |
| ------- | ----------- |
| [`attest`](./attest/core/) | Core attestation primitives. |
| [`common`](./common) | Items shared across MobileCoin crates. |
| [`crypto`](./crypto) | Cryptography. |
| [`ledger/db`](./ledger/db/) | Local ledger storage of the MobileCoin blockchain. |
| [`mcconnection`](./mcconnection/) | Attested MobileCoin connections. |
| [`peers`](./peers/) | Peer-to-peer networking. |
| [`sgx`](./sgx/) | Support for Intel's Software Guard eXtensions (SGX). |
| [`transaction`](./transaction/) | Private transactions. |
