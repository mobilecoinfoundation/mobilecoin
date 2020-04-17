![](./img/mobilecoin_logo.png)

### Note to Developers

* MobileCoin is a prototype. Expect substantial changes before the release.
* Please see [*CONTRIBUTING.md*](./CONTRIBUTING.md) for notes on contributing bug reports and code.

# MobileCoin
MobileCoin is a privacy-preserving payments network designed for use on mobile devices.

# Table of Contents
- [License](#license)
- [Cryptography Notice](#cryptography-notice)
- [Repository Structure](#repository-structure)
- [Build Instructions](#build-instructions)
- [Overview](#overview)
- [Support](#support)

## License
MobileCoin is available under open-source licenses. Look for the *LICENSE* file in each crate for more information.

## Cryptography Notice
This distribution includes cryptographic software. Your country may have restrictions on the use of encryption software. Please check your country's laws before downloading or using this software.

## Repository Structure
|Directory |Description |
| :-- | :-- |
| [attest](./attest) | Remote attestation primitives. |
| [build-info](./build-info) | Measurements made at compile time. |
| [common](./common) | Items shared across MobileCoin crates. |
| [consensus](./consensus) | Byzantine Fault Tolerant Consensus. |
| [crypto](./crypto) | Cryptography. |
| [enclave-boundary](./enclave-boundary) | SGX ECALL infrastructure. |
| [ledger](./ledger) | Storage and synchronization for the MobileCoin blockchain. |
| [mcbuild](./mcbuild/) | Tools for building and signing enclaves. |
| [mcconnection](./mcconnection/) | Attested MobileCoin connections. |
| [mobilecoind](./mobilecoind/) | Blockchain daemon and example client code. |
| [peers](./peers/) | Peer-to-peer networking. |
| [sgx](./sgx/) | Support for Intel® Software Guard eXtensions (Intel® SGX). |
| [transaction](./transaction/) | Private transactions. |
| [util](./util/) | Testing and bootstrap utilities. |

#### Selected Binaries
| Target | Description | Nodes |
| :-- | :-- |:--|
| [`consensus-service`](./consensus/service) | Validates new transactions for the public ledger.| Validator Nodes |
| [`ledger-distribution`](./ledger/distribution) | Publishes the ledger to long-term storage. | Full Validator Nodes|
| [`mobilecoind`](./mobilecoind) | Synchronizes the ledger and provides the desktop API. | Watcher and Validator Nodes |

## Build Instructions

The workspace can be built with `cargo build` and tested with `cargo test`. Either command will recognize the cargo `--release` flag to build with optimizations.

Some crates require additional environment variables to build successfully. For example, the `consensus` crate requires an environment variable "SGX_MODE" to be set for either "hardware mode" or "simulation mode" as well as a variable "IAS_MODE" to indicate the type of attestation service to use. You can find more information in the *BUILD.md* file found in crates that require additional build information.

To simplify the build process, we provide a tool, `mob` which creates a docker container with the required dependencies, including the necessary versions of SGX and protobuf libraries. You can use this tool with the following commands:

```
# From the root of the cloned repository
./mob prompt

# At the resulting docker container prompt
cargo build
```

## Overview

MobileCoin is a payment network with no central authority. The fundamental goal of the network is to safely and efficiently enable the exchange of value, represented as fractional ownership of the total value of the network. Like most cryptocurrencies, MobileCoin maintains a permanent and immutable record of all successfully completed payments in a blockchain data structure. Cryptography is used extensively to establish ownership, control transfers, and to preserve cash-like privacy for users.

Here we review a few design concepts that are essential for understanding the software.

##### Transactions

The MobileCoin blockchain is the source of truth for the allocation of value. It consists of an ordered collection of *transaction outputs*, organized into blocks. Each *transaction output* ("*txo*") has a unique corresponding construction called a *key image*. Every *txo* initially appears in the blockchain in a spendable state, as an *unspent transaction output* or *utxo*. Every successful payment consumes some *utxos* as inputs and creates new *utxos* as outputs. When a *utxo* is consumed, its corresponding *key image* is permanently added to the blockchain, ensuring that it can not be spent a second time.

The total value of the MobileCoin network is fixed by convention at a sum of 250 million *mobilecoins*. Each *mobilecoin* consists of 10<sup>12</sup> indivisible parts, each referred to as one *picomob*. Each *utxo* represents an integer number of *picomob* that can be consumed in a valid payment.

Ownership of a *utxo* in the MobileCoin network is equivalent to knowledge of two private keys, called the *spend private key* and the *view private key*, that provision control over discovery and transfer of value. Most users will derive these two private key values from a single underlying key we call the *root entropy*.

To receive a payment, a user must calculate the two  public key values corresponding to their private keys to share with their counter-party. MobileCoin specifies a standard encoding scheme using a base-58 symbol library for users to safely exchange payment information.

For more information on how transactions work, and how they use CrytpoNote-style transactions to preserve privacy of both the sender and receiver, see the [transaction](./transaction) crate.

To understand the blockchain format and storage, see the [ledger_db](./ledger/db) crate.

##### Consensus

New transactions must be checked for attempts to counterfeit value before new *key images* and *utxos* can be added to the MobileCoin blockchain. Transactions are prepared by the user on their local computer or mobile device, and submitted to a secure enclave running on a *validator node* of their choice. The *validator node* checks the transaction and, assuming it believes the transaction is valid, shares it with other nodes in the MobileCoin network. The transaction is passed only to peer secure enclaves that can establish via remote attestation that they are running unmodified MobileCoin software on an authentic Intel processor. Each secure enclave replicates a state machine that adds valid transactions to the ledger in a deterministic order using a consensus algorithm called the MobileCoin Consensus Protocol.

The MobileCoin Consensus Protocol is a high-performance solution to the byzantine agreement problem that allows new payments to be rapidly confirmed. The `consensus-service` target binary uses Intel Software Guard eXtensions (SGX) to provide defense-in-depth improvements to privacy and trust.

To learn how MobileCoin uses SGX to provide integrity in Byzantine Fault Tolerant (BFT) consensus as well as forward secrecy to secure your privacy, see the [consensus/enclave](./consensus/enclave) crate. To build and run consensus, see the [consensus/service](./consensus/service) crate.

*Full validator nodes* additionally use the `ledger-distribution` target binary to publish a copy of their computed blockchain to content delivery networks (currently to Amazon S3 only). The public blockchain is a zero-knowledge data structure that consists only of *utxos*, *key images* and block metadata used to ensure consistency and to construct Merkle proofs. To build and run ledger distribution, see the [ledger/distribution](./ledger/distribution) crate.

*Watcher nodes* perform an essential role in the MobileCoin network by verifying the signatures that the *full validator nodes* attach to each block. In this way the *watcher nodes* continuously monitor the integrity of the decentralized MobileCoin network. A *watcher node* also maintains a complete local copy of the blockchain and provide an API for wallet or exchange clients.

To run a *watcher node*, build and run the [`mobilecoind`](./mobilecoind) daemon.

## Support

For troubleshooting and questions, please visit our [support center](https://mobilecoin.zendesk.com/) or our [community forum](https://community.mobilecoin.com/).

You can also open a technical support ticket via [email](mailto://support@mobilecoin.com).

#### Trademarks

*Intel and the Intel logo are trademarks of Intel Corporation or its subsidiaries."
*MobileCoin is a registered trademark of MobileCoin Inc."
