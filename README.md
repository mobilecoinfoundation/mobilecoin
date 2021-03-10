[](./img/mobilecoin_logo.png)

# MobileCoin Fog

Crates that are not part of the initial open source release.

### Note to Developers

* MobileCoin Fog is a prototype. Expect substantial changes before and after the release.
* Please see [*CONTRIBUTING.md*](./CONTRIBUTING.md) for notes on contributing bug reports and code.

# MobileCoin Fog
MobileCoin Fog is a privacy-preserving service designed to support use of the MobileCoin Payments Network on mobile devices.

# Table of Contents
- [License](#license)
- [Cryptography Notice](#cryptography-notice)
- [Repository Structure](#repository-structure)
- [Build Instructions](#build-instructions)
- [Overview](#overview)
- [FAQ](#faq)
- [Support](#support)

## License
MobileCoin Fog is available under open-source licenses. Look for the *LICENSE* file in each crate for more information.

## Cryptography Notice
This distribution includes cryptographic software. Your country may have restrictions on the use of encryption software. Please check your country's laws before downloading or using this software.

## Repository Structure
|Directory |Description |
| :-- | :-- |
| [fog](./fog) | Privacy-preserving services to support MobileCoin payments on mobile devices. |
| [android-bindings](./android-bindings) | Bindings for android clients. |
| [libmobilecoin](./libmobilecoin) | Library for use in SDKs to interact with MobileCoin payment primitives. |
| [util](./util) | Miscellaneous utilities. |

#### Selected Binaries
| Target | Description | Used by... |
| :-- | :-- |:--|
| [`fog-ingest-server`](./fog/ingest/server) | Obliviously post-processes the blockchain to organize transaction outputs according to fog hints.| 
| [`fog-ledger-server`](./fog/ledger/server) | Obliviously serves ledger materials such as rings, merkle proofs, and key images, used to verify whether a Txo was spent, or construct new transactions. | 
| [`fog-report-server`](./fog/report/server) | Provides the ingest enclave's Attestation Verification Report for transaction construction. | 
| [`fog-view-server`](./fog/view/server) | Obliviously serves the post-processed Txos to clients who wish to check their balance and construct new transactions. | 

## Build Instructions

The workspace can be built with `cargo build` and tested with `cargo test`. Either command will recognize the cargo `--release` flag to build with optimizations.

Some crates (for example [`fog-ingest-service`](./fog/ingest/service)) depend on Intel SGX, which adds additional build and runtime requirements. For detailed information about setting up a build environment, how enclaves are built, and on configuring the build, see [BUILD.md](BUILD.md).

For a quick start, you can build in the same docker image that we use for CI, using the `mob` tool. Note that this requires you to install [Docker](https://docs.docker.com/get-docker/). You can use the `mob` tool with the following commands:

```
# From the root of the cloned repository
./mob prompt

# At the resulting docker container prompt
cargo build
```

## Overview

MobileCoin Fog is a suite of microservices designed to enable MobileCoin payments on mobile devices.

For MobileCoin payments to be practical, we cannot require the mobile device to 
sync the ledger or download the entire blockchain. However, a so-called “thin wallet” doesn’t 
work either, because the types of queries that a thin wallet makes generally reveal to the 
server what the user's balance is, when they got paid, etc. In typical thin wallet designs, the 
server is trusted by the user.

MobileCoin has been engineered to eliminate this sort of trust — the service is “oblivious” 
to the nature of the user requests, and the service operator is unable to harvest the users’ 
data in exchange for running the service.

Because of this, off-the-shelf solutions to wallet services simply don’t work — in many cases, 
if we naively make a database query to handle a query that a wallet would make if it had access 
to the ledger, it reveals significant information about e.g. whether Bob was paid or not in the 
last block, which payments Bob recieved, whether Alice paid Bob, etc., any of which would not 
meet our privacy goals.

Instead, Fog makes heavy use of SGX enclaves and Oblivious RAM data structures to serve such 
queries privately, without compromising scalability. The use of SGX in this way has the 
potential to create operational challenges, and the system has been carefully designed to 
navigate that.

### Architecture

Fog works by post-processing the blockchain in an SGX-mediated way, writing records to a 
database (the “recovery database”) which contains all the information that a user needs to 
recover all of their transactions privately.

Fog consists of four services:

  • The “fog-ingest” service consumes and post-processes the blockchain, writing records to the
    recovery database. This is an SGX service. It additionally publishes a public key to the 
    “fog-report” service.

  • The “fog-view” service provides an API for fog users to access this database. Some of the 
    queries that the user needs to make to the database are sensitive. To protect them, this 
    is an SGX service and some of the queries are resolved obliviously.

  • The “fog-ledger” service provides several APIs for fog users to make queries against the 
    MobileCoin ledger. Some of the queries that the user needs to make are sensitive, so this is 
    also an SGX service and some of the queries are resolved obliviously.

  • The “fog-report” service. The fog report service publishes a signed fog public key which 
    comes from the fog-ingest SGX enclave. This public key needs to be available to anyone 
    who wants to send MobileCoin to a fog user, so the fog report service is expected to be 
    publicly accessible and not require authentication (the way the others probably would). 
    In addition to the Intel report, there is an X509 certificate chain signing the report as 
    well. The “fog-report” service is not an SGX service.

## FAQ

1. Is Fog decentralized?

   Fog is a scalable service that helps users find their transactions, conduct balance checks,
   and build new transactions, without needing a local copy of the blockchain, and without
   revealing their activities or giving away their private keys.

   Fog is intended to be run by app providers to help their users have both privacy and a
   good mobile experience. Users only have to trust the integrity of SGX, and not the service
   provider, for their privacy.

   Fog is thus not a single, decentralized network, but can be deployed as needed by each
   party that wants to offer it and treated as critical infrastructure for their app, and
   scaled to meet their needs.

1. What is the hint field? Can I put anything in there?

   The purpose of the hint field is to send an encrypted message to a fog enclave associated
   to the transaction, which it finds when it post-processes the blockchain. A conforming
   client puts only an mc-crypto-box ciphertext of a specific size there. For non-fog
   transactions, a ciphertext encrypted for a random public key should be put there. Putting
   something in the hint field which is distinguishable from this may degrade privacy.

## Support

For troubleshooting help and other questions, please visit our [community forum](https://community.mobilecoin.foundation/).

You can also open a technical support ticket via [email](mailto://support@mobilecoin.foundation).

#### Trademarks

Intel and the Intel logo are trademarks of Intel Corporation or its subsidiaries. MobileCoin is a registered trademark of MobileCoin Inc.
