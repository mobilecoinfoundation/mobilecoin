#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.
#
# Launches a local `mobilecoind` instance that syncs the ledger from two nodes in the
# test network and hosts wallet service running on port 4444.

set -e

source "$HOME/.cargo/env"

echo "Pulling down TestNet consensus validator signature material"
curl -O https://enclave-distribution.test.mobilecoin.com/pool/e57b6902aee60be45b78b496c1bef781746e4389/bf7fa957a6a94acb588851bc8767eca5776c79f4fc2aa6bcb99312c3c386c/consensus-enclave.css

if [[ -d ../../../target/release/mobilecoind ]]; then
    echo "Building mobilecoind. This will take a few moments."
    SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css cargo build --release -p mobilecoind
fi

# Note that it may be necessary to delete the previous transaction database for a clean run:
# rm -rf /tmp/ledger-db; rm -rf /tmp/transaction_db; mkdir /tmp/transaction_db

echo "Starting local mobilecoind using TestNet servers for source of ledger. Check log at /tmp/mobilecoind.log."
SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css ../../../target/release/mobilecoind \
      --ledger-db /tmp/ledger-db \
      --poll-interval 10 \
      --peer mc://node1.test.mobilecoin.com/ \
      --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
      --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
      --mobilecoind-db /tmp/transaction_db \
      --service-port 4444
