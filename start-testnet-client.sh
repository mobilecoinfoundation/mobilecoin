#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.
#
# Launches a local `mobilecoind` instance that syncs the ledger from two nodes in the
# test network and hosts a wallet service running on port 4444, then launches a local
# `mc-testnet-client` instance that interacts with the local `mobilecoind`.

set -e

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

source "$HOME/.cargo/env"

pushd "$(dirname "$0")"

echo "Pulling down TestNet consensus validator signature material"
curl -O https://enclave-distribution.test.mobilecoin.com/pool/e57b6902aee60be45b78b496c1bef781746e4389/bf7fa957a6a94acb588851bc8767eca5776c79f4fc2aa6bcb99312c3c386c/consensus-enclave.css

TARGETDIR=./target/release

echo "Building mobilecoind and mc-testnet-client. This will take a few moments."
SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
        cargo build --release -p mobilecoind -p mc-testnet-client

if [[ -f /tmp/ledger-db ]] || [[ -f /tmp/transaction-db ]]; then
    echo "Removing ledger-db and transaction_db from previous runs. Comment out this line to keep them for future runs."
    rm -rf /tmp/ledger-db; rm -rf /tmp/transaction-db; mkdir /tmp/transaction-db
fi

echo "Starting local mobilecoind using TestNet servers for source of ledger. Check log at $(pwd)/mobilecoind.log."
${TARGETDIR}/mobilecoind \
        --ledger-db /tmp/ledger-db \
        --poll-interval 10 \
        --peer mc://node1.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
        --mobilecoind-db /tmp/transaction-db \
        --service-port 4444 &> $(pwd)/mobilecoind.log &

echo "Sleeping 10s to allow mobilecoind to sync the ledger"
sleep 10

echo "Starting local mc-test-client."
${TARGETDIR}/mc-testnet-client

popd
