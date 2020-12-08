#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.
#
# Launches a local `mc-mobilecoind` instance that syncs the ledger from two nodes in the
# test network and hosts a wallet service running on port 4444, then launches a local
# `mc-testnet-client` instance that interacts with the local `mc-mobilecoind`.

set -e

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

source "$HOME/.cargo/env"

pushd "$(dirname "$0")"

echo "Pulling down TestNet consensus validator signature material"

TARGETDIR=./target/debug

echo "Building mobilecoind and mc-testnet-client. This will take a few moments."
SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
        cargo build -p mc-mobilecoind

echo "Starting local mobilecoind using TestNet servers for source of ledger. Check log at $(pwd)/mobilecoind.log."
${TARGETDIR}/mobilecoind \
        --ledger-db /tmp/ledger-db \
        --poll-interval 10 \
        --peer mc://node1.test.mobilecoin.com/ \
        --peer mc://node2.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
        --mobilecoind-db /tmp/transaction-db \
        --listen-uri insecure-mobilecoind://0.0.0.0:4444/
