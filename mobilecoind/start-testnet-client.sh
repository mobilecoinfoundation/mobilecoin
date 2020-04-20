#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.
#
# Launches a local `testnet-client` instance that interacts with a local mobilecoind.

set -e

source "$HOME/.cargo/env"

pushd "$(dirname "$0")"

TARGETDIR=../target/release

if [[ ! -f ${TARGETDIR}/mc-testnet-client ]]; then
    echo "Building testnetclient. This will take a few moments."
    SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css cargo build --release -p mc-testnet-client
fi

echo "Starting local testclient using TestNet servers for source of ledger. Check log at /tmp/mobilecoind.log."
${TARGETDIR}/mc-testnet-client

popd
