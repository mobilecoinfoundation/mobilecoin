#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.
#
# Builds linux client tarball for a release.
#
# Usage:
#
# `./testnet-client-release.sh`

set -ex

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

pushd "$(dirname "$0")"

pushd ../../
MOBILECOIN_ROOT=$(pwd)

# Input Vars
: NAMESPACE=${NAMESPACE:?"Must provide NAMESPACE for enclave-distribution path"}
: VERSION=${VERSION:?"Must provide VERSION for ledger-db and mobilecoind-db paths"}

# Build Vars
SGX_MODE=${SGX_MODE:-HW}
IAS_MODE=${IAS_MODE:-PROD}

pushd ${MOBILECOIN_ROOT}
  
# Release Vars
RELEASE_REVISION=${RELEASE_REVISION:-$( git rev-parse HEAD )}

SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NAMESPACE}.mobilecoin.com/production.json | grep sigstruct | awk '{print $2}' | tr -d \")
curl -O https://enclave-distribution.${NAMESPACE}.mobilecoin.com/${SIGSTRUCT_URI}
CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css

# Build the binaries
RUSTFLAGS=' ' SGX_MODE=${SGX_MODE} IAS_MODE=${IAS_MODE} CONSENSUS_ENCLAVE_CSS=${CONSENSUS_ENCLAVE_CSS} \
  cargo build --release -p mc-mobilecoind -p mc-testnet-client

# Client directory is non-versioned because it is used for mobilecoind distribution in other scripts
mkdir -p mobilecoin-testnet-linux/bin
cp target/release/{mobilecoind,mc-testnet-client} mobilecoin-testnet-linux/bin

mkdir -p ${MOBILECOIN_ROOT}/tools/release/${VERSION}
cp ${MOBILECOIN_ROOT}/tools/release/package/mobilecoin-testnet.sh ${MOBILECOIN_ROOT}/tools/release/${VERSION}
sed -i 's/VERSION/'${VERSION}'/g' ${MOBILECOIN_ROOT}/mobilecoind/tools/release/${VERSION}/mobilecoin-testnet.sh
cp ${MOBILECOIN_ROOT}/tools/release/${VERSION}/mobilecoin-testnet.sh mobilecoin-testnet-linux/

# Modify the startup script
tar -czvf mobilecoin-testnet-linux.tar.gz mobilecoin-testnet-linux/
