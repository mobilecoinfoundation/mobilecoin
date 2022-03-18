#!/bin/bash

# Copyright (c) 2018-2021 The MobileCoin Foundation

set -e  # exit on error

if [[ ! -z "$1" ]]; then
    cd "$1"
fi

cargo install cargo-sort

export SGX_MODE=SW
export IAS_MODE=DEV
export CONSENSUS_ENCLAVE_SIGNED=$(pwd)/libconsensus-enclave.signed.so
export CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css

export PARENT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

source $PARENT_PATH/download_sigstruct.sh

for toml in $(grep --exclude-dir cargo --exclude-dir rust-mbedtls --include=Cargo.toml -r . -e '\[workspace\]' | cut -d: -f1); do
  pushd $(dirname $toml) >/dev/null
  echo "Linting in $PWD"
  cargo sort --workspace --grouped --check
  cargo fmt -- --unstable-features --check
  cargo clippy --all --all-features
  echo "Linting in $PWD complete."
  popd >/dev/null
done
