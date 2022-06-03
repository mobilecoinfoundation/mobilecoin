#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -e  # exit on error

if [[ ! -z "$1" ]]; then
    cd "$1"
fi

# We want to check with --all-targets since it checks test code, but that flag
# leads to build errors in enclave workspaces, so check it here.
cargo clippy --all --all-features --all-targets

cargo install cargo-sort

for toml in $(grep --exclude-dir cargo --exclude-dir rust-mbedtls --include=Cargo.toml -r . -e '\[workspace\]' | cut -d: -f1); do
  pushd $(dirname $toml) >/dev/null
  echo "Linting in $PWD"
  cargo sort --workspace --grouped --check
  cargo fmt -- --unstable-features --check
  cargo clippy --all --all-features
  echo "Linting in $PWD complete."
  popd >/dev/null
done
