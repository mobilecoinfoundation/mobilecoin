#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -e  # exit on error

if [[ ! -z "$1" ]]; then
    cd "$1"
fi

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
