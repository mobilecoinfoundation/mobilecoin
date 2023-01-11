#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -e  # exit on error

CHECK=""

while [ "$1" != "" ]; do
  case "$1" in
    --check)
      CHECK="--check"
      ;;
    -h | --help)
      echo "Lints rust files in the repo"
      echo "Linters that can fix will fix the files, by default."
      echo "Fixing linters include 'cargo sort' and 'cargo fmt'."
      echo ""
      echo "Usage: $(basename $0) [--check]"
      echo ""
      echo "Args:"
      echo "        --check  Limit linters that can fix to only check"
      echo "    -h, --help   Prints help information"
      exit 0
      ;;
    *)
      echo "Unrecognized argument: '$1'"
      exit 2
      ;;
  esac
  shift
done

# We want to check with --all-targets since it checks test code, but that flag
# leads to build errors in enclave workspaces, so check it here.
cargo clippy --all --all-features --all-targets

cargo install cargo-sort

for toml in $(grep --exclude-dir cargo --exclude-dir rust-mbedtls --include=Cargo.toml -r . -e '\[workspace\]' | cut -d: -f1); do
  pushd $(dirname $toml) >/dev/null
  echo "Linting in $PWD"
  cargo sort --workspace --grouped $CHECK
  cargo fmt -- --unstable-features $CHECK
  cargo clippy --all --all-features
  echo "Linting in $PWD complete."
  popd >/dev/null
done
