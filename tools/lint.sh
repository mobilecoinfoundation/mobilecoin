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

cargo install --version 1.0.9 --locked cargo-sort

# We want to check with --all-targets since it checks test code, but that flag
# leads to build errors in enclave workspaces, so check it here.
cargo sort --workspace --grouped $CHECK
cargo clippy --all --all-features --all-targets -- -D warnings
cargo fmt -- --unstable-features $CHECK

# Run on all the nested workspaces.
# We exclude `cargo` paths as these are crates from `[patch.crates-io]`
for toml in $(find . -mindepth 2 -type f -not -path '*/cargo/*' -name Cargo.toml -exec grep -l -e '\[workspace\]' {} +); do
  pushd $(dirname $toml) >/dev/null
  echo "Linting in $PWD"
  cargo sort --workspace --grouped $CHECK
  cargo clippy --all --all-features -- -D warnings
  cargo fmt -- --unstable-features $CHECK
  echo "Linting in $PWD complete."
  popd >/dev/null
done
