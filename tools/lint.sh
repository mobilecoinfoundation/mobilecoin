#!/bin/bash

# Copyright (c) 2018-2023 The MobileCoin Foundation

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
cargo fmt -- --unstable-features $CHECK
cargo clippy --all --all-features --all-targets -- -D warnings

# Run on all the nested workspaces.
# We exclude `cargo` paths as these are crates from `[patch.crates-io]`
for toml in $(find . -mindepth 2 -type f -not -path '*/cargo/*' -name Cargo.toml -exec grep -l -e '\[workspace\]' {} +); do
  pushd $(dirname $toml) >/dev/null
  echo "Linting in $PWD"
  cargo fmt -- --unstable-features $CHECK
  cargo clippy --all --all-features -- -D warnings
  echo "Linting in $PWD complete."
  popd >/dev/null
done

# `cargo sort` is a bit too aggressive at modifying files. When not provided the
# `--check` flag it will *always* re-write the files it's sorting. This results
# in cargo seeing the `Cargo.toml` files as modified and often requiring a
# rebuild of a package. To work around this, we first check and only if it fails
# will we fix. We operate on each `Cargo.toml` file individually to minimize the
# incremental build impact of fixing a file.
SORT_COMMAND="cargo sort --grouped --check"
if [ -z "$CHECK" ]
then
    SORT_COMMAND="$SORT_COMMAND || cargo sort --grouped"
fi

for toml in $(find . -type f -not -path '*/cargo/*' -name Cargo.toml); do
  pushd $(dirname $toml) >/dev/null
  echo "Checking $toml"
  eval $SORT_COMMAND
  popd >/dev/null
done
