#!/bin/bash
#
# Copyright (c) 2018-2021 The MobileCoin Foundation
#
# This script performs any "health checks" that are not considered unit tests,
# such as code formatting, that are run in CI.
#
# This script is meant to run inside the container, and be invoked by `mob`.
# It should not be referred to directly by CI so that it can change or be moved
# without requiring CI to be reconfigured. CI should use `./mob check`
set -ex

echo "=== Checking code is formatted. ==="
cargo fmt --version
cargo fmt -- --unstable-features --check

cd consensus_enclave/static/
cargo fmt -- --unstable-features --check

rustc --version
cargo --version
