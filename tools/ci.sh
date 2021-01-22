#!/bin/bash

# Copyright (c) 2018-2021 The MobileCoin Foundation

#
# This script is run from outside the container to exercise CI functionality, via
# mob.
#
# Invokes check, build, and test, forwarding any config options each time,
# such as `--release`,`--hw`, `--tag`
set -ex

ls -l

echo "build"
time ./mob build --locked "$@"

# Note: check comes after build because if generated files are missing,
# cargo fmt fails
echo "check"
time ./mob check "$@"

echo "test"
time ./mob test "$@"
